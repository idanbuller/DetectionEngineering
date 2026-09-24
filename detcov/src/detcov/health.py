"""Decide whether the data a detection needs is actually flowing.

Health comes from one of:
  * a JSON/YAML file: a list of {index, sourcetype, last_seen, events}, or
    {"index::sourcetype": {"last_seen": ..., "events": ...}}
  * a live Splunk instance, via one tstats over the metadata.

A data pair is:
  healthy - seen within the freshness window with events
  stale   - seen, but older than the freshness window
  missing - never seen
  unknown - no health information available (or the rule's index comes from a macro)
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .catalog import DataPair

HEALTHY, STALE, MISSING, UNKNOWN = "healthy", "stale", "missing", "unknown"


class HealthError(RuntimeError):
    pass


@dataclass
class SourceHealth:
    index: str
    sourcetype: Optional[str]
    last_seen: Optional[float]  # epoch seconds
    events: int


class Health:
    """Answers pair -> status, given collected per-(index, sourcetype) facts."""

    def __init__(self, facts: List[SourceHealth], freshness_seconds: float, now: Optional[float] = None) -> None:
        self.freshness = freshness_seconds
        self.now = now if now is not None else time.time()
        self.by_pair: Dict[Tuple[str, Optional[str]], SourceHealth] = {}
        self.by_index: Dict[str, SourceHealth] = {}
        for f in facts:
            self.by_pair[(f.index, f.sourcetype)] = f
            existing = self.by_index.get(f.index)
            if existing is None or (f.last_seen or 0) > (existing.last_seen or 0):
                self.by_index[f.index] = SourceHealth(f.index, None, f.last_seen, f.events)
        self.has_data = bool(facts)

    def status(self, pair: DataPair) -> str:
        index, sourcetype = pair
        fact = self.by_pair.get((index, sourcetype))
        if fact is None:
            fact = self.by_index.get(index)  # fall back to index-level health
        if fact is None:
            return MISSING if self.has_data else UNKNOWN
        if not fact.events or fact.last_seen is None:
            return MISSING
        return HEALTHY if (self.now - fact.last_seen) <= self.freshness else STALE

    def worst(self, pairs) -> str:
        """The worst status across a rule's data pairs (missing beats stale beats healthy)."""
        if not pairs:
            return UNKNOWN
        order = {MISSING: 0, STALE: 1, UNKNOWN: 2, HEALTHY: 3}
        return min((self.status(p) for p in pairs), key=lambda s: order[s])


def load_health_file(path: str, freshness_seconds: float, now: Optional[float] = None) -> Health:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    facts = []
    if isinstance(data, dict):
        for key, val in data.items():
            index, _, sourcetype = str(key).partition("::")
            facts.append(_fact(index, sourcetype or None, val))
    elif isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            facts.append(_fact(item.get("index"), item.get("sourcetype"), item))
    else:
        raise HealthError(f"{path}: expected a list or mapping of source health")
    return Health([f for f in facts if f.index], freshness_seconds, now)


def _fact(index, sourcetype, val: Any) -> SourceHealth:
    if not isinstance(val, dict):
        val = {}
    return SourceHealth(
        index=str(index) if index else "",
        sourcetype=str(sourcetype) if sourcetype else None,
        last_seen=_epoch(val.get("last_seen") if isinstance(val, dict) else None),
        events=int(val.get("events", 1) or 0) if isinstance(val, dict) else 0,
    )


def _epoch(value) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def from_splunk(
    url: str,
    token: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_tls: bool = True,
    lookback: str = "-30d",
    freshness_seconds: float = 86400,
    timeout: float = 120.0,
) -> Health:
    """One tstats over the requested lookback: last event time and count per index+sourcetype."""
    if not token and not (username and password):
        raise HealthError("Splunk credentials missing: set a token, or a username and password")
    auth = f"Bearer {token}" if token else "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    context = None
    if url.startswith("https") and not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    search = "| tstats latest(_time) as last_seen count where index=* by index, sourcetype"
    body = urllib.parse.urlencode(
        {"search": search, "output_mode": "json", "earliest_time": lookback, "latest_time": "now"}
    ).encode()
    req = urllib.request.Request(
        f"{url.rstrip('/')}/services/search/v2/jobs/export",
        data=body,
        method="POST",
        headers={"Authorization": auth, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise HealthError(f"Splunk returned HTTP {exc.code}: {exc.read().decode(errors='replace')[:400]}") from None
    except urllib.error.URLError as exc:
        raise HealthError(f"can't reach Splunk at {url}: {exc.reason}") from None
    facts = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        for msg in obj.get("messages", []):
            if msg.get("type") in ("FATAL", "ERROR"):
                raise HealthError(f"health search failed: {msg.get('text')}")
        r = obj.get("result")
        if r and r.get("index"):
            facts.append(
                SourceHealth(
                    r["index"], r.get("sourcetype") or None, _epoch(r.get("last_seen")), int(r.get("count", 0))
                )
            )
    return Health(facts, freshness_seconds, now=datetime.now(timezone.utc).timestamp())


def empty(freshness_seconds: float = 86400) -> Health:
    return Health([], freshness_seconds)
