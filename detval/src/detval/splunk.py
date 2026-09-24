"""A small Splunk client: run a time-bounded search over REST and get result rows."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class SplunkError(RuntimeError):
    pass


def to_splunk_time(dt: datetime) -> str:
    return str(int(dt.timestamp()))


class SplunkClient:
    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 120.0,
    ) -> None:
        if not token and not (username and password):
            raise SplunkError("Splunk credentials missing: set a token, or a username and password")
        self.url = url.rstrip("/")
        self.auth = (
            f"Bearer {token}" if token else "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        )
        self.timeout = timeout
        self.context = None
        if self.url.startswith("https") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def search(self, spl: str, earliest: str = "0", latest: str = "now") -> List[Dict[str, Any]]:
        query = spl if spl.lstrip().startswith("|") else f"search {spl}"
        body = urllib.parse.urlencode(
            {"search": query, "output_mode": "json", "earliest_time": earliest, "latest_time": latest}
        ).encode()
        req = urllib.request.Request(
            f"{self.url}/services/search/v2/jobs/export",
            data=body,
            method="POST",
            headers={"Authorization": self.auth, "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise SplunkError(f"Splunk returned HTTP {exc.code}: {exc.read().decode(errors='replace')[:500]}") from None
        except urllib.error.URLError as exc:
            raise SplunkError(f"can't reach Splunk at {self.url}: {exc.reason}") from None
        return parse_export(text)


def parse_export(text: str) -> List[Dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        for msg in obj.get("messages", []):
            if msg.get("type") in ("FATAL", "ERROR"):
                raise SplunkError(f"search failed: {msg.get('text')}")
        if "result" in obj and not obj.get("preview", False):
            rows.append(obj["result"])
    return rows


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds from an epoch number/string, ISO time, or Splunk's display format."""
    import re

    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    try:
        x = float(text)
        return x if 1e9 <= x < 1e11 else None
    except ValueError:
        pass
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:\s*(?:UTC|Z|[+-]\d{2}:?\d{2}))?$", text)
    if not m:
        return None
    return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").replace(tzinfo=timezone.utc).timestamp()
