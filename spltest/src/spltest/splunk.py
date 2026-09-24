"""Run a search on Splunk over REST, or load results that were saved elsewhere."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class SplunkError(RuntimeError):
    pass


class SplunkClient:
    """Minimal client for the export endpoint: one request, streamed JSON results."""

    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 300.0,
    ) -> None:
        if not token and not (username and password):
            raise SplunkError("Splunk credentials missing: set a token, or a username and password")
        self.url = url.rstrip("/")
        if token:
            self.auth = f"Bearer {token}"
        else:
            self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.context = None
        if self.url.startswith("https") and not verify_tls:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.timeout = timeout

    def search(self, spl: str) -> List[Dict[str, Any]]:
        query = spl if spl.lstrip().startswith("|") else f"search {spl}"
        body = urllib.parse.urlencode(
            {"search": query, "output_mode": "json", "earliest_time": "0", "latest_time": "now"}
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
            detail = exc.read().decode(errors="replace")[:500]
            raise SplunkError(f"Splunk returned HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise SplunkError(f"can't reach Splunk at {self.url}: {exc.reason}") from None
        return parse_export(text)


def parse_export(text: str) -> List[Dict[str, Any]]:
    """Parse the export endpoint's JSON lines; raise on fatal search messages."""
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


def load_results(path: str) -> List[Dict[str, Any]]:
    """Results saved from anywhere: a JSON list of rows, {"results": [...]}, or export JSON lines."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.strip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return parse_export(text)
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    if isinstance(data, dict) and "result" in data:
        return [data["result"]]
    raise ValueError(f"{path}: expected a JSON list of result rows or an object with a results list")
