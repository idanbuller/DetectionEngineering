"""Where generated events go: files, Splunk HEC, or an inline makeresults search."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Optional, Sequence

from . import render
from .engine import Dataset, Event
from .generators import Template


def _templates(dataset: Dataset) -> Dict[str, Optional[Template]]:
    return {name: Template(s.raw) if s.raw else None for name, s in dataset.spec.sources.items()}


def write_files(dataset: Dataset, out_dir: str, label_field: Optional[str] = None) -> List[str]:
    """One file per source (<source>.jsonl, or <source>.log for raw sources) plus truth.json."""
    os.makedirs(out_dir, exist_ok=True)
    templates = _templates(dataset)
    written = []
    for name, events in dataset.events.items():
        source = dataset.spec.sources[name]
        template = templates[name]
        path = os.path.join(out_dir, f"{name}.log" if template else f"{name}.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for e in events:
                if template:
                    fh.write(render.raw_line(e, source, template, label_field) + "\n")
                else:
                    fh.write(json.dumps(render.fields(e, source, label_field), ensure_ascii=False) + "\n")
        written.append(path)
    truth_path = os.path.join(out_dir, "truth.json")
    with open(truth_path, "w", encoding="utf-8") as fh:
        json.dump(dataset.truth, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    written.append(truth_path)
    return written


def _splunk_record(e: Event, dataset: Dataset, templates, label_field: Optional[str]):
    source = dataset.spec.sources[e.source]
    template = templates[e.source]
    if template:
        return source, render.raw_line(e, source, template, label_field)
    event = render.fields(e, source, label_field)
    event.pop("_time", None)  # Splunk takes the time from the envelope, as an epoch
    return source, event


def hec_payloads(dataset: Dataset, label_field: Optional[str] = None, batch_size: int = 500) -> Iterable[bytes]:
    """HEC /services/collector/event bodies: newline-free JSON objects concatenated per batch."""
    templates = _templates(dataset)
    batch: List[str] = []
    for e in dataset.all_events():
        source, event = _splunk_record(e, dataset, templates, label_field)
        record = {"time": render.epoch(e.time), "source": f"synthlog:{source.name}", "event": event}
        if source.index:
            record["index"] = source.index
        if source.sourcetype:
            record["sourcetype"] = source.sourcetype
        host = render.host(e, source)
        if host:
            record["host"] = host
        batch.append(json.dumps(record, ensure_ascii=False))
        if len(batch) >= batch_size:
            yield "\n".join(batch).encode()
            batch = []
    if batch:
        yield "\n".join(batch).encode()


def send_hec(
    dataset: Dataset,
    url: str,
    token: str,
    verify_tls: bool = True,
    label_field: Optional[str] = None,
    batch_size: int = 500,
    timeout: float = 30.0,
) -> int:
    endpoint = url.rstrip("/")
    if not endpoint.endswith("/services/collector/event"):
        endpoint += "/services/collector/event"
    context = None
    if endpoint.startswith("https") and not verify_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    sent = 0
    for body in hec_payloads(dataset, label_field, batch_size):
        req = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise RuntimeError(f"HEC rejected a batch after {sent} events: HTTP {exc.code}: {detail}") from None
        sent += body.count(b"\n") + 1
    return sent


def makeresults_search(
    dataset: Dataset,
    sources: Optional[Sequence[str]] = None,
    label_field: Optional[str] = None,
) -> str:
    """A self-contained search that recreates the events with | makeresults format=json.

    Each event carries _time, index, sourcetype, source and host, so a detection's own
    base search terms (index=... sourcetype=... "some text") can follow as | search.
    _raw is exactly what the source would have logged: the text line, or the JSON
    event. JSON fields are then extracted with spath, the way KV_MODE=json would.
    Needs Splunk 9.1 or later.
    """
    templates = _templates(dataset)
    wanted = set(sources) if sources else None
    records = []
    has_json = False
    for e in dataset.all_events():
        if wanted is not None and e.source not in wanted:
            continue
        source, event = _splunk_record(e, dataset, templates, label_field)
        meta = {"_time": render.epoch(e.time), "source": f"synthlog:{source.name}"}
        if source.index:
            meta["index"] = source.index
        if source.sourcetype:
            meta["sourcetype"] = source.sourcetype
        host = render.host(e, source)
        if host:
            meta["host"] = host
        if not isinstance(event, str):
            has_json = True
            event = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        records.append({**meta, "_raw": event})
    data = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
    escaped = data.replace("\\", "\\\\").replace('"', '\\"')
    search = f'| makeresults format=json data="{escaped}"'
    if has_json:
        search += "\n| spath"
    return search
