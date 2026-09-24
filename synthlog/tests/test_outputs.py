import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from synthlog import outputs

SPEC = r"""
seed: 1
start: 2026-01-05T00:00:00Z
duration: 1h
sources:
  web:
    index: web
    sourcetype: access
    host_field: host
    events: 3
    raw: '{_time:%d/%b/%Y:%H:%M:%S} {host} "GET {path}" {status}'
    fields: {host: web-01, path: 'C:\x\"y', status: 200}
  edr:
    index: edr
    sourcetype: edr:json
    nested: true
    events: 2
    fields: {process.name: cmd.exe, process.path: 'C:\Windows\cmd.exe'}
scenarios:
  - {id: s1, steps: [{source: web, set: {status: 500}}]}
"""


def unescape_spl(search: str):
    m = re.match(r'\| makeresults format=json data="(.*)"(\n\| spath)?$', search, re.S)
    assert m, search[:80]
    body = re.sub(r"\\(.)", r"\1", m.group(1))
    return json.loads(body), bool(m.group(2))


def test_write_files(build, tmp_path):
    ds = build(SPEC)
    paths = outputs.write_files(ds, str(tmp_path), label_field="synthetic")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["edr.jsonl", "truth.json", "web.log"]
    web = (tmp_path / "web.log").read_text().splitlines()
    assert len(web) == 4 and all(line.startswith("05/Jan/2026:") for line in web)
    assert sum('" 500' in line for line in web) == 1
    edr = [json.loads(line) for line in (tmp_path / "edr.jsonl").read_text().splitlines()]
    assert edr[0]["process"] == {"name": "cmd.exe", "path": "C:\\Windows\\cmd.exe"}
    assert edr[0]["synthetic"] == "background"
    truth = json.loads((tmp_path / "truth.json").read_text())
    assert [t["scenario"] for t in truth] == ["s1"]
    assert len(paths) == 3


def test_makeresults_round_trip(build):
    ds = build(SPEC)
    records, spath = unescape_spl(outputs.makeresults_search(ds))
    assert spath
    assert len(records) == 6
    assert [r["_time"] for r in records] == sorted(r["_time"] for r in records)
    web = [r for r in records if r["sourcetype"] == "access"]
    assert web[0]["host"] == "web-01" and web[0]["index"] == "web"
    assert 'C:\\x\\"y' in web[0]["_raw"]
    edr = [r for r in records if r["sourcetype"] == "edr:json"]
    assert json.loads(edr[0]["_raw"]) == {"process": {"name": "cmd.exe", "path": "C:\\Windows\\cmd.exe"}}
    assert "index" not in edr[0]["_raw"]  # metadata stays out of _raw


def test_makeresults_source_filter(build):
    records, spath = unescape_spl(outputs.makeresults_search(build(SPEC), ["web"]))
    assert {r["sourcetype"] for r in records} == {"access"} and not spath


class _Collector(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Collector.received.append((self.path, self.headers["Authorization"], body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')

    def log_message(self, *args):
        pass


def test_hec(build):
    _Collector.received = []
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        sent = outputs.send_hec(build(SPEC), url, "tok", batch_size=4)
    finally:
        server.shutdown()
    assert sent == 6
    assert len(_Collector.received) == 2
    path, auth, body = _Collector.received[0]
    assert path == "/services/collector/event" and auth == "Splunk tok"
    first = json.loads(body.split(b"\n")[0])
    assert set(first) >= {"time", "event", "index", "sourcetype", "source"}
