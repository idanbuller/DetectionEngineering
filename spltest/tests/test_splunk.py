import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from spltest.splunk import SplunkClient, SplunkError, load_results, parse_export


class FakeSplunk(BaseHTTPRequestHandler):
    """Answers the export endpoint with whatever rows the test sets."""

    rows = []
    fatal = None
    seen = []

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        FakeSplunk.seen.append((self.path, self.headers["Authorization"], body))
        if self.headers["Authorization"] == "Bearer bad":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}')
            return
        self.send_response(200)
        self.end_headers()
        lines = [json.dumps({"preview": True, "result": {"ignored": "1"}})]
        lines += [json.dumps({"preview": False, "offset": i, "result": r}) for i, r in enumerate(FakeSplunk.rows)]
        if FakeSplunk.fatal:
            lines.append(json.dumps({"messages": [{"type": "FATAL", "text": FakeSplunk.fatal}]}))
        self.wfile.write("\n".join(lines).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def splunk():
    FakeSplunk.rows, FakeSplunk.fatal, FakeSplunk.seen = [], None, []
    server = HTTPServer(("127.0.0.1", 0), FakeSplunk)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_client_runs_export(splunk):
    FakeSplunk.rows = [{"src": "1.2.3.4", "count": "3"}]
    rows = SplunkClient(splunk, token="t").search("| makeresults | eval x=1")
    assert rows == [{"src": "1.2.3.4", "count": "3"}]
    path, auth, body = FakeSplunk.seen[0]
    assert path == "/services/search/v2/jobs/export" and auth == "Bearer t"
    assert body["search"] == ["| makeresults | eval x=1"] and body["output_mode"] == ["json"]


def test_client_basic_auth_and_errors(splunk):
    SplunkClient(splunk, username="u", password="p").search("index=x")
    assert FakeSplunk.seen[0][1].startswith("Basic ")
    assert FakeSplunk.seen[0][2]["search"] == ["search index=x"]
    with pytest.raises(SplunkError, match="HTTP 401"):
        SplunkClient(splunk, token="bad").search("| makeresults")
    FakeSplunk.fatal = "Unknown search command 'nope'."
    with pytest.raises(SplunkError, match="Unknown search command"):
        SplunkClient(splunk, token="t").search("| nope")
    with pytest.raises(SplunkError, match="credentials"):
        SplunkClient(splunk)
    with pytest.raises(SplunkError, match="can't reach"):
        SplunkClient("http://127.0.0.1:9", token="t", timeout=2).search("| makeresults")


def test_parse_export():
    text = '{"preview":false,"result":{"a":"1"}}\n\n{"preview":false,"result":{"a":"2"},"lastrow":true}\n'
    assert parse_export(text) == [{"a": "1"}, {"a": "2"}]


def test_load_results_formats(tmp_path):
    (tmp_path / "list.json").write_text('[{"a": 1}]')
    (tmp_path / "obj.json").write_text('{"results": [{"a": 2}], "total_rows": 1}')
    (tmp_path / "export.json").write_text('{"preview":false,"result":{"a":"3"}}\n{"preview":false,"result":{"a":"4"}}')
    (tmp_path / "empty.json").write_text("")
    assert load_results(str(tmp_path / "list.json")) == [{"a": 1}]
    assert load_results(str(tmp_path / "obj.json")) == [{"a": 2}]
    assert load_results(str(tmp_path / "export.json")) == [{"a": "3"}, {"a": "4"}]
    assert load_results(str(tmp_path / "empty.json")) == []
