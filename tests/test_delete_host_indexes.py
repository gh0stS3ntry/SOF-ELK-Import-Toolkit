#!/usr/bin/env python3
"""Tests for SOF-ELK_DeleteHostIndexes.py against an in-process mock Elasticsearch.

    python3 tests/test_delete_host_indexes.py -v
"""
import contextlib
import importlib.util
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("delete_host", ROOT / "SOF-ELK_DeleteHostIndexes.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

# index -> (status, {field: [values]}); a field missing from the dict has no values,
# and None means the field is not aggregatable (search returns HTTP 400).
INDICES = {}
DELETED = []


class MockEs(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path.startswith("/_cat/indices/"):
            suffix = path[len("/_cat/indices/*"):]
            rows = [{"index": name, "status": status, "health": "green", "docs.count": "10", "store.size": "1kb"}
                    for name, (status, _) in sorted(INDICES.items()) if name.endswith(suffix)]
            return self.reply(200, rows)
        self.reply(404, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length))
        index = unquote(urlsplit(self.path).path).split("/")[1]
        status, fields = INDICES[index]
        if status == "close":
            return self.reply(400, {"error": {"type": "index_closed_exception"}})
        field = body["aggs"]["owners"]["terms"]["field"]
        values = fields.get(field, [])
        if values is None:
            return self.reply(400, {"error": {"type": "illegal_argument_exception"}})
        self.reply(200, {"aggregations": {"owners": {"buckets": [{"key": v, "doc_count": 1} for v in values]}}})

    def do_DELETE(self):
        index = unquote(urlsplit(self.path).path).lstrip("/")
        if index not in INDICES:
            return self.reply(404, {"error": {"type": "index_not_found_exception"}})
        del INDICES[index]
        DELETED.append(index)
        self.reply(200, {"acknowledged": True})


class DeleteHostIndexes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockEs)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        DELETED.clear()
        INDICES.clear()
        INDICES.update({
            "amcache-rd01": ("open", {"host.name": ["rd01"]}),
            "filesystem-rd01": ("open", {"host.name": ["rd01"]}),
            "evtxlogs-rd01": ("open", {}),                               # old import, no host.name
            "prefetch-rd01": ("close", {}),
            "amcache-test-rd01": ("open", {"host.name": ["rd01"]}),      # custom --index prefix
            "notes-rd01": ("open", {}),                                  # unknown prefix, no host field
            "registry-rd01": ("open", {"host.name": None}),              # host.name not aggregatable
            "amcache-rd011": ("open", {"host.name": ["rd011"]}),
            "amcache-rd01-old": ("open", {"host.name": ["rd01-old"]}),
            "amcache-ws-01": ("open", {"host.name": ["ws-01"]}),
            "aws-cloudtrail-prod": ("open", {"labels.evidence_source": ["prod"]}),
            "aws-cloudtrail-01": ("open", {"labels.evidence_source": ["01"]}),
        })

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = d.main(["--es", self.url, "--max-retries", "0", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_lists_and_deletes_nothing(self):
        code, out, _ = self.run_main("RD01", "--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(DELETED, [])
        self.assertIn("note: hostname normalized to 'rd01'", out)
        selected = out.split("NOT selected")[0]
        for name in ("amcache-rd01", "filesystem-rd01", "evtxlogs-rd01", "prefetch-rd01",
                     "amcache-test-rd01", "registry-rd01"):
            self.assertIn(name, selected)
        self.assertNotIn("notes-rd01", selected)
        self.assertNotIn("rd011", out)
        self.assertNotIn("rd01-old", out)

    def test_yes_deletes_only_this_host(self):
        code, out, _ = self.run_main("rd01", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "amcache-test-rd01", "evtxlogs-rd01",
                                           "filesystem-rd01", "prefetch-rd01", "registry-rd01"])
        self.assertIn("notes-rd01", INDICES)
        self.assertIn("amcache-rd011", INDICES)

    def test_hyphenated_hostname_is_not_caught_by_its_suffix(self):
        code, out, _ = self.run_main("01", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(DELETED, ["aws-cloudtrail-01"])
        self.assertIn("amcache-ws-01", INDICES)
        self.assertIn("documents belong to ws-01", out)

    def test_prefix_restricts_and_unlocks_custom_prefix(self):
        code, out, _ = self.run_main("rd01", "--prefix", "amcache", "--prefix", "notes", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "notes-rd01"])

    def test_confirmation_required(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            with self.assertRaises(SystemExit):
                self.run_main("rd01")
            stdin.isatty.return_value = True
            with mock.patch("builtins.input", return_value="rd02"):
                code, out, _ = self.run_main("rd01")
            self.assertEqual(code, 1)
            self.assertIn("Aborted", out)
            self.assertEqual(DELETED, [])
            with mock.patch("builtins.input", return_value="RD01"):
                code, _, _ = self.run_main("rd01")
        self.assertEqual(code, 0)
        self.assertEqual(len(DELETED), 6)

    def test_nothing_to_delete(self):
        code, out, _ = self.run_main("nosuchhost", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("Nothing to delete", out)

    def test_unreachable(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = d.main(["--es", "http://127.0.0.1:9", "--max-retries", "0", "rd01", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("unreachable", err.getvalue())


if __name__ == "__main__":
    unittest.main()
