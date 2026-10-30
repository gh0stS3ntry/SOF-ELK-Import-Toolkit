#!/usr/bin/env python3
"""Tests for SOF-ELK_DeleteIndexes.py against an in-process mock Elasticsearch.

    python3 tests/test_delete_indexes.py -v
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
spec = importlib.util.spec_from_file_location("delete_indexes", ROOT / "SOF-ELK_DeleteIndexes.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

# index -> (status, [documents as flat {field: value} dicts], {fields that are not aggregatable})
INDICES = {}
DELETED = []


def case_matches(doc, query):
    term = query["term"]["case"]
    value = doc.get("case")
    return value is not None and value.lower() == term["value"].lower()


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
            rows = [{"index": name, "status": status, "health": "green",
                     "docs.count": str(len(docs)), "store.size": "1kb"}
                    for name, (status, docs, _) in sorted(INDICES.items()) if name.endswith(suffix)]
            return self.reply(200, rows)
        self.reply(404, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length))
        target, endpoint = unquote(urlsplit(self.path).path).split("/")[1:3]
        if target == "*,-.*":
            # Case search across all open indexes, aggregated by _index.
            buckets = []
            for name, (status, docs, _) in sorted(INDICES.items()):
                hits = sum(case_matches(doc, body["query"]) for doc in docs)
                if status == "open" and hits:
                    buckets.append({"key": name, "doc_count": hits})
            return self.reply(200, {"aggregations": {"indexes": {"buckets": buckets}}})
        status, docs, unaggregatable = INDICES[target]
        if status == "close":
            return self.reply(400, {"error": {"type": "index_closed_exception"}})
        if endpoint == "_count":
            query = body["query"]["bool"]["must_not"][0]
            return self.reply(200, {"count": sum(not case_matches(doc, query) for doc in docs)})
        field = body["aggs"]["owners"]["terms"]["field"]
        if field in unaggregatable:
            return self.reply(400, {"error": {"type": "illegal_argument_exception"}})
        values = sorted({doc[field] for doc in docs if field in doc})
        self.reply(200, {"aggregations": {"owners": {"buckets": [{"key": v, "doc_count": 1} for v in values]}}})

    def do_DELETE(self):
        index = unquote(urlsplit(self.path).path).lstrip("/")
        if index not in INDICES:
            return self.reply(404, {"error": {"type": "index_not_found_exception"}})
        del INDICES[index]
        DELETED.append(index)
        self.reply(200, {"acknowledged": True})


def host_docs(host, case=None, field="host.name"):
    doc = {field: host}
    if case:
        doc["case"] = case
    return [doc]


class DeleteIndexes(unittest.TestCase):
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
            "amcache-rd01": ("open", host_docs("rd01", "IR-42"), set()),
            "filesystem-rd01": ("open", host_docs("rd01", "IR-42"), set()),
            "evtxlogs-rd01": ("open", [{"case": "IR-42"}], set()),          # old import, no host.name
            "prefetch-rd01": ("close", [{}], set()),
            "amcache-test-rd01": ("open", host_docs("rd01"), set()),        # custom --index prefix
            "notes-rd01": ("open", [{}], set()),                            # unknown prefix, no host field
            "registry-rd01": ("open", host_docs("rd01", "IR-42"), {"host.name"}),  # not aggregatable
            "amcache-rd011": ("open", host_docs("rd011", "IR-42"), set()),
            "amcache-rd01-old": ("open", host_docs("rd01-old"), set()),
            "amcache-ws-01": ("open", host_docs("ws-01", "IR-7"), set()),
            # Same host imported under two cases: must survive a case delete.
            "shimcache-ws-01": ("open", host_docs("ws-01", "IR-42") + host_docs("ws-01", "IR-7"), set()),
            "aws-cloudtrail-prod": ("open", host_docs("prod", "IR-42", "labels.evidence_source"), set()),
            "aws-cloudtrail-01": ("open", host_docs("01", None, "labels.evidence_source"), set()),
            "srum-oldcase": ("close", host_docs("oldcase", "IR-42"), set()),
        })

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = d.main(["--es", self.url, "--max-retries", "0", *argv])
        return code, out.getvalue(), err.getvalue()

    # --- by hostname ---------------------------------------------------------------

    def test_host_dry_run_lists_and_deletes_nothing(self):
        code, out, _ = self.run_main("--hostname", "RD01", "--dry-run")
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

    def test_host_yes_deletes_only_this_host(self):
        code, out, _ = self.run_main("--hostname", "rd01", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "amcache-test-rd01", "evtxlogs-rd01",
                                           "filesystem-rd01", "prefetch-rd01", "registry-rd01"])
        self.assertIn("notes-rd01", INDICES)
        self.assertIn("amcache-rd011", INDICES)

    def test_hyphenated_hostname_is_not_caught_by_its_suffix(self):
        code, out, _ = self.run_main("--hostname", "01", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(DELETED, ["aws-cloudtrail-01"])
        self.assertIn("amcache-ws-01", INDICES)
        self.assertIn("documents belong to ws-01", out)

    def test_prefix_restricts_and_unlocks_custom_prefix(self):
        code, out, _ = self.run_main("--hostname", "rd01", "--prefix", "amcache", "--prefix", "notes", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "notes-rd01"])

    # --- by case ---------------------------------------------------------------------

    def test_case_deletes_indexes_wholly_in_the_case(self):
        code, out, _ = self.run_main("--case", "ir-42", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "amcache-rd011", "aws-cloudtrail-prod",
                                           "evtxlogs-rd01", "filesystem-rd01", "registry-rd01"])
        # Mixed-case index is kept and explained; other cases and closed indexes are untouched.
        self.assertIn("shimcache-ws-01", INDICES)
        self.assertIn("1 doc(s) are case 'ir-42' but 1 are not", out)
        self.assertIn("amcache-ws-01", INDICES)
        self.assertIn("srum-oldcase", INDICES)
        self.assertIn("closed index(es) cannot be searched", out)

    def test_case_with_prefix(self):
        code, out, _ = self.run_main("--case", "IR-42", "--prefix", "amcache", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "amcache-rd011"])

    def test_host_and_case_together(self):
        code, out, _ = self.run_main("--hostname", "rd01", "--case", "IR-42", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(DELETED), ["amcache-rd01", "evtxlogs-rd01", "filesystem-rd01", "registry-rd01"])
        self.assertIn("amcache-rd011", INDICES)
        self.assertIn("amcache-test-rd01", INDICES)
        self.assertIn("no documents for case 'IR-42'", out)

    def test_unknown_case(self):
        code, out, _ = self.run_main("--case", "nope", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(DELETED, [])
        self.assertIn("Nothing to delete", out)

    # --- common ----------------------------------------------------------------------

    def test_hostname_or_case_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            d.main(["--es", self.url])

    def test_confirmation_required(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            with self.assertRaises(SystemExit):
                self.run_main("--hostname", "rd01")
            stdin.isatty.return_value = True
            with mock.patch("builtins.input", return_value="rd02"):
                code, out, _ = self.run_main("--hostname", "rd01")
            self.assertEqual(code, 1)
            self.assertIn("Aborted", out)
            self.assertEqual(DELETED, [])
            with mock.patch("builtins.input", return_value="IR-42") as ask:
                code, _, _ = self.run_main("--case", "ir-42", "--prefix", "filesystem")
            self.assertIn("Type the case ID 'ir-42'", ask.call_args[0][0])
            self.assertEqual(DELETED, ["filesystem-rd01"])
            with mock.patch("builtins.input", return_value="RD01"):
                code, _, _ = self.run_main("--hostname", "rd01")
        self.assertEqual(code, 0)
        self.assertEqual(len(DELETED), 6)

    def test_nothing_to_delete(self):
        code, out, _ = self.run_main("--hostname", "nosuchhost", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("Nothing to delete", out)

    def test_unreachable(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = d.main(["--es", "http://127.0.0.1:9", "--max-retries", "0", "--hostname", "rd01", "--yes"])
        self.assertEqual(code, 2)
        self.assertIn("unreachable", err.getvalue())


if __name__ == "__main__":
    unittest.main()
