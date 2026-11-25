#!/usr/bin/env python3
"""Tests for Windows/csv_importers/iisgeolocate2sofelk.py (standard library only).

    python3 tests/test_iisgeolocate.py -v

Synthetic fixtures: an iisGeolocate output folder (Chunk CSVs, !UniqueIPs.csv, console log,
BadDataRows_REVIEW_ME.txt) and the raw IIS W3C log the CSV was made from. An in-process mock
Elasticsearch takes the bulk requests.
"""
import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "Windows" / "csv_importers"))

import iisgeolocate2sofelk as iis  # noqa: E402
import sof_elk_index_templates as templates  # noqa: E402

FIELDS = ("date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
          "c-ip cs-version cs(User-Agent) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes "
          "cs-bytes time-taken X-Forwarded-For")
RAW_LINES = [
    "2026-11-02 03:04:05 W3SVC1 WEB01 10.0.0.5 GET /owa/auth/logon.aspx url=%2fowa%2f 443 - 203.0.113.7 HTTP/1.1 "
    "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) https://mail.example.com/ mail.example.com 200 0 0 5120 640 15 -",
    "2026-11-02 03:04:06 W3SVC1 WEB01 10.0.0.5 POST /aspnet_client/x.aspx cmd=whoami 443 CORP\\jdoe 10.0.0.9 HTTP/2 "
    "python-requests/2.31.0 - mail.example.com 500 0 64 120 900 1234 198.51.100.4,+10.1.1.1",
    # the same request twice in one second: two documents, not one
    "2026-11-02 03:04:07 W3SVC1 WEB01 10.0.0.5 GET /favicon.ico - 443 - 203.0.113.7 HTTP/1.1 - - "
    "mail.example.com 404 0 2 0 300 1 -",
    "2026-11-02 03:04:07 W3SVC1 WEB01 10.0.0.5 GET /favicon.ico - 443 - 203.0.113.7 HTTP/1.1 - - "
    "mail.example.com 404 0 2 0 300 1 -",
]
GEO = [("Singapore", "Singapore"), ("NA", "NA"), ("Ho_Chi_Minh_City", "Viet_Nam"), ("Ho_Chi_Minh_City", "Viet_Nam")]


def write_fixtures(root: Path):
    raw = root / "logs" / "W3SVC1"
    raw.mkdir(parents=True)
    (raw / "u_ex261102.log").write_text(
        "#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n"
        "#Date: 2026-11-02 03:04:05\n#Fields: " + FIELDS + "\n" + "\n".join(RAW_LINES) + "\n", encoding="utf-8")
    out = root / "iisgeolocate"
    out.mkdir()
    import csv
    with (out / "20261120085119_u_ex261102_Chunk1.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(FIELDS.split() + ["GeoCity", "GeoCountry"])
        for line, (city, country) in zip(RAW_LINES, GEO):
            w.writerow(line.split(" ") + [city, country])
    (out / "!UniqueIPs.csv").write_text("IpAddress,City,Country\n203.0.113.7,Singapore,Singapore\n", encoding="utf-8")
    (out / "20261120085119_iisGeolocate_2026.10.1_ConsoleLog.txt").write_text("[08:51:19.909 INF] iisgeolocate\n")
    (out / "BadDataRows_REVIEW_ME.txt").write_text("SourceFile\tLineNumber\tReason\tRow\nu_ex.log\t9\tbad\tx y z\n")
    return raw, out


def leaf_paths(doc, prefix=""):
    for key, value in doc.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from leaf_paths(value, path + ".")
        else:
            yield path


class MockES:
    """Just enough of Elasticsearch for the importer: HEAD/PUT index, mapping, _bulk, _count."""

    def __init__(self):
        self.indices = {}
        self.templates = {}
        mock = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def reply(self, status, obj=None):
                data = b"" if obj is None or self.command == "HEAD" else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def read(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def do_HEAD(self):
                self.reply(200 if self.path.strip("/") in mock.indices else 404)

            def do_GET(self):
                parts = self.path.strip("/").split("/")
                if parts == [""]:
                    return self.reply(200, {"version": {"number": "9.4.3-test"}})
                if len(parts) == 2 and parts[1] == "_mapping" and parts[0] in mock.indices:
                    return self.reply(200, {parts[0]: {"mappings": mock.indices[parts[0]]["mappings"]}})
                self.reply(404, {})

            def do_PUT(self):
                body = json.loads(self.read() or b"{}")
                parts = self.path.strip("/").split("/")
                if parts[0] in ("_component_template", "_index_template"):
                    mock.templates[parts[1]] = body
                    return self.reply(200, {"acknowledged": True})
                if len(parts) == 1:
                    mock.indices[parts[0]] = {"mappings": body.get("mappings", {}), "docs": {}}
                    return self.reply(200, {"acknowledged": True})
                if parts[1] == "_mapping":
                    m = mock.indices[parts[0]]["mappings"]
                    m["_meta"] = body.get("_meta", m.get("_meta"))
                    m.setdefault("properties", {}).update(body.get("properties", {}))
                    return self.reply(200, {"acknowledged": True})
                self.reply(404, {})

            def do_POST(self):
                raw = self.read()
                parts = self.path.strip("/").split("/")
                if parts[-1] == "_refresh":
                    return self.reply(200, {})
                if parts[-1] == "_count":
                    return self.reply(200, {"count": len(mock.indices.get(parts[0], {"docs": {}})["docs"])})
                lines = [ln for ln in raw.decode().split("\n") if ln.strip()]
                items = []
                for action, doc in zip(lines[::2], lines[1::2]):
                    meta = json.loads(action)["index"]
                    docs = mock.indices[meta["_index"]]["docs"]
                    existed = meta["_id"] in docs
                    docs[meta["_id"]] = json.loads(doc)
                    items.append({"index": {"status": 200 if existed else 201,
                                            "result": "updated" if existed else "created"}})
                self.reply(200, {"errors": False, "items": items})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def run_importer(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = iis.main([str(a) for a in argv] + ["--retry-backoff", "0.01"])
    return code, out.getvalue()


class ParseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw, self.out = write_fixtures(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def docs(self, path, fmt):
        meta = {"host": "web01", "path": str(path), "format": fmt, "case": "IR-1"}
        return [iis.build(pairs, meta)[0] for pairs in iis.records(path, fmt)]

    def test_sniff(self):
        self.assertEqual(iis.sniff(self.raw / "u_ex261102.log")[0], "w3c")
        self.assertEqual(iis.sniff(self.out / "20261120085119_u_ex261102_Chunk1.csv")[0], "iisgeolocate")
        for side in ("!UniqueIPs.csv", "20261120085119_iisGeolocate_2026.10.1_ConsoleLog.txt",
                     "BadDataRows_REVIEW_ME.txt"):
            self.assertEqual(iis.sniff(self.out / side)[0], "side", side)
        self.assertEqual(iis.bad_rows(self.out / "BadDataRows_REVIEW_ME.txt"), 1)
        # CloudFront standard logs are W3C too; they are left to the CloudFront importer.
        cf = self.raw / "E2ABCDEF.2026-11-02-01.abcd.log"
        cf.write_text("#Version: 1.0\n#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status\n")
        self.assertIsNone(iis.sniff(cf)[0])
        cf.unlink()

    def test_field_mapping(self):
        docs = self.docs(self.out / "20261120085119_u_ex261102_Chunk1.csv", "iisgeolocate")
        d = docs[0]
        self.assertEqual(d["@timestamp"], "2026-11-02T03:04:05.000Z")
        self.assertEqual(d["source"], {"ip": "203.0.113.7", "bytes": 640,
                                       "geo": {"city_name": "Singapore", "country_name": "Singapore"}})
        self.assertEqual(d["destination"], {"ip": "10.0.0.5", "port": 443, "bytes": 5120})
        self.assertEqual(d["url"], {"path": "/owa/auth/logon.aspx", "query": "url=%2fowa%2f", "extension": "aspx",
                                    "original": "/owa/auth/logon.aspx?url=%2fowa%2f", "domain": "mail.example.com"})
        self.assertEqual(d["user_agent"]["original"], "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual(d["http"], {"version": "1.1", "request": {"method": "GET", "referrer": "https://mail.example.com/"},
                                     "response": {"status_code": 200, "substatus_code": 0}})
        self.assertEqual(d["event"], {"duration": 15_000_000, "dataset": "iis.access", "kind": "event", "category": "web"})
        self.assertEqual(d["host"], {"name": "web01", "hostname": "WEB01", "os": {"type": "windows"}})
        self.assertEqual(d["service"], {"name": "W3SVC1"})
        self.assertEqual(d["case"], "IR-1")
        self.assertNotIn("xff", d)
        d = docs[1]
        self.assertEqual(d["client"]["user"]["name"], "CORP\\jdoe")
        self.assertEqual(d["http"]["version"], "2")
        self.assertEqual(d["process"]["exit_code"], 64)
        self.assertEqual(d["xff"]["ip"], ["198.51.100.4", "10.1.1.1"])
        self.assertEqual(d["iis"]["unmapped"]["x_forwarded_for"], "198.51.100.4,+10.1.1.1")
        self.assertNotIn("geo", d["source"])                       # "NA" is left out
        self.assertEqual(docs[2]["source"]["geo"]["country_name"], "Viet Nam")   # "_" -> space

    def test_every_field_is_mapped(self):
        _c, _t, body = templates.load("httpdlog")
        mapped = set(templates.field_types(body["mappings"]))
        for path, fmt in ((self.out / "20261120085119_u_ex261102_Chunk1.csv", "iisgeolocate"),
                          (self.raw / "u_ex261102.log", "w3c")):
            for doc in self.docs(path, fmt):
                for leaf in leaf_paths(doc):
                    if leaf.startswith("iis.unmapped."):
                        continue
                    self.assertIn(leaf, mapped, f"{fmt}: {leaf} is not in index-httpdlog.json")

    def test_shared_fields_match_other_httpdlog_importers(self):
        _c, _t, body = templates.load("httpdlog")
        mine = templates.field_types(body["mappings"])
        for other in ("AWS/index_templates/index-httpdlog.json", "Linux/index_templates/index-httpdlog.json"):
            theirs = templates.field_types(json.loads((REPO / other).read_text())["template"]["mappings"])
            clash = {f: (mine[f], t) for f, t in theirs.items() if f in mine and mine[f] != t}
            self.assertEqual(clash, {}, other)

    def test_raw_log_and_csv_give_the_same_ids(self):
        def ids(path, fmt):
            seen = {}
            return [iis.doc_id("web01", iis.log_name(path), pairs, seen) for pairs in iis.records(path, fmt)]
        a = ids(self.raw / "u_ex261102.log", "w3c")
        b = ids(self.out / "20261120085119_u_ex261102_Chunk1.csv", "iisgeolocate")
        self.assertEqual(a, b)
        self.assertEqual(len(set(a)), 4)        # identical requests stay separate documents
        self.assertEqual(iis.log_name(self.out / "20261120085119_u_ex261102_Chunk1.csv"), "u_ex261102")


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw, self.out = write_fixtures(Path(self.tmp.name))
        self.es = MockES()

    def tearDown(self):
        self.es.close()
        self.tmp.cleanup()

    def test_load_rerun_and_raw_log(self):
        code, out = run_importer(self.out, "--hostname", "WEB01", "--case", "IR-1", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("Index 'httpdlog-web01': created", out)
        self.assertIn("could not parse 1 row(s)", out)
        self.assertIn("Done: 4 new document(s), 0 already in index", out)
        docs = self.es.indices["httpdlog-web01"]["docs"]
        self.assertEqual(len(docs), 4)
        self.assertEqual({d["iis"]["source_format"] for d in docs.values()}, {"iisgeolocate"})
        # the raw log of the same requests overwrites (no duplicates)
        code, out = run_importer(self.raw, "--hostname", "WEB01", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("Index 'httpdlog-web01': appending", out)
        self.assertIn("0 new document(s), 4 already in index", out)
        self.assertEqual(len(docs), 4)

    def test_appends_to_an_index_made_by_another_web_importer(self):
        aws = json.loads((REPO / "AWS/index_templates/index-httpdlog.json").read_text())
        self.es.indices["httpdlog-web01"] = {"mappings": aws["template"]["mappings"], "docs": {}}
        code, out = run_importer(self.out, "--hostname", "web01", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        props = self.es.indices["httpdlog-web01"]["mappings"]["properties"]
        self.assertIn("iis", props)
        self.assertIn("aws", props)

    def test_refuses_an_index_it_did_not_make(self):
        self.es.indices["httpdlog-web01"] = {"mappings": {"properties": {}}, "docs": {}}
        with self.assertRaises(SystemExit) as cm:
            run_importer(self.out, "--hostname", "web01", "--es", self.es.url)
        self.assertIn("not created by a toolkit web log importer", str(cm.exception))

    def test_dry_run_sends_nothing(self):
        code, out = run_importer(self.out, self.raw, "--hostname", "web01", "--dry-run", "--es", "http://127.0.0.1:9")
        self.assertEqual(code, 0, out)
        self.assertIn("1 iisGeolocate CSV(s), 1 raw W3C log(s)", out)
        self.assertIn("Dry run only", out)


if __name__ == "__main__":
    unittest.main()
