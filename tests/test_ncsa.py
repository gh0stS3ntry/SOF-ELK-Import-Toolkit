#!/usr/bin/env python3
"""Tests for Web/ncsa2sofelk.py and its wrapper discovery (standard library only).

    python3 tests/test_ncsa.py -v

Synthetic fixtures: Apache common/combined/vhost logs (current and a rotated .gz), a Tomcat
AccessLogValve log, an IIS NCSA log, plus files that must not be claimed (an IIS W3C log, a
CSV, a text note). An in-process mock Elasticsearch (from test_iisgeolocate.py) takes the bulk
requests.
"""
import contextlib
import gzip
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "Web"))
sys.path.insert(0, str(REPO / "Linux" / "common"))
sys.path.insert(0, str(REPO))

import ncsa2sofelk as ncsa  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402
from test_iisgeolocate import MockES, leaf_paths  # noqa: E402

APACHE = [
    '192.0.2.10 - - [25/Nov/2026:09:15:01 +0800] "GET /index.php?id=1%27%20OR%201=1 HTTP/1.1" 200 5120',
    '192.0.2.11 - frank [25/Nov/2026:09:15:02 +0800] "POST /wp-login.php HTTP/1.1" 302 - '
    '"https://example.com/wp-login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    'www.example.com:443 198.51.100.7 - - [25/Nov/2026:09:15:03 +0800] "GET /shell.php?cmd=whoami HTTP/1.1" 200 12'
    ' "-" "curl/8.4.0"',
    'www.example.com:80 198.51.100.8 - - [25/Nov/2026:09:15:04 +0800] "GET /robots.txt HTTP/1.0" 404 -',
    '2001:db8::5 - - [25/Nov/2026:09:15:05 +0800] "\\x16\\x03\\x01" 400 226 "-" "-"',
    'cut-off line [25/Nov/2026:09:15:06 +0800] "GET /',
]
ROTATED = ['203.0.113.9 - - [24/Nov/2026:23:59:59 +0800] "GET /old HTTP/1.1" 200 1 "-" "Wget/1.21"']
TOMCAT = ['10.0.0.5 - - [25/Nov/2026:01:00:00 +0000] "GET /manager/html HTTP/1.1" 401 2473 12',
          '10.0.0.5 - admin [25/Nov/2026:01:00:01 +0000] "GET /manager/html HTTP/1.1" 200 15000 30']
IIS_NCSA = ['172.21.13.45 - REDMOND\\fred [08/Apr/2026:17:39:04 -0800] "GET /scripts/iisadmin/ism.dll?http/serv HTTP/1.0" 200 3401']


def write_fixtures(root: Path):
    (root / "apache").mkdir(parents=True)
    (root / "apache" / "access.log").write_text("﻿" + "\r\n".join(APACHE) + "\r\n", encoding="utf-8")
    with gzip.open(root / "apache" / "access.log.1.gz", "wt", encoding="utf-8") as fh:
        fh.write("\n".join(ROTATED) + "\n")
    (root / "tomcat").mkdir()
    (root / "tomcat" / "localhost_access_log.2026-11-25.txt").write_text("\n".join(TOMCAT) + "\n")
    (root / "W3SVC1").mkdir()
    (root / "W3SVC1" / "nc260408.log").write_text("\n".join(IIS_NCSA) + "\n")
    (root / "W3SVC1" / "u_ex260408.log").write_text(
        "#Software: Microsoft Internet Information Services 10.0\n#Fields: date time cs-method cs-uri-stem\n"
        "2026-04-08 01:02:03 GET /\n")
    (root / "misc").mkdir()
    (root / "misc" / "notes.txt").write_text("nothing to see\n")
    (root / "misc" / "export.csv").write_text("a,b\n1,2\n")
    return root


def run_importer(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = ncsa.main([str(a) for a in argv] + ["--retry-backoff", "0.01"])
    return code, out.getvalue()


def parsed(path, rel, server):
    ncsa.parse.seen = {}
    report = common.Report()
    return [(parts, doc) for parts, doc in ncsa.parse(None, None, None, (path, rel, server), report)]


class ParseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_detect(self):
        for rel in ("apache/access.log", "apache/access.log.1.gz", "tomcat/localhost_access_log.2026-11-25.txt",
                    "W3SVC1/nc260408.log"):
            self.assertTrue(ncsa.detect(self.root / rel), rel)
        for rel in ("W3SVC1/u_ex260408.log", "misc/notes.txt", "misc/export.csv"):
            self.assertFalse(ncsa.detect(self.root / rel), rel)

    def test_guess_server(self):
        self.assertEqual(ncsa.guess_server("apache/access.log"), "apache")
        self.assertEqual(ncsa.guess_server("C/xampp/apache/logs/access.log"), "apache")
        self.assertEqual(ncsa.guess_server("var/log/httpd/access_log-20261125"), "apache")
        self.assertEqual(ncsa.guess_server("nginx/access.log.2.gz"), "nginx")
        self.assertEqual(ncsa.guess_server("tomcat/localhost_access_log.2026-11-25.txt"), "tomcat")
        self.assertEqual(ncsa.guess_server("logs/localhost_access_log.2026-11-25.txt"), "tomcat")
        self.assertEqual(ncsa.guess_server("W3SVC1/nc260408.log"), "iis")
        self.assertEqual(ncsa.guess_server("access.log"), "web")
        self.assertEqual(ncsa.guess_server("access.log", "nginx"), "nginx")

    def test_common_combined_and_vhost_lines(self):
        rows = parsed(self.root / "apache" / "access.log", "apache/access.log", "apache")
        docs = [d for p, d in rows if p is not None]
        self.assertEqual(len(docs), 6)
        self.assertEqual([d["httpd"]["log_format"] for d in docs],
                         ["common", "combined", "vhost_combined", "vhost_common", "combined", "partial"])
        common_doc, combined, vhost = docs[0], docs[1], docs[2]
        self.assertEqual(common_doc["@timestamp"], "2026-11-25T01:15:01.000000Z")    # +0800 -> UTC
        self.assertEqual(common_doc["source"]["ip"], "192.0.2.10")
        self.assertEqual(common_doc["url"]["path"], "/index.php")
        self.assertEqual(common_doc["url"]["query"], "id=1%27%20OR%201=1")
        self.assertEqual(common_doc["http"]["response"]["status_code"], 200)
        self.assertEqual(common_doc["destination"]["bytes"], 5120)
        self.assertEqual(common_doc["event"]["dataset"], "apache.access")
        self.assertEqual(common_doc["log"]["file"]["path"], "apache/access.log")
        self.assertNotIn("user_agent", common_doc)
        self.assertEqual(combined["server"]["user"]["name"], "frank")
        self.assertEqual(combined["http"]["request"]["method"], "POST")
        self.assertEqual(combined["http"]["request"]["referrer"], "https://example.com/wp-login.php")
        self.assertEqual(combined["user_agent"]["original"], "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertEqual(combined["destination"]["bytes"], 0)                       # "-" is 0
        self.assertEqual(vhost["url"]["domain"], "www.example.com")
        self.assertEqual(vhost["destination"]["port"], 443)
        self.assertEqual(docs[3]["destination"]["port"], 80)
        self.assertEqual(docs[4]["source"]["ip"], "2001:db8::5")
        self.assertEqual(docs[4]["sof-elk"]["rawrequest"], "\\x16\\x03\\x01")       # not a request line
        self.assertIn("partial_httpd_log", docs[5]["tags"])

    def test_tomcat_extra_fields_and_iis_user(self):
        docs = [d for _p, d in parsed(self.root / "tomcat" / "localhost_access_log.2026-11-25.txt", "x", "tomcat")]
        self.assertEqual(docs[0]["httpd"]["extra"], "12")          # %D after the common fields
        self.assertEqual(docs[0]["httpd"]["log_format"], "common")
        self.assertEqual(docs[1]["server"]["user"]["name"], "admin")
        self.assertEqual(docs[0]["event"]["dataset"], "tomcat.access")
        docs = [d for _p, d in parsed(self.root / "W3SVC1" / "nc260408.log", "W3SVC1/nc260408.log", "iis")]
        self.assertEqual(docs[0]["server"]["user"]["name"], "REDMOND\\fred")
        self.assertEqual(docs[0]["@timestamp"], "2026-04-09T01:39:04.000000Z")

    def test_every_field_is_mapped(self):
        exact = common.template_fields(common.load_templates("httpdlog")[2]["mappings"])
        for rel, server in (("apache/access.log", "apache"), ("tomcat/localhost_access_log.2026-11-25.txt", "tomcat"),
                            ("W3SVC1/nc260408.log", "iis")):
            for _p, doc in parsed(self.root / rel, rel, server):
                doc = dict(doc, host={"name": "web01", "os": {"type": "windows"}}, case="IR-1")
                self.assertEqual(common.unknown_fields(doc, exact), [], rel)

    def test_log_format_type_matches_every_httpdlog_template(self):
        for other in ("AWS/index_templates/index-httpdlog.json", "Windows/index_templates/index-httpdlog.json"):
            body = json.loads((REPO / other).read_text())["template"]["mappings"]
            self.assertNotEqual(common.template_fields(body).get("httpd.log_format", "keyword"), "text", other)

    def test_ids_ignore_the_folder_given(self):
        a = [p for p, _d in parsed(self.root / "apache" / "access.log", "apache/access.log", "apache")]
        b = [p for p, _d in parsed(self.root / "apache" / "access.log", "access.log", "apache")]
        self.assertEqual(a, b)
        self.assertEqual(a[0][1], "access.log")


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name))
        self.es = MockES()
        ncsa.NCSA.datasets = ncsa.DATASETS

    def tearDown(self):
        self.es.close()
        self.tmp.cleanup()

    def test_load_and_rerun(self):
        code, out = run_importer(self.root, "--hostname", "WEB01", "--case", "IR-1", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("4 NCSA access log file(s): 2 apache, 1 iis, 1 tomcat", out)
        self.assertIn("skipped 3 file(s)", out)
        self.assertIn("Index 'httpdlog-web01': created", out)
        docs = list(self.es.indices["httpdlog-web01"]["docs"].values())
        self.assertEqual(len(docs), 10)
        self.assertEqual({d["case"] for d in docs}, {"IR-1"})
        self.assertEqual({d["host"]["name"] for d in docs}, {"web01"})
        self.assertEqual({d["event"]["dataset"] for d in docs}, {"apache.access", "tomcat.access", "iis.access"})
        self.assertEqual(self.es.indices["httpdlog-web01"]["mappings"]["_meta"]["toolkit_schema"], "httpdlog")
        # the folder given differently: same ids, nothing new
        code, out = run_importer(self.root / "apache", "--hostname", "WEB01", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("Index 'httpdlog-web01': appending", out)
        self.assertIn("-> 0 new documents, 7 already in index", out)
        self.assertEqual(len(self.es.indices["httpdlog-web01"]["docs"]), 10)

    def test_iis_only_sets_windows(self):
        code, out = run_importer(self.root / "W3SVC1", "--hostname", "WEB01", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        doc = next(iter(self.es.indices["httpdlog-web01"]["docs"].values()))
        self.assertEqual(doc["host"]["os"]["type"], "windows")
        self.assertEqual(doc["event"]["dataset"], "iis.access")

    def test_appends_to_an_iis_w3c_index(self):
        win = json.loads((REPO / "Windows/index_templates/index-httpdlog.json").read_text())
        self.es.indices["httpdlog-web01"] = {"mappings": win["template"]["mappings"], "docs": {}}
        code, out = run_importer(self.root / "tomcat", "--hostname", "web01", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        props = self.es.indices["httpdlog-web01"]["mappings"]["properties"]
        self.assertIn("iis", props)
        self.assertIn("log_format", props["httpd"]["properties"])

    def test_refuses_an_index_it_did_not_make(self):
        self.es.indices["httpdlog-web01"] = {"mappings": {"properties": {}}, "docs": {}}
        with self.assertRaises(SystemExit) as cm:
            run_importer(self.root / "tomcat", "--hostname", "web01", "--es", self.es.url)
        self.assertIn("was not created by this importer", str(cm.exception))

    def test_nothing_found_and_dry_run(self):
        code, out = run_importer(self.root / "misc", "--hostname", "web01", "--dry-run")
        self.assertEqual(code, 1, out)
        self.assertIn("No NCSA common/combined access logs found.", out)
        code, out = run_importer(self.root, "--hostname", "web01", "--dry-run", "--local-tz", "+08:00",
                                 "--es", "http://127.0.0.1:9")
        self.assertEqual(code, 0, out)
        self.assertIn("--local-tz ignored", out)
        self.assertIn("Dry run only", out)
        self.assertIn("Line layouts: combined 3, common 4, partial 1, vhost_combined 1, vhost_common 1", out)


def load_wrapper():
    import importlib.util
    spec = importlib.util.spec_from_file_location("sof_elk_import_wrapper", REPO / "SOF-ELK_ImportWrapper.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WrapperDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name) / "evidence")
        # A UAC collection's own web logs stay with Linux/linux2sofelk.py.
        uac = Path(self.tmp.name) / "evidence" / "uac-web01"
        (uac / "[root]" / "var" / "log" / "apache2").mkdir(parents=True)
        (uac / "uac.log").write_text("uac\n")
        (uac / "[root]" / "var" / "log" / "apache2" / "access.log").write_text("\n".join(APACHE) + "\n")
        self.w = load_wrapper()
        self.ncsa = self.w.NcsaDetector(REPO)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detector_loaded(self):
        self.assertEqual(self.ncsa.error, "")
        self.assertEqual(self.w.CSV_IMPORTERS[self.w.NCSA_LABEL], ("ncsa2sofelk.py", "httpdlog"))
        self.assertIn(self.w.NCSA_LABEL, self.w.NO_LOCAL_TZ)

    def test_discovery(self):
        _json, csv_files, linux, _aws = self.w.discover(self.root, None, self.ncsa)
        names = sorted(p.relative_to(self.root).as_posix() for p in csv_files[self.w.NCSA_LABEL])
        self.assertEqual(names, ["W3SVC1/nc260408.log", "apache/access.log", "apache/access.log.1.gz",
                                 "tomcat/localhost_access_log.2026-11-25.txt"])
        self.assertEqual([p.name for p in csv_files[self.w.IIS_LABEL]], ["u_ex260408.log"])
        self.assertEqual([p.name for p in linux], ["uac-web01"])

    def test_discovery_without_detector(self):
        _json, csv_files, _linux, _aws = self.w.discover(self.root)
        self.assertEqual(csv_files[self.w.NCSA_LABEL], [])


if __name__ == "__main__":
    unittest.main()
