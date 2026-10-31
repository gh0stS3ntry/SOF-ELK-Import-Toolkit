#!/usr/bin/env python3
"""Tests for the phase 4 Linux importers: web server logs, FTP logs and browser history.

    python3 Linux/tests/test_linux_web_ftp_browser.py -v

Fixtures (Linux/tests/fixtures/):
  uac-web/        a UAC folder (Debian 12, Asia/Singapore): apache2 access (current and
                  rotated), other_vhosts_access, 2.4 and 2.2 error lines; nginx access and
                  error; lighttpd error; vsftpd.log with log_ftp_protocol (incl. a PASS command
                  and an anonymous login) and xferlog; vsftpd.conf with use_localtime=YES
  rhel-web-root/  a plain root filesystem (Rocky 9, America/New_York): httpd access_log with
                  dated rotation, ssl_request_log, ssl_error_log; xferlog with a vsftpd.conf
                  that leaves use_localtime at its default (UTC)
The browser databases (Firefox places.sqlite, Chrome History, one with an uncheckpointed -wal)
are built by the tests with sqlite3, then read from a folder and from a zip.
Every document is checked against the index template it is written with.
"""
import json
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "common"))

import browser2sofelk  # noqa: E402
import httpd2sofelk  # noqa: E402
import linux2sofelk  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402
import vsftpd2sofelk  # noqa: E402

FIXTURES = HERE / "fixtures"
REPO = HERE.parent.parent


def args(**kw):
    base = dict(web_log=None, ftp_log=None, ftp_time="auto", case=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def run(source, evidence, **kw):
    ev = common.Evidence(evidence)
    profile = common.HostProfile(ev)
    a = args(**kw)
    httpd2sofelk.parse.seen = {}
    vsftpd2sofelk.parse.seen = {}
    report = common.Report()
    docs, skipped = [], []
    for item in source.collect(ev, profile, a) or []:
        for parts, doc in source.parse(ev, profile, a, item, report):
            if parts is None:
                skipped.append(doc)
            else:
                docs.append((parts, doc))
    return docs, skipped, report


def find(docs, pred):
    return next(d for _, d in docs if pred(d))


def get(doc, dotted):
    return common.get_field(doc, dotted)


class TemplateCheck(unittest.TestCase):
    def assert_mapped(self, docs, prefix, template_set="linux"):
        _, _, body = common.load_templates(prefix, template_set)
        exact = common.template_fields(body["mappings"])
        for _, doc in docs:
            self.assertEqual(common.unknown_fields(doc, exact), [], doc)

    def assert_unique_ids(self, docs):
        ids = [json.dumps(p) for p, _ in docs]
        self.assertEqual(len(ids), len(set(ids)))


class HttpdTests(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.docs, cls.skipped, cls.report = run(httpd2sofelk.HTTPD, FIXTURES / "uac-web")

    def test_files_and_template(self):
        self.assertEqual(len(self.docs), 17)
        self.assertEqual(self.skipped, ["line in no known web log format"])
        self.assert_mapped(self.docs, "httpdlog")
        self.assertEqual(httpd2sofelk.HTTPD.prefix, "httpdlog")
        self.assertFalse(httpd2sofelk.HTTPD.index_template)  # SOF-ELK's own family

    def test_combined_line(self):
        d = find(self.docs, lambda d: get(d, "url.path") == "/uploads/shell.php")
        self.assertEqual(d["@timestamp"], "2026-10-30T14:16:40.000000Z")
        self.assertEqual(get(d, "source.ip"), "198.51.100.7")
        self.assertEqual(get(d, "server.user.name"), "admin")  # SOF-ELK: %u -> server.user.name
        self.assertEqual(get(d, "http.request.method"), "POST")
        self.assertEqual(get(d, "url.query"), "cmd=id")
        self.assertEqual(get(d, "url.original"), "/uploads/shell.php?cmd=id")
        self.assertEqual(get(d, "url.extension"), "php")
        self.assertEqual(get(d, "http.version"), "1.1")
        self.assertEqual(get(d, "http.response.status_code"), 200)
        self.assertEqual(get(d, "destination.bytes"), 37)
        self.assertEqual(get(d, "user_agent.original"), "python-requests/2.31.0")
        self.assertEqual(get(d, "event.dataset"), "apache.access")
        self.assertEqual(get(d, "labels.type"), "httpdlog")
        self.assertEqual(d["tags"], ["page"])
        self.assertNotIn("timezone", d["event"])  # access log times carry their own offset
        css = find(self.docs, lambda d: get(d, "url.path") == "/css/site.css")
        self.assertEqual(css["tags"], ["not_page"])
        self.assertEqual(get(css, "http.request.referrer"), "http://ftpweb01/index.php")

    def test_odd_requests(self):
        bad = find(self.docs, lambda d: get(d, "http.response.status_code") == 400
                   and get(d, "url.path") == "/../../etc/passwd")
        self.assertEqual(get(bad, "event.outcome"), "failure")
        proxy = find(self.docs, lambda d: get(d, "url.scheme") == "http")
        self.assertEqual(get(proxy, "source.ip"), "2001:db8::5")
        self.assertEqual(get(proxy, "url.domain"), "ftpweb01")
        self.assertEqual(get(proxy, "destination.port"), 8080)
        self.assertEqual(get(proxy, "url.path"), "/proxy/test")
        self.assertEqual(get(proxy, "url.query"), "a=1")
        self.assertNotIn("user_agent", proxy)
        raw = find(self.docs, lambda d: get(d, "sof-elk.rawrequest"))
        self.assertEqual(get(raw, "sof-elk.rawrequest"), "\\x16\\x03\\x01\\x02")
        connect = find(self.docs, lambda d: get(d, "http.request.method") == "CONNECT")
        self.assertEqual(get(connect, "url.path"), "(Tunnel setup request)")
        self.assertEqual(get(connect, "destination.port"), 443)
        old = find(self.docs, lambda d: get(d, "user_agent.original") == "Wget/1.21.3")
        self.assertEqual(get(old, "destination.bytes"), 0)  # "-" -> 0, as in SOF-ELK
        self.assertEqual(get(old, "http.version"), "1.0")

    def test_vhost_line(self):
        d = find(self.docs, lambda d: "other_vhosts" in d["log"]["file"]["path"])
        self.assertEqual(get(d, "url.domain"), "shop.example.com")
        self.assertEqual(get(d, "destination.port"), 443)
        self.assertEqual(get(d, "source.ip"), "203.0.113.50")
        self.assertEqual(get(d, "http.version"), "2.0")

    def test_apache_error_local_time(self):
        d = find(self.docs, lambda d: get(d, "apache.error.module") == "php")
        # 22:16:40.123456 in Asia/Singapore (+08:00)
        self.assertEqual(d["@timestamp"], "2026-10-30T14:16:40.123456Z")
        self.assertEqual(get(d, "event.timezone"), "Asia/Singapore")
        self.assertEqual(get(d, "event.dataset"), "apache.error")
        self.assertEqual(get(d, "log.level"), "error")
        self.assertEqual(get(d, "process.pid"), 4242)
        self.assertEqual(get(d, "source.ip"), "198.51.100.7")
        self.assertEqual(get(d, "source.port"), 51234)
        self.assertEqual(get(d, "http.request.referrer"), "http://ftpweb01/upload.php")
        self.assertTrue(get(d, "error.message").startswith("PHP Warning:"))
        denied = find(self.docs, lambda d: get(d, "error.code") == "AH00035")
        self.assertEqual(get(denied, "error.message"), "access to /../../etc/passwd denied")
        old = find(self.docs, lambda d: (get(d, "error.message") or "").startswith("File does not exist"))
        self.assertEqual(get(old, "log.level"), "error")
        self.assertEqual(get(old, "source.ip"), "192.0.2.1")
        self.assertEqual(old["@timestamp"], "2026-10-28T00:00:00.000000Z")

    def test_nginx_and_lighttpd(self):
        acc = find(self.docs, lambda d: get(d, "event.dataset") == "nginx.access")
        self.assertEqual(get(acc, "server.user.name"), "bob")
        self.assertEqual(get(acc, "http.response.status_code"), 401)
        err = find(self.docs, lambda d: get(d, "httpd.connection_id") == 15)
        self.assertEqual(get(err, "event.dataset"), "nginx.error")
        self.assertEqual(get(err, "source.ip"), "192.0.2.10")
        self.assertEqual(get(err, "url.path"), "/wp-login.php")
        self.assertEqual(get(err, "url.domain"), "ftpweb01")
        self.assertEqual(get(err, "httpd.server_name"), "ftpweb01")
        self.assertEqual(get(err, "http.request.referrer"), "http://ftpweb01/")
        self.assertTrue(get(err, "error.message").startswith('open() "/usr/share/nginx/html/wp-login.php" failed'))
        self.assertEqual(err["@timestamp"], "2026-10-30T15:00:00.000000Z")
        light = find(self.docs, lambda d: get(d, "event.dataset") == "lighttpd.error")
        self.assertEqual(get(light, "apache.error.module"), "server.c.1513")

    def test_identical_lines_kept_and_rotation_does_not_duplicate(self):
        # The same line twice in one collection is two requests: two documents.
        self.assert_unique_ids(self.docs)
        shells = [p for p, d in self.docs if get(d, "url.path") == "/uploads/shell.php"]
        self.assertEqual(len(shells), 2)
        # A later collection where access.log was rotated to access.log.1: same _id values.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "uac-web"
            shutil.copytree(FIXTURES / "uac-web", root)
            log = root / "[root]/var/log/apache2"
            (log / "access.log.1").unlink()
            (log / "access.log").rename(log / "access.log.1")
            later, _, _ = run(httpd2sofelk.HTTPD, root)
        first = {json.dumps(p) for p, d in self.docs if d["log"]["file"]["path"].endswith("apache2/access.log")}
        again = {json.dumps(p) for p, d in later if d["log"]["file"]["path"].endswith("apache2/access.log.1")}
        self.assertEqual(len(first), 8)
        self.assertEqual(first, again)

    def test_rhel_layout(self):
        docs, skipped, _ = run(httpd2sofelk.HTTPD, FIXTURES / "rhel-web-root")
        self.assertEqual((len(docs), skipped), (3, []))
        self.assert_mapped(docs, "httpdlog")
        acc = find(docs, lambda d: get(d, "url.path") == "/index.html")
        self.assertEqual(acc["@timestamp"], "2026-10-24T14:00:00.000000Z")
        ssl = find(docs, lambda d: get(d, "tls.protocol"))
        self.assertEqual(get(ssl, "tls.cipher"), "TLS_AES_256_GCM_SHA384")
        self.assertEqual(get(ssl, "destination.bytes"), 3120)
        self.assertEqual(get(ssl, "event.dataset"), "apache.access")
        err = find(docs, lambda d: get(d, "event.dataset") == "apache.error")
        self.assertEqual(err["@timestamp"], "2026-10-30T16:00:01.500000Z")  # EDT -04:00

    def test_web_log_option_and_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rhel"
            shutil.copytree(FIXTURES / "rhel-web-root", root)
            import gzip
            data = (root / "var/log/httpd/access_log-20261025").read_bytes()
            (root / "srv/shop/logs").mkdir(parents=True)
            (root / "srv/shop/logs/shop.log.gz").write_bytes(gzip.compress(data.replace(b"index", b"shop")))
            docs, _, _ = run(httpd2sofelk.HTTPD, root, web_log=["/srv/shop/logs/shop.log.gz"])
            d = find(docs, lambda d: get(d, "url.path") == "/shop.html")
            self.assertEqual(get(d, "event.dataset"), "web.access")

    def test_types_match_aws_httpdlog(self):
        """httpdlog-* holds ALB logs too: a field both define must have the same type."""
        linux = common.template_fields(common.load_templates("httpdlog")[2]["mappings"])
        aws = json.loads((REPO / "AWS/index_templates/index-httpdlog.json").read_text())
        aws_fields = common.template_fields(aws["template"]["mappings"])
        for name in set(linux) & set(aws_fields):
            self.assertEqual(linux[name], aws_fields[name], name)


class VsftpdTests(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.docs, cls.skipped, cls.report = run(vsftpd2sofelk.VSFTPD, FIXTURES / "uac-web")

    def test_counts_and_template(self):
        self.assertEqual((len(self.docs), self.skipped), (15, []))
        self.assert_mapped(self.docs, "logstash")
        self.assert_unique_ids(self.docs)
        self.assertEqual(vsftpd2sofelk.VSFTPD.prefix, "logstash")

    def test_passwords_never_loaded(self):
        text = json.dumps([d for _, d in self.docs])
        for secret in ("S3cr3t", "guest@example.com"):
            self.assertNotIn(secret, text)
        cmd = find(self.docs, lambda d: get(d, "ftp.command") == "PASS")
        self.assertEqual(get(cmd, "ftp.command_arg"), "<redacted>")
        self.assertTrue(cmd["message"].endswith('"PASS <redacted>"'))
        anon = find(self.docs, lambda d: get(d, "user.name") == "ftp")
        self.assertIn('anon password "<redacted>"', anon["message"])
        xfer = find(self.docs, lambda d: get(d, "ftp.access_mode") == "anonymous")
        self.assertEqual(get(xfer, "user.name"), "anonymous")
        self.assertIn(" a _ o a <redacted> ftp ", xfer["message"])

    def test_vsftpd_log(self):
        login = find(self.docs, lambda d: get(d, "ftp.action") == "FAIL LOGIN")
        # use_localtime=YES in the evidence's vsftpd.conf: Asia/Singapore
        self.assertEqual(login["@timestamp"], "2026-10-30T15:20:03.000000Z")
        self.assertEqual(get(login, "event.timezone"), "Asia/Singapore")
        self.assertEqual(get(login, "event.action"), "ftp-login")
        self.assertEqual(get(login, "event.outcome"), "failure")
        self.assertEqual(get(login, "event.category"), "authentication")
        self.assertEqual(get(login, "user.name"), "ftpuser")
        self.assertEqual(get(login, "source.ip"), "198.51.100.7")  # ::ffff: mapping removed
        self.assertEqual(get(login, "process.pid"), 3000)
        self.assertEqual(get(login, "log.syslog.appname"), "vsftpd")
        self.assertEqual(get(login, "event.dataset"), "ftp.vsftpd")
        up = find(self.docs, lambda d: get(d, "event.action") == "ftp-upload" and get(d, "event.dataset") == "ftp.vsftpd")
        self.assertEqual(get(up, "file.path"), "/home/ftpuser/upload/tool.tar.gz")
        self.assertEqual(get(up, "file.name"), "tool.tar.gz")
        self.assertEqual(get(up, "ftp.transfer.bytes"), 1048576)
        self.assertEqual(get(up, "ftp.transfer.rate"), "512.00Kbyte/sec")
        ren = find(self.docs, lambda d: get(d, "event.action") == "ftp-rename")
        self.assertEqual(get(ren, "file.path"), "/home/ftpuser/upload/tool.tar.gz")
        self.assertEqual(get(ren, "ftp.rename_to"), "/home/ftpuser/upload/.cache")
        mk = find(self.docs, lambda d: get(d, "event.action") == "ftp-mkdir")
        self.assertEqual(get(mk, "file.path"), "/home/ftpuser/new dir")
        resp = find(self.docs, lambda d: get(d, "ftp.response.code") == 331)
        self.assertEqual(get(resp, "ftp.response.message"), "Please specify the password.")
        conn = find(self.docs, lambda d: get(d, "event.action") == "ftp-connect")
        self.assertNotIn("user", conn)

    def test_xferlog(self):
        d = find(self.docs, lambda d: get(d, "file.name") == "customer list.csv")
        self.assertEqual(get(d, "event.dataset"), "ftp.xferlog")
        self.assertEqual(get(d, "event.action"), "ftp-download")
        self.assertEqual(get(d, "ftp.transfer.direction"), "outgoing")
        self.assertEqual(get(d, "ftp.transfer.duration"), 1)
        self.assertEqual(get(d, "ftp.completion"), "complete")
        self.assertEqual(get(d, "ftp.access_mode"), "real")
        self.assertEqual(d["@timestamp"], "2026-10-30T15:22:00.000000Z")
        bad = find(self.docs, lambda d: get(d, "ftp.completion") == "incomplete")
        self.assertEqual(get(bad, "event.outcome"), "failure")
        self.assertEqual(get(bad, "ftp.transfer.type"), "ascii")

    def test_default_utc_and_override(self):
        docs, _, _ = run(vsftpd2sofelk.VSFTPD, FIXTURES / "rhel-web-root")
        self.assertEqual(docs[0][1]["@timestamp"], "2026-10-30T16:05:00.000000Z")
        self.assertEqual(get(docs[0][1], "event.timezone"), "UTC")
        docs, _, _ = run(vsftpd2sofelk.VSFTPD, FIXTURES / "rhel-web-root", ftp_time="local")
        self.assertEqual(docs[0][1]["@timestamp"], "2026-10-30T20:05:00.000000Z")  # EDT -04:00

    def test_no_config_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            shutil.copytree(FIXTURES / "rhel-web-root", root)
            (root / "etc/vsftpd/vsftpd.conf").unlink()
            _, _, report = run(vsftpd2sofelk.VSFTPD, root)
            self.assertTrue(any("--ftp-time local" in w for w in report.warnings))


def make_firefox(path, wal=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
    con.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT,
            visit_count INTEGER, hidden INTEGER, typed INTEGER, frecency INTEGER, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
            visit_date INTEGER, visit_type INTEGER, session INTEGER, source INTEGER, triggeringPlaceId INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER,
            content TEXT, flags INTEGER, expiration INTEGER, type INTEGER, dateAdded INTEGER, lastModified INTEGER);
        INSERT INTO moz_places VALUES (1, 'https://www.google.com/search?q=mimikatz+linux', 'mimikatz linux - Google Search', '', 1, 0, 1, 0, 0);
        INSERT INTO moz_places VALUES (2, 'https://github.com/evil/tool/releases/download/v1/tool.tar.gz', NULL, '', 1, 0, 0, 0, 0);
        INSERT INTO moz_historyvisits VALUES (1, 0, 1, 1793440000000000, 2, 0, 3, NULL);
        INSERT INTO moz_historyvisits VALUES (2, 1, 2, 1793440005000000, 7, 0, 0, NULL);
        INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI'), (2, 'downloads/metaData');
        INSERT INTO moz_annos VALUES (1, 2, 1, 'file:///home/alice/Downloads/tool%20v1.tar.gz', 0, 4, 3, 1793440005000000, 0);
        INSERT INTO moz_annos VALUES (2, 2, 2, '{"state":1,"deleted":false,"endTime":1793440009000,"fileSize":4096}', 0, 4, 3, 1793440005000000, 0);
    """)
    con.commit()
    return con


def make_chrome(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    off = browser2sofelk.WEBKIT_EPOCH_OFFSET_US
    con.executescript(f"""
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
            typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
            transition INTEGER, segment_id INTEGER, visit_duration INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT,
            start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER,
            interrupt_reason INTEGER, end_time INTEGER, opened INTEGER, referrer TEXT, tab_url TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
        INSERT INTO urls VALUES (1, 'https://pastebin.com/raw/abc', 'Pastebin', 2, 1, 0, 0);
        INSERT INTO urls VALUES (2, 'https://example.org/next', 'Next', 1, 0, 0, 0);
        INSERT INTO visits VALUES (1, 1, {1793440000000000 + off}, 0, {1 | 0x02000000 | 0x10000000 | 0x20000000}, 0, 65250000);
        INSERT INTO visits VALUES (2, 2, {1793440060000000 + off}, 1, 0, 0, 0);
        INSERT INTO downloads VALUES (1, 'g-1', '/root/Downloads/x.sh', '/root/Downloads/x.sh', {1793440100000000 + off},
            512, 512, 1, 0, 0, {1793440101000000 + off}, 1, 'https://pastebin.com/', 'https://pastebin.com/raw/abc', 'text/x-sh');
        INSERT INTO downloads_url_chains VALUES (1, 0, 'https://pastebin.com/dl/x');
        INSERT INTO downloads_url_chains VALUES (1, 1, 'https://cdn.example.net/x.sh');
    """)
    con.commit()
    con.close()


class BrowserTests(TemplateCheck):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "uac-web"
        shutil.copytree(FIXTURES / "uac-web", self.root)
        home = self.root / "[root]/home/alice"
        # Firefox in WAL mode, the open connection keeps the visits in places.sqlite-wal only.
        ff = home / ".mozilla/firefox/ab12cd34.default-release/places.sqlite"
        self.ff_con = make_firefox(ff, wal=True)
        self.assertTrue((ff.parent / "places.sqlite-wal").stat().st_size > 0)
        snapshot = ff.parent.parent / "snapshot"
        snapshot.mkdir()
        shutil.copy(ff, snapshot / "places.sqlite")
        shutil.copy(str(ff) + "-wal", snapshot / "places.sqlite-wal")
        self.ff_con.close()
        shutil.rmtree(ff.parent)
        snapshot.rename(ff.parent)
        # Files that must never be read
        (ff.parent / "logins.json").write_text('{"logins": [{"encryptedPassword": "x"}]}')
        (ff.parent / "key4.db").write_bytes(b"SQLite format 3\x00secret")
        make_chrome(self.root / "[root]/root/.config/google-chrome/Default/History")
        (self.root / "[root]/root/.config/google-chrome/Default/Cookies").write_bytes(b"SQLite format 3\x00c")

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, docs):
        self.assertEqual(len(docs), 6)
        self.assert_mapped(docs, "browsinghistory", "windows")
        self.assert_unique_ids(docs)
        search = find(docs, lambda d: get(d, "browsinghistory.visit_type") == "Typed"
                      and get(d, "browsinghistory.web_browser") == "Firefox")
        self.assertEqual(search["@timestamp"], "2026-10-31T09:46:40.000000Z")
        self.assertEqual(get(search, "browsinghistory.visit_time"), search["@timestamp"])
        self.assertEqual(get(search, "url.domain"), "www.google.com")
        self.assertEqual(get(search, "user.name"), "alice")
        self.assertEqual(get(search, "browsinghistory.user_profile"), "/home/alice")
        self.assertEqual(get(search, "browsinghistory.browser_profile"), "ab12cd34.default-release")
        self.assertEqual(get(search, "browsinghistory.history_file"),
                         "/home/alice/.mozilla/firefox/ab12cd34.default-release/places.sqlite")
        self.assertEqual(get(search, "browsinghistory.visit_source"), "searched")
        self.assertEqual(get(search, "event.dataset"), "browsinghistory")
        dl_visit = find(docs, lambda d: get(d, "browsinghistory.transition") == 7)
        self.assertEqual(get(dl_visit, "browsinghistory.visit_type"), "Download")
        self.assertEqual(get(dl_visit, "browsinghistory.visited_from"), "https://www.google.com/search?q=mimikatz+linux")
        ff_dl = find(docs, lambda d: get(d, "event.dataset") == "browsinghistory.download"
                     and get(d, "browsinghistory.web_browser") == "Firefox")
        self.assertEqual(get(ff_dl, "file.path"), "/home/alice/Downloads/tool v1.tar.gz")
        self.assertEqual(get(ff_dl, "file.extension"), "gz")
        self.assertEqual(get(ff_dl, "browsinghistory.download.state"), "complete")
        self.assertEqual(get(ff_dl, "browsinghistory.download.end_time"), "2026-10-31T09:46:49.000000Z")
        self.assertEqual(get(ff_dl, "browsinghistory.download.total_bytes"), 4096)
        chrome = find(docs, lambda d: get(d, "browsinghistory.web_browser") == "Chrome"
                      and get(d, "event.dataset") == "browsinghistory")
        self.assertEqual(chrome["@timestamp"], "2026-10-31T09:46:40.000000Z")
        self.assertEqual(get(chrome, "user.name"), "root")
        self.assertEqual(get(chrome, "browsinghistory.browser_profile"), "Default")
        self.assertEqual(get(chrome, "browsinghistory.visit_type"), "Typed")
        self.assertEqual(get(chrome, "browsinghistory.transition_qualifiers"),
                         ["FROM_ADDRESS_BAR", "CHAIN_START", "CHAIN_END"])
        self.assertEqual(get(chrome, "browsinghistory.visit_duration"), "00:01:05.250")
        self.assertEqual(get(chrome, "browsinghistory.typed_count"), 1)
        nxt = find(docs, lambda d: get(d, "url.original") == "https://example.org/next")
        self.assertEqual(get(nxt, "browsinghistory.visited_from"), "https://pastebin.com/raw/abc")
        cdl = find(docs, lambda d: get(d, "event.dataset") == "browsinghistory.download"
                   and get(d, "browsinghistory.web_browser") == "Chrome")
        self.assertEqual(get(cdl, "url.original"), "https://cdn.example.net/x.sh")  # end of the redirect chain
        self.assertEqual(get(cdl, "file.path"), "/root/Downloads/x.sh")
        self.assertEqual(get(cdl, "file.size"), 512)
        self.assertEqual(get(cdl, "browsinghistory.download.opened"), True)
        self.assertEqual(get(cdl, "browsinghistory.download.danger_type"), "not dangerous")
        self.assertEqual(get(cdl, "browsinghistory.visit_type"), "Download")
        text = json.dumps([d for _, d in docs])
        self.assertNotIn("encryptedPassword", text)

    def test_folder(self):
        ev = common.Evidence(self.root)
        items = browser2sofelk.collect(ev, common.HostProfile(ev), args())
        names = sorted(Path(i[2]).name for i in items)
        self.assertEqual(names, ["History", "places.sqlite"])  # not Cookies, key4.db, logins.json
        docs, skipped, report = run(browser2sofelk.BROWSER, self.root)
        self.assertEqual((skipped, report.warnings), ([], []))
        self.check(docs)

    def test_zip(self):
        z = Path(self.tmp.name) / "uac-web.zip"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(self.root.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(self.root.parent).as_posix())
        docs, _, _ = run(browser2sofelk.BROWSER, z)
        self.check(docs)

    def test_damaged_database_warns(self):
        bad = self.root / "[root]/home/bob/.config/chromium/Default/History"
        bad.parent.mkdir(parents=True)
        bad.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
        docs, _, report = run(browser2sofelk.BROWSER, self.root)
        self.assertEqual(len(docs), 6)
        self.assertTrue(any("/home/bob/.config/chromium/Default/History" in w for w in report.warnings))

    def test_hunting_fields_are_mapped(self):
        """The browsinghistory hunting queries keep these fields; Linux documents fill them."""
        exact = common.template_fields(common.load_templates("browsinghistory", "windows")[2]["mappings"])
        for name in ("url.original", "url.domain", "user.name", "browsinghistory.visit_time",
                     "browsinghistory.web_browser", "browsinghistory.browser_profile", "browsinghistory.title",
                     "browsinghistory.visit_type", "browsinghistory.visited_from", "browsinghistory.visit_count",
                     "browsinghistory.typed_count", "browsinghistory.history_file", "host.id", "host.os.family"):
            self.assertIn(name, exact)


class FrontEndTests(unittest.TestCase):
    def test_sources_registered(self):
        self.assertEqual([s.name for s in linux2sofelk.SOURCES],
                         ["journal", "syslog", "auditd", "bodyfile", "wtmp", "packages", "linuxconfig", "httpd", "browser", "vsftpd"])

    def test_installer_excludes_httpdlog_template(self):
        """Install-ForensicELK.ps1 must not install either httpdlog template (SOF-ELK owns httpdlog-*)."""
        text = (REPO / "Install-ForensicELK.ps1").read_text(encoding="utf-8")
        self.assertIn("Exclude = @('index-logstash.json', 'index-httpdlog.json')", text)


if __name__ == "__main__":
    unittest.main()
