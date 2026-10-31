#!/usr/bin/env python3
"""Tests for the Linux importers (standard library only, no Elasticsearch needed).

    python3 Linux/tests/test_linux_importers.py -v

Fixtures (Linux/tests/fixtures/):
  rhel-root/   a collected root filesystem that is not UAC (Rocky 9): secure with a December ->
               January rollover, a dated and (in the test) gzip/xz-rotated messages file,
               firewalld, America/New_York /etc/localtime
  uac-ubuntu/  a UAC folder (Ubuntu 24.04): ISO 8601 auth.log and syslog (with RFC 5424 and UFW
               lines) and a journalctl -o json export with byte-array and repeated fields
  uac-nojson/  a UAC folder with binary journal files but no JSON export
Every document is checked against index-logstash.json: a field the template does not map
would be silently dropped by Elasticsearch (the index uses dynamic: false).
"""
import datetime as dt
import gzip
import lzma
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "common"))

import journal2sofelk  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402
import syslog2sofelk  # noqa: E402
from sof_elk_linux_messages import enrich  # noqa: E402

FIXTURES = HERE / "fixtures"


def args(**kw):
    base = dict(journal_json=None, syslog_file=None, year=None, case=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def run(source, evidence, hostname=None, local_tz=None, **kw):
    ev = common.Evidence(evidence)
    profile = common.HostProfile(ev, hostname, local_tz)
    a = args(**kw)
    syslog2sofelk.parse.seen = {}
    report = common.Report()
    docs, skipped = [], []
    for item in source.collect(ev, profile, a) or []:
        for parts, doc in source.parse(ev, profile, a, item, report):
            if parts is None:
                skipped.append(doc)
            else:
                docs.append((parts, doc))
    return ev, profile, docs, skipped, report


def by_message(docs, text):
    return next(d for _, d in docs if text in (d.get("message") or ""))


class TemplateCheck(unittest.TestCase):
    def assert_mapped(self, docs):
        _, _, body = common.load_templates("logstash")
        exact = common.template_fields(body["mappings"])
        for _, doc in docs:
            self.assertEqual(common.unknown_fields(doc, exact), [], doc)


class EvidenceTests(unittest.TestCase):
    def test_uac_folder_profile(self):
        ev = common.Evidence(FIXTURES / "uac-ubuntu")
        self.assertTrue(ev.is_uac)
        self.assertEqual(ev.root, "[root]")
        p = common.HostProfile(ev)
        self.assertEqual(p.hostname, "web01")
        self.assertEqual(p.os["family"], "debian")
        self.assertEqual(p.os["version"], "24.04")
        self.assertEqual(p.os["kernel"], "6.8.0-45-generic")

    def test_plain_root_profile(self):
        ev = common.Evidence(FIXTURES / "rhel-root")
        self.assertFalse(ev.is_uac)
        p = common.HostProfile(ev)
        self.assertEqual((p.hostname, p.os["family"], p.os["platform"]), ("web02", "redhat", "rocky"))
        self.assertEqual(p.host_id, "0123456789abcdef0123456789abcdef")
        # America/New_York read from the evidence's /etc/localtime (TZif), not this machine.
        self.assertEqual(dt.datetime(2026, 7, 1, tzinfo=p.tz).utcoffset(), dt.timedelta(hours=-4))
        self.assertEqual(dt.datetime(2026, 1, 1, tzinfo=p.tz).utcoffset(), dt.timedelta(hours=-5))

    def test_root_found_one_level_down_and_hostname_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(FIXTURES / "rhel-root", Path(tmp) / "uploads" / "rootfs")
            ev = common.Evidence(tmp)
            self.assertEqual(ev.root, "uploads/rootfs")
            p = common.HostProfile(ev, "WEB 02-B")
            self.assertEqual(p.hostname, "web-02-b")
            self.assertTrue(any("differs" in n for n in p.notes))

    def test_zip_is_read_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "uac-web01.zip"
            with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in (FIXTURES / "uac-ubuntu").rglob("*"):
                    if f.is_file():
                        zf.write(f, f.relative_to(FIXTURES / "uac-ubuntu").as_posix())
            ev, profile, docs, _, _ = run(journal2sofelk.JOURNAL, z)
            self.assertEqual(profile.hostname, "web01")
            self.assertEqual(len(docs), 2)
            _, _, sdocs, _, _ = run(syslog2sofelk.SYSLOG, z)
            self.assertEqual(len(sdocs), 8)


class JournalTests(TemplateCheck):
    def setUp(self):
        self.ev, self.profile, self.docs, self.skipped, self.report = run(
            journal2sofelk.JOURNAL, FIXTURES / "uac-ubuntu")

    def test_fields(self):
        self.assertEqual(len(self.docs), 2)
        self.assertEqual(sorted(self.skipped), ["entry without a valid __REALTIME_TIMESTAMP",
                                                "line is not JSON (is this a journalctl -o json export?)"])
        parts, d = self.docs[0]
        self.assertEqual(parts, ["journal", "s=aa;i=1;b=bb;m=1;t=1;x=1"])
        self.assertEqual(d["@timestamp"], "2026-10-31T10:00:00.000000Z")
        self.assertEqual(d["log"]["syslog"]["appname"], "sshd")
        self.assertEqual(d["log"]["syslog"]["facility"], {"code": 10, "name": "security/authorization"})
        self.assertEqual(d["log"]["syslog"]["priority"], 86)
        self.assertEqual(d["event"]["dataset"], "syslog.journal")
        self.assertEqual(d["journald"]["unit"], "ssh.service")
        self.assertEqual((d["user"]["name"], d["source"]["ip"], d["ssh"]["auth_result"]),
                         ("carol", "192.0.2.10", "accepted"))
        self.assertEqual(d["process"]["user"]["id"], "0")
        self.assertNotIn("extra", d["journald"])  # SYSLOG_TIMESTAMP is dropped
        self.assert_mapped(self.docs)

    def test_binary_and_repeated_values(self):
        d = self.docs[1][1]
        self.assertEqual(d["message"], "hi�\nthere")
        self.assertEqual(d["journald"]["extra"], ["CUSTOM_FIELD=one\ntwo"])

    def test_machine_id_mismatch_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(FIXTURES / "uac-ubuntu", Path(tmp) / "c")
            (Path(tmp) / "c" / "[root]" / "etc" / "machine-id").write_text("0" * 32 + "\n")
            _, _, _, _, report = run(journal2sofelk.JOURNAL, Path(tmp) / "c")
            self.assertTrue(any("_MACHINE_ID" in w for w in report.warnings))

    def test_missing_export_explains_journalctl(self):
        ev = common.Evidence(FIXTURES / "uac-nojson")
        profile = common.HostProfile(ev)
        self.assertEqual(journal2sofelk.collect(ev, profile, args()), [])
        code, message = journal2sofelk.missing(ev, profile, args())
        self.assertEqual(code, 3)
        self.assertIn("journalctl --directory=", message)
        self.assertIn("[root]/var/log/journal/0123456789abcdef0123456789abcdef", message)
        self.assertIn("mkdir -p", message)
        code, message = journal2sofelk.missing(common.Evidence(FIXTURES / "rhel-root"), profile, args())
        self.assertEqual(code, 0)

    def test_journal_json_option(self):
        export = FIXTURES / "uac-ubuntu" / "journal" / "journalctl_full_journal_logs.json"
        with tempfile.TemporaryDirectory() as tmp:
            gz = Path(tmp) / "export.json.gz"
            gz.write_bytes(gzip.compress(export.read_bytes()))
            _, profile, docs, _, _ = run(journal2sofelk.JOURNAL, FIXTURES / "uac-nojson", journal_json=[str(gz)])
            self.assertEqual((len(docs), profile.hostname), (2, "db01"))


class SyslogTests(TemplateCheck):
    def rhel(self):
        """rhel-root copied with fixed mtimes, plus gzip and xz rotated copies of messages."""
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / "r"
        shutil.copytree(FIXTURES / "rhel-root", root)
        log = root / "var" / "log"
        stamp = dt.datetime(2026, 1, 3, 12, 0).timestamp()
        os.utime(log / "secure", (stamp, stamp))
        data = (log / "messages-20261025").read_bytes()
        (log / "messages-20261018.gz").write_bytes(gzip.compress(data.replace(b"Oct 24", b"Oct 17")))
        (log / "messages-20261011.xz").write_bytes(lzma.compress(data.replace(b"Oct 24", b"Oct 10")))
        for f in log.glob("messages*"):
            s = dt.datetime(2026, 10, 25, 3, 0).timestamp()
            os.utime(f, (s, s))
        self.addCleanup(tmp.cleanup)
        return root

    def test_rfc3164_year_rollover_and_local_time(self):
        _, profile, docs, skipped, report = run(syslog2sofelk.SYSLOG, self.rhel())
        secure = [d for _, d in docs if d["log"]["file"]["path"].endswith("secure")]
        self.assertEqual(len(secure), 10)
        # Dec 30 23:59:01 EST (UTC-5) in 2025, Jan 2 in 2026 (file mtime 2026-01-03)
        self.assertEqual(secure[0]["@timestamp"], "2025-12-31T04:59:01.000000Z")
        self.assertEqual(secure[3]["@timestamp"], "2026-01-02T15:15:42.000000Z")
        self.assertEqual(secure[0]["event"]["timezone"], "evidence /etc/localtime")
        self.assertTrue(report.warnings)
        self.assert_mapped(docs)

    def test_year_option(self):
        _, _, docs, _, _ = run(syslog2sofelk.SYSLOG, self.rhel(), year=2024)
        secure = [d for _, d in docs if d["log"]["file"]["path"].endswith("secure")]
        self.assertTrue(secure[0]["@timestamp"].startswith("2023-12-31"))

    def test_rhel_messages(self):
        _, _, docs, _, _ = run(syslog2sofelk.SYSLOG, self.rhel(), local_tz="+00:00")
        paths = sorted({d["log"]["file"]["path"] for _, d in docs})
        self.assertEqual(paths, ["var/log/firewalld", "var/log/messages-20261011.xz",
                                 "var/log/messages-20261018.gz", "var/log/messages-20261025", "var/log/secure"])
        tb = by_message(docs, "Traceback")
        self.assertIn('File "/opt/app/run.py"', tb["message"])  # continuation line kept
        fw = [d for _, d in docs if d.get("tags") and "got_iptables" in d["tags"]][0]
        self.assertEqual((fw["source"]["ip"], fw["destination"]["port"], fw["network"]["transport"]),
                         ("203.0.113.7", 22, "tcp"))
        self.assertEqual(fw["host"]["uptime"], 1234.56789)
        self.assertEqual(fw["source"]["mac"], "00-50-56-DD-EE-FF")
        self.assertIn("kernel_module", by_message(docs, "module verification failed")["tags"])
        cron = by_message(docs, "backup.sh")
        self.assertEqual((cron["event"]["action"], cron["user"]["name"]), ("cron-command", "root"))
        fwd = by_message(docs, "COMMAND_FAILED")
        self.assertEqual((fwd["log"]["syslog"]["appname"], fwd["@timestamp"]),
                         ("firewalld", "2026-10-24T03:15:00.000000Z"))

    def test_auth_events(self):
        _, _, docs, _, _ = run(syslog2sofelk.SYSLOG, self.rhel(), local_tz="UTC")
        sudo_fail = by_message(docs, "incorrect password")
        self.assertEqual((sudo_fail["event"]["outcome"], sudo_fail["sudo"]["result"],
                          sudo_fail["process"]["command_line"]),
                         ("failure", "3 incorrect password attempts", "/bin/cat /etc/shadow"))
        login = by_message(docs, "Accepted publickey")
        self.assertEqual((login["ssh"]["key_type"], login["ssh"]["login_method"]), ("ED25519", "publickey"))
        user = by_message(docs, "new user: name=bob")
        self.assertEqual((user["event"]["action"], user["user"]["target"]["name"], user["account"]["shell"]),
                         ("user-created", "bob", "/bin/bash"))
        grp = by_message(docs, "to group 'wheel'")
        self.assertEqual((grp["event"]["action"], grp["group"]["name"]), ("group-membership-added", "wheel"))
        su = by_message(docs, "FAILED SU")
        self.assertEqual((su["event"]["outcome"], su["user"]["name"], su["user"]["effective"]["name"]),
                         ("failure", "bob", "root"))
        bad = by_message(docs, "Failed password")
        self.assertEqual((bad["ssh"]["user_validity"], bad["user"]["name"]), ("invalid", "admin"))

    def test_rotated_copy_does_not_duplicate(self):
        root = self.rhel()
        log = root / "var" / "log"
        shutil.copy(log / "secure", log / "secure-20260101")
        _, _, docs, _, _ = run(syslog2sofelk.SYSLOG, root)
        ids = [common.doc_id("logstash", "web02", *p) for p, _ in docs]
        self.assertEqual(len(docs), 23 + 10)
        # the same line in two files of one family is two documents (occurrence count)
        self.assertEqual(len(set(ids)), len(ids))

    def test_ubuntu_iso_rfc5424_ufw(self):
        _, _, docs, _, _ = run(syslog2sofelk.SYSLOG, FIXTURES / "uac-ubuntu")
        self.assertEqual(len(docs), 8)
        ufw = by_message(docs, "UFW BLOCK")
        self.assertEqual((ufw["iptables"]["label"], ufw["event"]["action"], ufw["destination"]["port"]),
                         ("UFW BLOCK", "firewall-block", 3389))
        app = by_message(docs, "Application event")
        self.assertEqual((app["log"]["syslog"]["appname"], app["log"]["syslog"]["msgid"],
                          app["log"]["syslog"]["severity"]["name"], app["@timestamp"]),
                         ("myapp", "ID47", "Informational", "2026-10-30T22:11:00.000000Z"))
        neg = by_message(docs, "Unable to negotiate")
        self.assertEqual(neg["ssh"]["source_kex_methods"], ["diffie-hellman-group1-sha1",
                                                            "diffie-hellman-group14-sha1"])
        fail = by_message(docs, "authentication failure")
        self.assertEqual((fail["pam"]["event"], fail["user"]["target"]["name"], fail["event"]["outcome"]),
                         ("authentication_failure", "carol", "failure"))
        pk = by_message(docs, "Executing command")
        self.assertEqual((pk["user"]["name"], pk["process"]["command_line"]), ("carol", "/usr/bin/bash"))
        self.assertNotIn("timezone", ufw["event"])  # ISO time with an offset: no local time used
        self.assert_mapped(docs)


class MessageTests(unittest.TestCase):
    def test_pam_old_and_new_session_format(self):
        new, old = {}, {}
        enrich(new, "sudo", "pam_unix(sudo:session): session opened for user root(uid=0) by kali(uid=1000)")
        enrich(old, "su", "pam_unix(su:session): session opened for user root by (uid=1000)")
        self.assertEqual((new["user"]["name"], new["user"]["id"], new["pam"]["by_user"]), ("root", "0", "kali"))
        self.assertEqual((old["user"]["name"], old["user"]["id"]), ("root", "1000"))

    def test_unrelated_message_untouched(self):
        doc = {}
        self.assertFalse(enrich(doc, "NetworkManager", "device (eth0): state change"))
        self.assertEqual(doc, {})


class WrapperDiscoveryTests(unittest.TestCase):
    """SOF-ELK_ImportWrapper.py hands UAC collections to linux2sofelk.py and skips their files."""

    def test_uac_folder_and_zip_are_found_and_pruned(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "wrapper", HERE.parent.parent / "SOF-ELK_ImportWrapper.py")
        wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(wrapper)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(FIXTURES / "uac-ubuntu", root / "case" / "uac-ubuntu")
            # A CSV inside the collection's [root] must not reach the Windows importers.
            stray = root / "case" / "uac-ubuntu" / "[root]" / "tmp" / "20260101_EvtxECmd_Output.csv"
            stray.parent.mkdir(parents=True)
            stray.write_text("TimeCreated,EventId\n")
            with zipfile.ZipFile(root / "uac-db01.zip", "w") as zf:
                zf.writestr("uac.log", "Hostname: db01\n")
                zf.writestr("[root]/etc/hostname", "db01\n")
            with zipfile.ZipFile(root / "other.zip", "w") as zf:
                zf.writestr("notes.txt", "x")
            json_files, csv_files, linux = wrapper.discover(root)
            self.assertEqual(sorted(p.name for p in linux), ["uac-db01.zip", "uac-ubuntu"])
            self.assertFalse(any(csv_files.values()))
            self.assertFalse(any(json_files.values()))


if __name__ == "__main__":
    unittest.main()
