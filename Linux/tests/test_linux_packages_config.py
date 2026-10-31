#!/usr/bin/env python3
"""Tests for packages2sofelk.py and linuxconfig2sofelk.py (standard library only, no Elasticsearch).

    python3 Linux/tests/test_linux_packages_config.py -v

Fixtures (Linux/tests/fixtures/):
  pkgcfg-uac-debian/   UAC folder (Debian 12, Asia/Singapore) with a bodyfile: dpkg.log, apt
                       history.log, dpkg status, passwd/passwd-/shadow/group/group-, sudoers(.d),
                       cron in every location, systemd units, a wants link, masks and a drop-in,
                       rc.local, profile files, XDG autostart, SSH keys, hosts, resolver,
                       ld.so.preload, apt .list and deb822 sources, plus files that must never be
                       loaded (shadow hashes, a private key, shell history)
  pkgcfg-rhel-root/    a plain root (Rocky 9): dnf.rpm.log, yum.log with a year rollover, yum
                       .repo files, /var/spool/cron, rc.d/init.d. The test adds symlinks
                       (absolute ones, which must be resolved inside the evidence), an rpmdb.sqlite
                       and a dnf history.sqlite in a temporary copy.
  pkgcfg-suse-root/    zypp/history (command, install, radd, remove), zypper .repo, cron tabs
  pkgcfg-alpine-root/  /lib/apk/db/installed + /etc/apk/world, apk repositories, busybox crontab,
                       /etc/periodic, /etc/local.d
Every document is checked against its index template (dynamic: false would drop unmapped fields).
"""
import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "common"))

import linux2sofelk  # noqa: E402
import linuxconfig2sofelk  # noqa: E402
import packages2sofelk  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402

FIXTURES = HERE / "fixtures"
DEBIAN = FIXTURES / "pkgcfg-uac-debian"
SECRETS = ("FIXTURESALTDONOTLEAK", "FIXTUREHASHDONOTLEAK", "FIXTUREHASH2DONOTLEAK", "FIXTURESALT2",
           "FIXTUREDESHASH", "FIXTUREPRIVATEKEYDONOTLOAD", "FIXTUREHISTORYDONOTLOAD")


def run(source, evidence, hostname=None, local_tz=None, **kw):
    ev = common.Evidence(evidence)
    profile = common.HostProfile(ev, hostname, local_tz)
    a = types.SimpleNamespace(year=None, case=None, **kw)
    if source is packages2sofelk.PACKAGES:
        packages2sofelk.parse.occ = packages2sofelk.Occurrences()
    report = common.Report()
    docs, skipped = [], []
    for item in source.collect(ev, profile, a) or []:
        for parts, doc in source.parse(ev, profile, a, item, report):
            if parts is None:
                skipped.append(doc)
            else:
                docs.append((parts, doc))
    return docs, skipped, report


def ds(docs, name):
    return [d for _, d in docs if d["event"]["dataset"] == name]


def get(doc, dotted):
    return common.get_field(doc, dotted)


def find(docs, dataset, **match):
    for d in ds(docs, dataset):
        if all(get(d, k.replace("__", ".")) == v for k, v in match.items()):
            return d
    raise AssertionError(f"no {dataset} document with {match}")


class MappingCheck(unittest.TestCase):
    def assert_mapped(self, docs, prefix):
        _, _, body = common.load_templates(prefix)
        exact = common.template_fields(body["mappings"])
        for _, doc in docs:
            self.assertEqual(common.unknown_fields(doc, exact), [], doc)
            self.assertIn("@timestamp", doc)
        ids = [common.doc_id(prefix, "h", *p) for p, _ in docs]
        self.assertEqual(len(ids), len(set(ids)), "duplicate _id values")

    def assert_no_secrets(self, docs):
        blob = json.dumps([d for _, d in docs])
        for secret in SECRETS:
            self.assertNotIn(secret, blob)


# --------------------------------------------------------------------------- packages

class DebianPackagesTests(MappingCheck):
    @classmethod
    def setUpClass(cls):
        cls.docs, cls.skipped, cls.report = run(packages2sofelk.PACKAGES, DEBIAN)

    def test_mapping_and_secrets(self):
        self.assert_mapped(self.docs, "packages")
        self.assert_no_secrets(self.docs)

    def test_dpkg_actions_local_time(self):
        d = find(self.docs, "packages.dpkg", package__name="openssl")
        self.assertEqual(d["event"]["action"], "upgrade")
        self.assertEqual(d["package"]["version"], "3.0.13-1")
        self.assertEqual(d["packages"]["previous_version"], "3.0.11-1")
        self.assertEqual(d["package"]["architecture"], "amd64")
        self.assertEqual(d["@timestamp"], "2026-10-20T01:24:11.000000Z")  # 09:24:11 +08:00
        self.assertEqual(d["event"]["timezone"], "Asia/Singapore")
        self.assertEqual(find(self.docs, "packages.dpkg", package__name="nano")["event"]["action"], "reinstall")
        removed = find(self.docs, "packages.dpkg", event__action="purge")
        self.assertEqual(removed["package"]["version"], "1.219-1")
        self.assertEqual(removed["event"]["type"], ["deletion"])
        self.assertIn("dpkg.log status line (not a package action)", self.skipped)

    def test_apt_transaction(self):
        d = find(self.docs, "packages.apt", package__name="libcurl4")
        self.assertTrue(d["packages"]["automatic"])
        self.assertEqual(d["process"]["command_line"], "apt install curl")
        self.assertEqual(d["user"], {"name": "alice", "id": "1000"})
        self.assertEqual(d["event"]["end"], "2026-10-20T01:24:12.000000Z")
        self.assertEqual(d["event"]["outcome"], "success")
        up = find(self.docs, "packages.apt", package__name="openssl")
        self.assertEqual((up["packages"]["previous_version"], up["package"]["version"]), ("3.0.11-1", "3.0.13-1"))
        failed = find(self.docs, "packages.apt", event__action="purge")
        self.assertEqual(failed["event"]["outcome"], "failure")
        self.assertIn("dpkg returned an error", failed["error"]["message"])

    def test_dpkg_inventory_install_time_from_bodyfile(self):
        curl = find(self.docs, "packages.inventory", package__name="curl")
        self.assertEqual(curl["package"]["installed"], "2026-10-20T01:24:10.000000Z")
        self.assertEqual(curl["@timestamp"], curl["package"]["installed"])
        self.assertEqual(curl["package"]["size"], 500 * 1024)
        self.assertEqual(curl["packages"]["source_package"], "curl")
        self.assertEqual(curl["event"]["kind"], "state")
        nc = find(self.docs, "packages.inventory", package__name="netcat-openbsd")
        self.assertEqual(nc["event"]["action"], "config-files")
        self.assertNotIn("installed", nc["package"])  # no .list file: falls back to the status file's mtime


def rpm_header(fields):
    """Build an rpm header blob (as rpmdb.sqlite stores it) from {tag: value}."""
    index, data = b"", b""
    for tag, value in fields.items():
        if isinstance(value, int):
            while len(data) % 4:
                data += b"\x00"
            index += struct.pack(">IIII", tag, 4, len(data), 1)
            data += struct.pack(">I", value)
        else:
            index += struct.pack(">IIII", tag, 6, len(data), 1)
            data += value.encode() + b"\x00"
    return struct.pack(">II", len(fields), len(data)) + index + data


class RhelTests(MappingCheck):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        root = Path(cls.tmp) / "db01"
        shutil.copytree(FIXTURES / "pkgcfg-rhel-root", root)
        cls.links = True
        try:
            os.symlink("rc.d/init.d", root / "etc/init.d")
            wants = root / "etc/systemd/system/multi-user.target.wants"
            wants.mkdir(parents=True)
            os.symlink("/usr/lib/systemd/system/crond.service", wants / "crond.service")
            os.symlink("/opt/units/legacy-only.service", wants / "legacy-only.service")
            os.symlink("/dev/null", root / "etc/systemd/system/tmp.mount")
        except (OSError, NotImplementedError):
            cls.links = False
        (root / "opt/units").mkdir(parents=True)
        (root / "opt/units/legacy-only.service").write_text(
            "[Service]\nExecStart=/opt/legacy/run --listen 0.0.0.0:8443\n", encoding="utf-8")
        db = root / "var/lib/rpm"
        db.mkdir(parents=True)
        con = sqlite3.connect(db / "rpmdb.sqlite")
        con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (rpm_header(
            {1000: "nmap", 1001: "7.92", 1002: "1.el9", 1003: 3, 1004: "Network exploration tool",
             1006: 1700000000, 1008: 1792908063, 1009: 25000000, 1011: "Rocky Enterprise Software Foundation",
             1022: "x86_64", 1044: "nmap-7.92-1.el9.src.rpm"}),))
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + rpm_header(
            {1000: "gpg-pubkey", 1001: "350d275d", 1002: "6279464b"}),))
        con.commit()
        con.close()
        hist = root / "var/lib/dnf"
        hist.mkdir(parents=True)
        con = sqlite3.connect(hist / "history.sqlite")
        con.executescript("""
            CREATE TABLE trans (id INTEGER PRIMARY KEY, dt_begin INTEGER NOT NULL, dt_end INTEGER,
                rpmdb_version_begin TEXT, rpmdb_version_end TEXT, releasever TEXT NOT NULL,
                user_id INTEGER NOT NULL, cmdline TEXT, state INTEGER NOT NULL, comment TEXT);
            CREATE TABLE item (id INTEGER PRIMARY KEY, item_type INTEGER NOT NULL);
            CREATE TABLE repo (id INTEGER PRIMARY KEY, repoid TEXT NOT NULL);
            CREATE TABLE trans_item (id INTEGER PRIMARY KEY, trans_id INTEGER, item_id INTEGER, repo_id INTEGER,
                action INTEGER NOT NULL, reason INTEGER NOT NULL, state INTEGER NOT NULL);
            CREATE TABLE rpm (item_id INTEGER UNIQUE NOT NULL, name TEXT NOT NULL, epoch INTEGER NOT NULL,
                version TEXT NOT NULL, release TEXT NOT NULL, arch TEXT NOT NULL);
            INSERT INTO trans VALUES (7, 1792908062, 1792908070, 'a', 'b', '9', 1000, 'install nmap', 1, '');
            INSERT INTO repo VALUES (1, 'appstream'), (2, '@System');
            INSERT INTO item VALUES (1, 1), (2, 1), (3, 1);
            INSERT INTO rpm VALUES (1, 'nmap', 3, '7.92', '1.el9', 'x86_64'),
                                   (2, 'openssl-libs', 1, '3.0.7', '27.el9', 'x86_64'),
                                   (3, 'openssl-libs', 1, '3.0.7', '25.el9', 'x86_64');
            INSERT INTO trans_item VALUES (1, 7, 1, 1, 1, 2, 1), (2, 7, 2, 1, 6, 1, 1), (3, 7, 3, 2, 7, 1, 1);
        """)
        con.commit()
        con.close()
        cls.root = root
        cls.pkg, cls.pkg_skipped, cls.pkg_report = run(packages2sofelk.PACKAGES, root)
        cls.cfg, cls.cfg_skipped, _ = run(linuxconfig2sofelk.LINUXCONFIG, root, local_tz="America/New_York")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_mapping(self):
        self.assert_mapped(self.pkg, "packages")
        self.assert_mapped(self.cfg, "linuxconfig")

    def test_dnf_rpm_log_pairs_upgrade(self):
        up = find(self.pkg, "packages.dnf", package__name="openssl-libs")
        self.assertEqual(up["event"]["action"], "upgrade")
        self.assertEqual(up["package"]["version"], "1:3.0.7-27.el9")
        self.assertEqual(up["packages"]["previous_version"], "1:3.0.7-25.el9")
        self.assertEqual(up["@timestamp"], "2026-10-25T10:01:02.000000Z")
        nmap = find(self.pkg, "packages.dnf", package__name="nmap")
        self.assertEqual((nmap["package"]["version"], nmap["package"]["architecture"]), ("3:7.92-1.el9", "x86_64"))
        self.assertEqual(find(self.pkg, "packages.dnf", package__name="telnet")["event"]["action"], "remove")
        self.assertEqual(len(ds(self.pkg, "packages.dnf")), 3)

    def test_dnf_history_database(self):
        nmap = find(self.pkg, "packages.dnf_history", package__name="nmap")
        self.assertEqual(nmap["process"]["command_line"], "install nmap")
        self.assertEqual(nmap["user"], {"id": "1000", "name": "oracle"})
        self.assertEqual(nmap["packages"]["repository"], "appstream")
        self.assertEqual(nmap["packages"]["reason"], "user")
        self.assertFalse(nmap["packages"]["automatic"])
        self.assertEqual(nmap["@timestamp"], "2026-10-25T06:01:02.000000Z")
        up = find(self.pkg, "packages.dnf_history", package__name="openssl-libs")
        self.assertEqual(up["event"]["action"], "upgrade")
        self.assertEqual(up["packages"]["previous_version"], "1:3.0.7-25.el9")
        self.assertEqual(len(ds(self.pkg, "packages.dnf_history")), 2)

    def test_rpmdb_inventory(self):
        inv = ds(self.pkg, "packages.inventory")
        self.assertEqual([d["package"]["name"] for d in inv], ["nmap"])  # gpg-pubkey skipped
        nmap = inv[0]
        self.assertEqual(nmap["package"]["version"], "3:7.92-1.el9")
        self.assertEqual(nmap["package"]["installed"], "2026-10-25T06:01:03.000000Z")
        self.assertEqual(nmap["@timestamp"], nmap["package"]["installed"])
        self.assertEqual(nmap["packages"]["vendor"], "Rocky Enterprise Software Foundation")
        self.assertEqual(nmap["packages"]["mtime_source"], "rpm installtime")

    def test_yum_log_year_rollover(self):
        yum = ds(self.pkg, "packages.yum")
        self.assertEqual(len(yum), 3)
        year = int(yum[-1]["@timestamp"][:4])
        self.assertEqual(int(yum[0]["@timestamp"][:4]), year - 1)  # Dec 30 is the year before Jan 02
        self.assertEqual(yum[1]["package"]["name"], "openssl-libs")
        self.assertEqual(yum[1]["package"]["version"], "1:1.0.2k-26.el7_9")
        self.assertEqual(yum[2]["package"]["name"], "telnet")
        self.assertEqual(yum[2]["event"]["action"], "remove")

    def test_rhel_config(self):
        self.assertEqual(find(self.cfg, "linux.cron", user__name="oracle")["process"]["command_line"],
                         "/home/oracle/bin/rman_backup.sh")
        rule = find(self.cfg, "linux.sudoers", user__name="oracle")
        self.assertTrue(rule["linuxconfig"]["sudoers"]["nopasswd"])
        wheel = find(self.cfg, "linux.group", group__name="wheel")
        self.assertTrue(wheel["linuxconfig"]["group"]["privileged"])
        tools = find(self.cfg, "linux.repository", linuxconfig__repository__id="tools")
        self.assertEqual(tools["linuxconfig"]["repository"]["urls"], ["http://203.0.113.9/el9/", "http://203.0.113.10/el9/"])
        self.assertFalse(tools["linuxconfig"]["repository"]["gpgcheck"])
        self.assertIn("unsigned_repository", tools["linuxconfig"]["flags"])
        base = find(self.cfg, "linux.repository", linuxconfig__repository__id="baseos")
        self.assertEqual(base["url"]["domain"], "mirrors.rockylinux.org")
        legacy = [d for d in ds(self.cfg, "linux.init_script") if d["linuxconfig"]["init"]["kind"] == "init.d"]
        self.assertEqual([d["linuxconfig"]["line"] for d in legacy], ["/opt/legacy/start.sh"])

    def test_symlinks_resolved_inside_evidence(self):
        if not self.links:
            self.skipTest("symlinks not available on this platform")
        crond = find(self.cfg, "linux.systemd_unit", event__action="unit", linuxconfig__systemd__unit="crond.service")
        self.assertTrue(crond["linuxconfig"]["systemd"]["enabled"])
        self.assertEqual(crond["linuxconfig"]["systemd"]["enabled_by"], ["multi-user.target"])
        link = find(self.cfg, "linux.systemd_unit", event__action="link", linuxconfig__systemd__unit="crond.service")
        self.assertEqual(link["linuxconfig"]["systemd"]["link_target"], "/usr/lib/systemd/system/crond.service")
        self.assertEqual(link["file"]["type"], "symlink")
        # The absolute link target is read from the evidence copy, never from the analyst's /opt
        only = find(self.cfg, "linux.systemd_unit", event__action="unit",
                    linuxconfig__systemd__unit="legacy-only.service")
        self.assertEqual(only["process"]["command_line"], "/opt/legacy/run --listen 0.0.0.0:8443")
        mask = find(self.cfg, "linux.systemd_unit", linuxconfig__systemd__unit="tmp.mount")
        self.assertTrue(mask["linuxconfig"]["systemd"]["masked"])
        # /etc/init.d -> rc.d/init.d is read once
        legacy = [d for d in ds(self.cfg, "linux.init_script") if d["linuxconfig"]["init"]["kind"] == "init.d"]
        self.assertEqual(len(legacy), 1)


class SuseAlpineTests(MappingCheck):
    def test_zypper_history(self):
        docs, skipped, _ = run(packages2sofelk.PACKAGES, FIXTURES / "pkgcfg-suse-root")
        self.assert_mapped(docs, "packages")
        nginx = find(docs, "packages.zypper", package__name="nginx")
        self.assertEqual(nginx["process"]["command_line"], "zypper in nginx")
        self.assertEqual(nginx["user"]["name"], "root")
        self.assertEqual(nginx["packages"]["repository"], "SLE-Module-Server-Applications")
        self.assertFalse(nginx["packages"]["automatic"])
        self.assertTrue(find(docs, "packages.zypper", package__name="libpcre2")["packages"]["automatic"])
        radd = find(docs, "packages.zypper", event__action="repository-added")
        self.assertEqual(radd["url"]["original"], "http://203.0.113.9/sles/")
        self.assertEqual(find(docs, "packages.zypper", package__name="telnet")["event"]["action"], "remove")
        self.assertEqual(find(docs, "packages.zypper", event__action="command")["event"]["type"], ["info"])

    def test_suse_config(self):
        docs, _, _ = run(linuxconfig2sofelk.LINUXCONFIG, FIXTURES / "pkgcfg-suse-root")
        self.assert_mapped(docs, "linuxconfig")
        cron = find(docs, "linux.cron", event__action="entry")
        self.assertEqual((cron["user"]["name"], cron["linuxconfig"]["cron"]["schedule"]), ("root", "@hourly"))
        repo = find(docs, "linux.repository", linuxconfig__repository__id="shady")
        self.assertEqual(repo["linuxconfig"]["repository"]["manager"], "zypper")

    def test_apk(self):
        docs, _, _ = run(packages2sofelk.PACKAGES, FIXTURES / "pkgcfg-alpine-root")
        self.assert_mapped(docs, "packages")
        busybox = find(docs, "packages.inventory", package__name="busybox")
        self.assertFalse(busybox["packages"]["automatic"])
        self.assertEqual(busybox["package"]["build_version"], "2024-06-10T06:13:20.000000Z")
        self.assertTrue(find(docs, "packages.inventory", package__name="socat")["packages"]["automatic"])
        cfg, _, _ = run(linuxconfig2sofelk.LINUXCONFIG, FIXTURES / "pkgcfg-alpine-root")
        self.assert_mapped(cfg, "linuxconfig")
        repos = ds(cfg, "linux.repository")
        self.assertEqual([r["linuxconfig"]["repository"]["enabled"] for r in repos], [True, False, True])
        self.assertEqual(repos[2]["linuxconfig"]["repository"]["id"], "@edge")
        self.assertEqual(find(cfg, "linux.cron", event__action="entry")["user"]["name"], "root")
        beacon = find(cfg, "linux.cron", event__action="script_line")
        self.assertEqual(beacon["linuxconfig"]["cron"]["schedule"], "15min")
        self.assertIn("download_exec", beacon["linuxconfig"]["flags"])
        local = find(cfg, "linux.init_script", linuxconfig__init__kind="local.d")
        self.assertIn("reverse_shell", local["linuxconfig"]["flags"])


# --------------------------------------------------------------------------- linuxconfig (Debian UAC)

class DebianConfigTests(MappingCheck):
    @classmethod
    def setUpClass(cls):
        cls.docs, cls.skipped, cls.report = run(linuxconfig2sofelk.LINUXCONFIG, DEBIAN)

    def test_mapping_and_secrets(self):
        self.assert_mapped(self.docs, "linuxconfig")
        self.assert_no_secrets(self.docs)
        paths = {d.get("file", {}).get("path") for _, d in self.docs}
        for never in ("/etc/shadow", "/etc/gshadow", "/home/alice/.bash_history", "/home/alice/.ssh/id_ed25519"):
            self.assertNotIn(never, paths)

    def test_accounts(self):
        alice = find(self.docs, "linux.account", user__name="alice")
        acc = alice["linuxconfig"]["account"]
        self.assertEqual((acc["password_state"], acc["password_algorithm"]), ("set", "yescrypt"))
        self.assertEqual(acc["password_last_changed"], "2025-07-31")
        self.assertEqual(alice["user"]["full_name"], "Alice Admin")
        self.assertFalse(acc["system_account"])
        self.assertEqual(alice["@timestamp"], "2026-10-22T07:00:00.000000Z")  # bodyfile mtime of /etc/passwd
        self.assertEqual(alice["linuxconfig"]["mtime_source"], "bodyfile")
        toor = find(self.docs, "linux.account", user__name="toor")
        self.assertEqual(toor["linuxconfig"]["account"]["state"], "new_since_backup")
        self.assertEqual(toor["linuxconfig"]["account"]["password_state"], "empty")
        self.assertEqual(set(toor["linuxconfig"]["flags"]), {"uid0", "empty_password", "duplicate_uid"})
        svc = find(self.docs, "linux.account", user__name="svc_backup")["linuxconfig"]
        self.assertEqual(svc["account"]["password_algorithm"], "sha512")
        self.assertEqual(svc["account"]["account_expires"], "2026-02-16")
        self.assertEqual(svc["account"]["password_max_days"], 90)
        self.assertIn("password_change_required", svc["flags"])
        self.assertEqual(find(self.docs, "linux.account", user__name="bob")["linuxconfig"]["account"]["state"],
                         "only_in_backup")
        legacy = find(self.docs, "linux.account", user__name="legacy")["linuxconfig"]
        self.assertIn("password_in_passwd", legacy["flags"])
        root = find(self.docs, "linux.account", user__name="root")["linuxconfig"]["account"]
        self.assertEqual(root["password_state"], "locked_no_password")

    def test_groups(self):
        sudo = find(self.docs, "linux.group", group__name="sudo")["linuxconfig"]["group"]
        self.assertEqual(sudo["state"], "changed_since_backup")
        self.assertEqual(sudo["members_added"], ["svc_backup"])
        ops = find(self.docs, "linux.group", group__name="ops")["linuxconfig"]
        self.assertTrue(ops["group"]["privileged"])  # through sudoers.d/90-ops
        self.assertIn("sudoers_rule", ops["flags"])
        self.assertEqual(find(self.docs, "linux.group", group__name="root")["linuxconfig"]["group"]["primary_members"],
                         ["root", "toor"])

    def test_sudoers(self):
        www = find(self.docs, "linux.sudoers", user__name="www-data")["linuxconfig"]
        self.assertEqual(www["sudoers"]["commands"], ["/usr/bin/find", "/usr/bin/vim"])
        self.assertEqual(www["sudoers"]["runas"], "root")
        self.assertTrue(www["sudoers"]["nopasswd"])
        self.assertFalse(www["sudoers"]["all_commands"])
        ops = find(self.docs, "linux.sudoers", group__name="ops")["linuxconfig"]
        self.assertEqual(set(ops["flags"]), {"nopasswd", "all_commands"})
        keep = find(self.docs, "linux.sudoers", linuxconfig__line='Defaults\tenv_keep += "LD_PRELOAD"')
        self.assertIn("env_preserved", keep["linuxconfig"]["flags"])
        alias = find(self.docs, "linux.sudoers", linuxconfig__kind="alias")["linuxconfig"]["sudoers"]
        self.assertEqual((alias["alias_type"], alias["alias_name"]), ("cmnd", "SHELLS"))
        files = {d["file"]["path"] for d in ds(self.docs, "linux.sudoers")}
        self.assertNotIn("/etc/sudoers.d/ignored.bak", files)  # sudo skips names with a dot

    def test_cron(self):
        boot = find(self.docs, "linux.cron", linuxconfig__cron__schedule="@reboot")
        self.assertEqual(boot["user"]["name"], "root")
        self.assertEqual(boot["process"]["command_line"], "/usr/local/bin/.sysupdate --daemon")
        www = find(self.docs, "linux.cron", user__name="www-data")
        self.assertEqual(www["linuxconfig"]["cron"]["source"], "user")
        self.assertEqual(set(www["linuxconfig"]["flags"]), {"dev_tcp", "reverse_shell"})
        script = find(self.docs, "linux.cron", event__action="script_line")
        self.assertEqual(script["linuxconfig"]["cron"]["schedule"], "daily")
        self.assertEqual(script["linuxconfig"]["flags"], ["download_exec"])
        path = find(self.docs, "linux.cron", linuxconfig__cron__variable_name="PATH")
        self.assertEqual(path["event"]["action"], "variable")
        self.assertNotIn("/etc/cron.d/.placeholder", {d["file"]["path"] for d in ds(self.docs, "linux.cron")})

    def test_systemd(self):
        units = {d["linuxconfig"]["systemd"]["unit"]: d for d in ds(self.docs, "linux.systemd_unit")
                 if d["event"]["action"] == "unit"}
        evil = units["sysupdate.service"]["linuxconfig"]
        self.assertTrue(evil["systemd"]["enabled"])
        self.assertEqual(evil["systemd"]["exec_start"], ["/tmp/.x/sysupdate --daemon"])
        self.assertEqual(evil["systemd"]["run_as_user"], "root")
        self.assertEqual(evil["systemd"]["origin"], "admin")
        self.assertIn("runs_from_temp", evil["flags"])
        self.assertEqual(units["cron.service"]["linuxconfig"]["systemd"]["origin"], "vendor")
        self.assertEqual(units["backup.timer"]["linuxconfig"]["systemd"]["timer_schedule"], ["OnCalendar=*-*-* 02:00:00"])
        self.assertEqual(units["backup.timer"]["linuxconfig"]["systemd"]["triggers_unit"], "backup.service")
        self.assertEqual(units["agent.service"]["user"]["name"], "alice")
        self.assertEqual(units["agent.service"]["linuxconfig"]["systemd"]["scope"], "user")
        # /lib is a symlink to usr/lib in the bodyfile, so lib/systemd is not read twice
        self.assertEqual(sum(1 for d in ds(self.docs, "linux.systemd_unit")
                             if d["linuxconfig"]["systemd"]["unit"] == "cron.service" and d["event"]["action"] == "unit"), 1)
        link = find(self.docs, "linux.systemd_unit", event__action="link", linuxconfig__systemd__unit="sysupdate.service")
        self.assertEqual(link["linuxconfig"]["systemd"]["link_target"], "/etc/systemd/system/sysupdate.service")
        self.assertEqual(link["@timestamp"], "2026-10-22T07:30:00.000000Z")  # when it was enabled
        masks = {d["linuxconfig"]["systemd"]["unit"] for d in ds(self.docs, "linux.systemd_unit")
                 if d["linuxconfig"]["systemd"].get("masked")}
        self.assertEqual(masks, {"ctrl-alt-del.target", "apt-daily.service"})  # from the bodyfile only
        drop = find(self.docs, "linux.systemd_unit", event__action="dropin")
        self.assertEqual(drop["linuxconfig"]["systemd"]["unit"], "ssh.service")
        self.assertEqual(drop["linuxconfig"]["systemd"]["exec_start"], ["/usr/sbin/sshd -D -o PermitRootLogin=yes"])

    def test_scripts_and_autostart(self):
        rc = [d["linuxconfig"]["line"] for d in ds(self.docs, "linux.init_script")
              if d["linuxconfig"]["init"]["kind"] == "rc.local"]
        self.assertEqual(rc, ["/usr/local/bin/.sysupdate &", "exit 0"])
        env = find(self.docs, "linux.init_script", linuxconfig__line="LD_PRELOAD=/usr/local/lib/libhide.so")
        self.assertEqual(env["linuxconfig"]["flags"], ["ld_preload"])
        bashrc = find(self.docs, "linux.init_script", linuxconfig__line="alias sudo='sudo -E'")
        self.assertEqual(bashrc["user"]["name"], "alice")
        self.assertEqual(bashrc["linuxconfig"]["line_number"], 3)
        auto = ds(self.docs, "linux.autostart")[0]
        self.assertEqual(auto["process"]["command_line"], "/usr/local/bin/.sysupdate --gui")
        self.assertEqual(auto["linuxconfig"]["autostart"]["only_show_in"], ["GNOME", "XFCE"])

    def test_ssh_keys(self):
        raw = base64.b64decode(b"AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f")
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        alice = find(self.docs, "linux.ssh_key", linuxconfig__ssh__comment="alice@laptop")
        self.assertEqual(alice["linuxconfig"]["ssh"]["fingerprint"], expected)
        self.assertEqual(alice["user"]["name"], "alice")
        backup = find(self.docs, "linux.ssh_key", linuxconfig__ssh__comment="backup@vault")["linuxconfig"]["ssh"]
        self.assertEqual(backup["forced_command"], "/usr/local/bin/backup.sh")
        self.assertEqual(backup["from"], ["203.0.113.0/24", "10.0.0.1"])
        root = find(self.docs, "linux.ssh_key", user__name="root")
        self.assertIn("root_authorized_key", root["linuxconfig"]["flags"])
        known = [d["linuxconfig"]["ssh"] for d in ds(self.docs, "linux.ssh_key") if d["event"]["action"] == "known_hosts"]
        self.assertEqual([k.get("hashed") for k in known], [True, False])
        self.assertEqual(known[1]["hosts"], ["10.0.0.20", "web02"])

    def test_hosts_resolver_loader_repos(self):
        hosts = {d["linuxconfig"]["hosts"]["ip"]: d["linuxconfig"]["hosts"] for d in ds(self.docs, "linux.hosts")}
        self.assertTrue(hosts["10.10.10.5"]["commented"])
        self.assertEqual(hosts["203.0.113.50"]["names"], ["updates.example.com"])
        servers = [s for d in ds(self.docs, "linux.resolver") for s in d["linuxconfig"]["resolver"].get("servers", [])]
        self.assertEqual(servers, ["10.0.0.53", "1.1.1.1", "9.9.9.9", "149.112.112.112"])
        pre = find(self.docs, "linux.ld_preload", event__action="preload")
        self.assertEqual(pre["linuxconfig"]["ld"]["entry"], "/usr/local/lib/libhide.so")
        repos = ds(self.docs, "linux.repository")
        urls = [(r["url"]["original"], r["linuxconfig"]["repository"]["enabled"]) for r in repos]
        self.assertIn(("http://203.0.113.9/repo", True), urls)
        self.assertIn(("http://deb.debian.org/debian", False), urls)  # commented deb-src line
        self.assertIn(("http://security.debian.org/debian-security", False), urls)  # Enabled: no
        trusted = find(self.docs, "linux.repository", url__original="http://203.0.113.9/repo")
        self.assertIn("unsigned_repository", trusted["linuxconfig"]["flags"])
        deb822 = [r for r in repos if r["file"]["path"].endswith(".sources")]
        self.assertEqual(len(deb822), 3)
        self.assertEqual(deb822[0]["linuxconfig"]["repository"]["suites"], ["bookworm", "bookworm-updates"])


class ZipAndFrontEndTests(MappingCheck):
    def test_zip_gives_same_documents(self):
        tmp = tempfile.mkdtemp()
        try:
            zpath = Path(tmp) / "uac-deb01.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                for p in sorted(DEBIAN.rglob("*")):
                    if p.is_file():
                        zf.write(p, p.relative_to(DEBIAN).as_posix())
            for source in (packages2sofelk.PACKAGES, linuxconfig2sofelk.LINUXCONFIG):
                folder, _, _ = run(source, DEBIAN)
                zipped, _, _ = run(source, zpath)
                self.assertEqual(sorted(common.doc_id(*p) for p, _ in folder),
                                 sorted(common.doc_id(*p) for p, _ in zipped))
                bodyfile_docs = [d for _, d in zipped if d.get("linuxconfig", {}).get("mtime_source") == "bodyfile"]
                self.assertTrue(bodyfile_docs or source is packages2sofelk.PACKAGES)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_linux2sofelk_dry_run(self):
        code = linux2sofelk.main([str(DEBIAN), "--only", "packages,linuxconfig", "--dry-run", "--sample-docs", "0"])
        self.assertEqual(code, 0)

    def test_index_templates_are_toolkit_templates(self):
        for prefix in ("packages", "linuxconfig"):
            _, tpl, body = common.load_templates(prefix)
            self.assertEqual(tpl["index_patterns"], [f"{prefix}-*"])
            self.assertEqual(body["mappings"]["_meta"]["toolkit_schema"], prefix)
            self.assertEqual(body["mappings"]["dynamic"], "false")
        self.assertTrue(packages2sofelk.PACKAGES.index_template)
        self.assertTrue(linuxconfig2sofelk.LINUXCONFIG.index_template)

    def test_shadow_metadata_never_returns_the_hash(self):
        for field, state, algo in (("", "empty", None), ("!", "locked_no_password", None), ("*", "no_password", None),
                                   ("!$6$s$h", "locked", "sha512"), ("$y$j9T$s$h", "set", "yescrypt"),
                                   ("abcdefghijklm", "set", "des")):
            self.assertEqual(linuxconfig2sofelk.shadow_metadata(field), (state, algo))


if __name__ == "__main__":
    unittest.main()
