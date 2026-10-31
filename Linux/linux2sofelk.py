#!/usr/bin/env python3
"""Load a Linux evidence collection into SOF-ELK: every Linux importer in one run.

The evidence can be a UAC output zip (read in place, nothing is extracted), an extracted UAC
folder, or any collected root filesystem: CyLR, Velociraptor or Dissect output, or a mounted
image (the folder that holds etc/ and var/log/). The host name, distro, machine-id and time
zone are read from the evidence and stamped on every document (host.name, host.os.*,
host.id), and every index is named <prefix>-<hostname>.

Sources loaded (use --only to pick some):
  journal  systemd journal from its journalctl -o json export   -> logstash-<hostname>
           (journal2sofelk.py; event.dataset syslog.journal)
  syslog   text syslog files under /var/log (auth.log, secure,   -> logstash-<hostname>
           messages, syslog, ...; syslog2sofelk.py; event.dataset syslog.file)
  auditd   /var/log/audit/audit.log*, one document per event     -> auditd-<hostname>
           (auditd2sofelk.py; event.dataset auditd.log)
  bodyfile UAC bodyfile/bodyfile.txt (or --bodyfile), with       -> bodyfile-<hostname>
           executable hashes and owner names (bodyfile2sofelk.py)
  wtmp     wtmp, btmp and wtmpdb login records, logins paired    -> wtmp-<hostname>
           with logouts (wtmp2sofelk.py)
  packages package history and installed packages: dpkg, apt,     -> packages-<hostname>
           dnf, yum, zypper, rpm, apk (packages2sofelk.py; event.dataset packages.*)
  linuxconfig  accounts (shadow metadata only), groups, sudoers,  -> linuxconfig-<hostname>
           cron, systemd units, init/profile scripts, autostart, SSH keys, hosts, resolver,
           ld.so.preload, repositories (linuxconfig2sofelk.py; event.dataset linux.*)

Exit status: 0 when everything loaded, 1 when Elasticsearch rejected documents, 3 when the
collection has binary journal files but no JSON export (the journal was not loaded; the
message says which journalctl command to run).

Example:
  python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from auditd2sofelk import AUDITD  # noqa: E402
from bodyfile2sofelk import BODYFILE  # noqa: E402
from journal2sofelk import JOURNAL  # noqa: E402
from linuxconfig2sofelk import LINUXCONFIG  # noqa: E402
from packages2sofelk import PACKAGES  # noqa: E402
from sof_elk_linux_common import run_sources  # noqa: E402
from syslog2sofelk import SYSLOG  # noqa: E402
from wtmp2sofelk import WTMP  # noqa: E402

SOURCES = [JOURNAL, SYSLOG, AUDITD, BODYFILE, WTMP, PACKAGES, LINUXCONFIG]


def main(argv=None):
    return run_sources(SOURCES, __doc__.split("\n\n")[0], argv,
                       epilog="Sources: " + ", ".join(s.name for s in SOURCES))


if __name__ == "__main__":
    sys.exit(main())
