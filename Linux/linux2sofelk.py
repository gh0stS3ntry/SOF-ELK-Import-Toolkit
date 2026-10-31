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
  httpd    Apache httpd, nginx and lighttpd access/error logs      -> httpdlog-<hostname>
           (httpd2sofelk.py; event.dataset apache.access, nginx.error, ...)
  browser  Firefox and Chromium-family history and downloads       -> browsinghistory-<hostname>
           (browser2sofelk.py; event.dataset browsinghistory, browsinghistory.download)
  vsftpd   vsftpd.log and xferlog FTP logs                         -> logstash-<hostname>
           (vsftpd2sofelk.py; event.dataset ftp.vsftpd, ftp.xferlog)

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

from browser2sofelk import BROWSER  # noqa: E402
from httpd2sofelk import HTTPD  # noqa: E402
from journal2sofelk import JOURNAL  # noqa: E402
from sof_elk_linux_common import run_sources  # noqa: E402
from syslog2sofelk import SYSLOG  # noqa: E402
from vsftpd2sofelk import VSFTPD  # noqa: E402

SOURCES = [JOURNAL, SYSLOG, HTTPD, BROWSER, VSFTPD]


def main(argv=None):
    return run_sources(SOURCES, __doc__.split("\n\n")[0], argv,
                       epilog="Sources: " + ", ".join(s.name for s in SOURCES))


if __name__ == "__main__":
    sys.exit(main())
