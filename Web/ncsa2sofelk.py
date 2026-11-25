#!/usr/bin/env python3
"""Load NCSA Common (CLF) and Combined access logs from any web server into SOF-ELK as httpdlog-<hostname>.

Linux/httpd2sofelk.py already reads these formats, but only from a Linux collection (a UAC
output or a collected root filesystem, under var/log/apache2, httpd, nginx or lighttpd). This
importer takes the log files themselves, wherever they came from:

  * Apache httpd on Windows (C:\\Apache24\\logs, XAMPP, WampServer), or logs copied off a server
  * nginx for Windows, or nginx/Apache logs handed over by a client or hosting provider
  * Apache Tomcat AccessLogValve logs (localhost_access_log.<date>.txt; its "common" and
    "combined" patterns are NCSA, and extra fields such as %D are kept in httpd.extra)
  * IIS logs written in IIS's "NCSA Common" format (nc<yymmdd>.log). IIS W3C logs (u_ex*.log)
    belong to Windows/csv_importers/iisgeolocate2sofelk.py.
  * HAProxy, Varnish (varnishncsa), Squid and load balancers configured to write CLF/Combined

Line formats (recognised per line, so a file with mixed layouts still loads):

  common          host ident authuser [dd/Mon/yyyy:HH:MM:SS +zzzz] "request" status bytes
  combined        common + "referrer" "user-agent"
  vhost_common    "vhost:port " + common     (Apache vhost_common)
  vhost_combined  "vhost:port " + combined   (Apache vhost_combined, other_vhosts_access.log)
Anything after these fields (%D, %T, X-Forwarded-For, ...) is kept in httpd.extra. A line that
fits none of them but carries an access log date is loaded as SOF-ELK does, tagged
partial_httpd_log with the raw line in message (httpd.log_format "partial"). Times carry their
own UTC offset, so no time zone option is needed.

The parsing is Linux/httpd2sofelk.py's own, so field names are identical to the other httpdlog
importers (SOF-ELK 6100-httpd.conf / 8004-postprocess-httpd.conf names, AWS httpdlog types) and
the web access log hunting checklist (W* queries) covers these logs as well:

  host (%h)              -> source.ip (or source.address when it is a host name)
  ident (%l)             -> client.user.name (lighttpd: url.domain, as in its default format)
  authuser (%u)          -> server.user.name
  [time] (%t)            -> @timestamp (UTC)
  "request" (%r)         -> http.request.method, url.original, url.path, url.query,
                            url.extension, http.version ("page" / "not_page" tag)
                            (an unparseable request line -> sof-elk.rawrequest)
  status (%>s)           -> http.response.status_code, event.outcome (>= 400 is failure)
  bytes (%b)             -> destination.bytes ("-" is 0)
  "referrer"             -> http.request.referrer
  "user-agent"           -> user_agent.original
  vhost:port             -> url.domain, destination.port
  layout                 -> httpd.log_format (common / combined / vhost_common / vhost_combined)

event.dataset is <server>.access, where the server is apache, nginx, lighttpd, tomcat, iis or web
(unknown). It is guessed per file from its path and name (apache2/, httpd/, xampp, nginx/,
localhost_access_log, nc<yymmdd>.log, ...) or forced with --server. Every document also gets
host.name (--hostname), event.kind "event", event.category "web", event.type "access",
labels.type "httpdlog", log.file.path (the path under the folder given) and log.offset (line
number), plus case (--case) and host.os.type (--host-os; "windows" for IIS logs).

Files that do not look like NCSA access logs (the first lines are checked) are skipped and
listed; .gz, .bz2 and .xz files are read without unpacking. The _id comes from the host, the
dataset, the log family (the file name without a rotation suffix such as .1, .2.gz or -20261125),
the line itself and its occurrence number, so re-running, or loading a log again after rotation
renamed it, overwrites instead of duplicating.

Like the other httpdlog importers, no index template is installed for httpdlog-*: the index is
created from Linux/index_templates/index-httpdlog.json, and an httpdlog-<hostname> index made by
another toolkit web importer (Linux, IIS, ALB/ELB, CloudFront) is extended, not replaced.

Standard library only (Python 3.9+); documents are sent with urllib to the _bulk API.

Examples:
  python3 Web/ncsa2sofelk.py /cases/IR-42/web01/logs --hostname WEB01 --dry-run
  python3 Web/ncsa2sofelk.py C:\\cases\\IR-42\\C\\xampp\\apache\\logs --hostname WEB01 --case IR-42
  python3 Web/ncsa2sofelk.py tomcat/logs --hostname APP01 --server tomcat --host-os linux
"""
import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path, PurePosixPath
from urllib import error

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "Linux"))
sys.path.insert(0, str(REPO / "Linux" / "common"))

import httpd2sofelk as httpd  # noqa: E402
from sof_elk_linux_common import (ES, LogSource, add_client_arguments, apply_client_arguments,  # noqa: E402
                                  iso_utc, open_compressed, rotation_family, rotation_sort_key,
                                  run_source, sanitize_hostname, set_field)

PREFIX = "httpdlog"
SERVERS = ("apache", "nginx", "lighttpd", "tomcat", "iis", "web")
DATASETS = tuple(f"{s}.access" for s in SERVERS)
HOST_OS = ("windows", "linux", "macos", "unix")
# A file is an NCSA access log when at least half of its first non-empty lines (and at least
# one) are common/combined lines.
SNIFF_LINES = 20
SNIFF_BYTES = 64 * 1024
# Path hints for --server auto (checked on the lower-cased path under the folder given).
SERVER_HINTS = (
    ("tomcat", re.compile(r"(^|/)(localhost_access_log[^/]*|[^/]*tomcat[^/]*|catalina[^/]*)(/|$)|_access_log\.\d{4}-\d{2}-\d{2}")),
    ("iis", re.compile(r"(^|/)(nc\d{6}\.log|ncsa[^/]*|w3svc\d*|inetpub)(/|$)")),
    ("nginx", re.compile(r"nginx")),
    ("lighttpd", re.compile(r"lighttpd")),
    ("apache", re.compile(r"apache|httpd|xampp|wamp|(^|/)access_log")),
)


# --------------------------------------------------------------------------- detection

def is_ncsa_line(line):
    """True when the line is NCSA common or combined (optionally vhost-prefixed)."""
    return httpd.parse_access(line.lstrip("\ufeff").rstrip("\r\n"), "web") is not None


def detect(path):
    """True when the file (plain, .gz, .bz2 or .xz) looks like an NCSA access log.

    Used by this importer and by SOF-ELK_ImportWrapper.py, so both agree on a file."""
    try:
        with open_compressed(path) as raw:
            head = raw.read(SNIFF_BYTES)
    except (OSError, EOFError, ValueError):
        return False
    except Exception:  # noqa: BLE001 - corrupt compressed data (zlib/lzma errors) means "not mine"
        return False
    if not head or b"\x00" in head[:4096]:
        return False
    text = head.decode("utf-8", "replace")
    lines = [x for x in text.splitlines()[:SNIFF_LINES * 2] if x.strip()]
    if len(head) == SNIFF_BYTES and len(lines) > 1:
        lines = lines[:-1]  # the last line may be cut off by the read limit
    lines = lines[:SNIFF_LINES]
    if not lines:
        return False
    hits = sum(1 for x in lines if is_ncsa_line(x))
    return hits >= 1 and hits * 2 >= len(lines)


def guess_server(rel, forced=None):
    if forced:
        return forced
    low = rel.replace("\\", "/").lower()
    for server, pattern in SERVER_HINTS:
        if pattern.search(low):
            return server
    return "web"


# --------------------------------------------------------------------------- input

class FileProfile:
    """The host the logs came from: only what the command line says (no evidence to read)."""

    def __init__(self, hostname, host_os=None):
        self.hostname = sanitize_hostname(hostname)
        self.host_os = host_os
        self.tz = None
        self.tz_name = None

    def fields(self):
        doc = {}
        set_field(doc, "host.name", self.hostname)
        set_field(doc, "host.os.type", self.host_os)
        return doc


def find_files(paths):
    """(file, rel) pairs; rel is the path under the folder given (as the other importers record
    log.file.path), or the path as given for a single file."""
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            found = [x for x in p.rglob("*") if x.is_file() and not x.name.startswith(".")]
            files += [(x, x.relative_to(p).as_posix()) for x in found]
        elif p.is_file():
            files.append((p, p.as_posix()))
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    return sorted(files, key=lambda fr: rotation_sort_key(fr[1]))


def collect(_ev, profile, args):
    items, skipped = [], []
    for f, rel in find_files(args.paths):
        if detect(f):
            server = guess_server(rel, args.server)
            if server == "web":  # nothing in the path under the folder given: try the folder itself
                server = guess_server(f.resolve().parent.as_posix())
            items.append((f, rel, server))
        else:
            skipped.append(rel)
    by_server = {}
    for _f, _rel, server in items:
        by_server[server] = by_server.get(server, 0) + 1
    print(f"{len(items)} NCSA access log file(s): "
          + (", ".join(f"{n} {s}" for s, n in sorted(by_server.items())) or "none"))
    # The index check after loading counts only the datasets these files hold.
    if by_server:
        NCSA.datasets = tuple(f"{s}.access" for s in sorted(by_server))
    # IIS NCSA logs come from a Windows server: say so when --host-os was not given.
    if items and not args.host_os and set(by_server) == {"iis"}:
        profile.host_os = "windows"
        print("  host.os.type 'windows' (IIS logs; set --host-os to change)")
    if skipped:
        print(f"  skipped {len(skipped)} file(s) that are not NCSA common/combined access logs: "
              + ", ".join(skipped[:5]) + (" ..." if len(skipped) > 5 else ""))
    return items


def item_label(item):
    return f"{item[1]} ({item[2]})"


# --------------------------------------------------------------------------- parsing

def parse(_ev, profile, args, item, report):
    path, rel, server = item
    dataset = f"{server}.access"
    # The family is the file name without its rotation suffix (access.log.2.gz -> access.log), not
    # its path, so the same line in access.log (one copy) and access.log.1 (a later one) gets the
    # same _id however the folder was given. The dataset is part of the _id too, so apache's and
    # nginx's access.log stay apart.
    family = rotation_family(PurePosixPath(rel).name)
    seen = parse.seen
    with io.TextIOWrapper(open_compressed(path), encoding="utf-8", errors="replace", newline="") as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if offset == 0:
                line = line.lstrip("\ufeff")
            if not line.strip():
                continue
            result = httpd.parse_access(line, server) or httpd.parse_partial(line, server)
            if result is None:
                yield None, "line not in NCSA common/combined format"
                continue
            stamp, _local, _kind, doc = result
            fmt = doc.get("httpd", {}).get("log_format", "partial")
            parse.formats[fmt] = parse.formats.get(fmt, 0) + 1
            doc["@timestamp"] = iso_utc(stamp)
            set_field(doc, "event.kind", "event")
            set_field(doc, "event.category", "web")
            set_field(doc, "event.type", "access")
            set_field(doc, "event.dataset", dataset)
            set_field(doc, "labels.type", "httpdlog")
            set_field(doc, "log.file.path", rel)
            set_field(doc, "log.offset", offset)
            key = hashlib.sha1(line.encode("utf-8", "replace")).digest()
            n = seen.get((family, key), 0)
            seen[(family, key)] = n + 1
            yield [dataset, family, key.hex(), n], doc


parse.seen = {}
parse.formats = {}

def missing(_ev, _profile, _args):
    return 1, "No NCSA common/combined access logs found."


NCSA = LogSource("ncsa", PREFIX, DATASETS, collect, parse, item_label, missing=missing)


# --------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Load NCSA Common (CLF) and Combined web access logs into"
                                             " SOF-ELK (index httpdlog-<hostname>)")
    ap.add_argument("paths", nargs="+", help="Access log files or folders (searched recursively;"
                                             " .gz, .bz2 and .xz are fine)")
    ap.add_argument("--hostname", required=True, help="The web server the logs came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--server", choices=SERVERS,
                    help="Web server that wrote the logs, for event.dataset <server>.access"
                         " (default: guessed per file from its path, else 'web')")
    ap.add_argument("--host-os", choices=HOST_OS,
                    help="host.os.type of the web server (default: 'windows' for IIS logs, else unset)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="Accepted for wrapper compatibility; NCSA times carry their own offset, so it is not used")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true", help="Parse everything and show sample documents;"
                                                           " send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    add_client_arguments(ap)
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    try:
        host_os = args.host_os or ("windows" if args.server == "iis" else None)
        profile = FileProfile(args.hostname, host_os)
    except ValueError as exc:
        sys.exit(str(exc))
    print(f"Host: '{profile.hostname}'" + (f" ({profile.host_os})" if profile.host_os else ""))
    if args.local_tz:
        print("  note: --local-tz ignored; NCSA access log times carry their own UTC offset.")

    es = None
    if not args.dry_run:
        es = ES(args.es, args.user, args.password, args.insecure)
        try:
            status, info = es.call("GET", "/")
        except error.URLError as exc:
            sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {exc.reason}")
        if status >= 300:
            sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
        print(f"Connected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    parse.seen, parse.formats = {}, {}
    code = run_source(NCSA, None, profile, args, es)
    if parse.formats:
        print("Line layouts: " + ", ".join(f"{k} {v}" for k, v in sorted(parse.formats.items())))
    if es is not None and code == 0:
        print("In Kibana, use the 'httpdlog-*' data view (time field @timestamp); ES|QL: FROM httpdlog-*"
              " METADATA _index.")
    return code


if __name__ == "__main__":
    sys.exit(main())
