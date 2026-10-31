#!/usr/bin/env python3
"""Load Linux web server logs (Apache httpd, nginx, lighttpd) into SOF-ELK as httpdlog-<hostname>.

Looks in the evidence's /var/log for every distro layout, including rotated copies
(.1, .2.gz, -20261025, -20261025.xz):

  Debian/Ubuntu/Kali/SUSE  apache2/access.log, error.log, other_vhosts_access.log, ssl_*.log
  RHEL family              httpd/access_log, error_log, ssl_access_log, ssl_request_log, ssl_error_log
  any                      nginx/access.log, error.log; lighttpd/access.log, error.log
Other files in those folders whose name says access, request or error are read too, and
--web-log adds files kept elsewhere (custom vhost log paths).

Line formats (recognised per line, so a file with mixed formats still loads):
  * NCSA common and combined, with or without a leading "vhost:port" (Apache vhost_combined,
    Debian's other_vhosts_access.log). nginx's default "combined" format is the same.
  * mod_ssl's ssl_request_log: "[time] client TLS-protocol cipher "request" bytes".
  * Apache 2.4 and 2.2 error logs, nginx error logs, lighttpd error logs.
Access log times carry their own UTC offset. Error log times are local time on the evidence
host: the zone comes from its /etc/localtime (or --local-tz) and is recorded in event.timezone.

Field names follow SOF-ELK's httpd parsing (6100-httpd.conf, 8004-postprocess-httpd.conf) and
match AWS/alb2sofelk.py, so `FROM httpdlog-*` covers ALB, Apache and nginx alike: source.ip,
client.user.name (identd), server.user.name (the authenticated user), http.request.method,
url.path, url.query, url.original, http.version, http.response.status_code, destination.bytes
(response size), http.request.referrer, user_agent.original, and the "page" / "not_page" tag.
event.dataset is <server>.access or <server>.error (apache, nginx, lighttpd).

The _id is derived from the host, the log family (access.log, access_log, ...) and the line, so a
line seen again in a later collection (after rotation renamed the file) overwrites instead of
duplicating. Like SOF-ELK, httpdlog-* gets no index template: the index is created from
Linux/index_templates/index-httpdlog.json.

Example:
  python3 Linux/httpd2sofelk.py /cases/uac-web01.zip --case IR-42 --dry-run
"""
import datetime as dt
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import (LogSource, is_ip, iso_utc, rotation_family, rotation_sort_key,  # noqa: E402
                                  run_sources, set_field, split_host_port)

WEB_DIRS = {"apache2": "apache", "httpd": "apache", "apache": "apache", "nginx": "nginx", "lighttpd": "lighttpd"}
SERVERS = ("apache", "nginx", "lighttpd", "web")
DATASETS = tuple(f"{s}.{k}" for s in SERVERS for k in ("access", "error"))
NAME_RE = re.compile(r"(access|request|error)", re.IGNORECASE)
MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

ACCESS_BODY = (r'(?P<client>\S+) (?P<ident>\S+) (?P<user>"(?:[^"\\]|\\.)*"|\S+) \[(?P<time>[^\]]+)\] '
               r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<bytes>\d+|-)'
               r'(?: (?:"-"|"(?P<referrer>(?:[^"\\]|\\.)*)") (?:"-"|"(?P<agent>(?:[^"\\]|\\.)*)"))?(?P<extra>.*)$')
ACCESS_RE = re.compile("^" + ACCESS_BODY)
VHOST_ACCESS_RE = re.compile(r"^(?P<vhost>[^\s:]+)(?::(?P<vport>\d+))? " + ACCESS_BODY)
SSL_REQUEST_RE = re.compile(r'^\[(?P<time>[^\]]+)\] (?P<client>\S+) (?P<proto>\S+) (?P<cipher>\S+) '
                            r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<bytes>\d+|-)$')
HTTP_TIME_RE = re.compile(r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))? ([+-])(\d{2}):?(\d{2})$")
REQUEST_RE = re.compile(r"^(?P<method>[A-Za-z][A-Za-z_-]*) (?P<target>\S+)(?: HTTP/(?P<version>[\d.]+))?$")
APACHE_ERROR_RE = re.compile(
    r"^\[(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}(?:\.\d{1,6})? \d{4})\] "
    r"\[(?:(?P<module>[^:\]\s]*):)?(?P<level>[a-z0-9]+)\] "
    r"(?:\[pid (?P<pid>\d+)(?::tid (?P<tid>\d+))?\] )?"
    r"(?:\((?P<oserr>-?\d+)\)[^:]*: )?"
    r"(?:\[(?:client|remote) (?P<client>[^\]]+)\] )?(?P<msg>.*)$")
NGINX_ERROR_RE = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>[a-z]+)\] (?P<pid>\d+)#(?P<tid>\d+): "
    r"(?:\*(?P<conn>\d+) )?(?P<msg>.*)$")
LIGHTTPD_ERROR_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?: \((?P<src>[^)]+)\) (?P<msg>.*)$")
NGINX_CTX_RE = re.compile(r', (client|server|request|upstream|host|referrer): ("(?:[^"\\]|\\.)*"|[^,]*)')
ANY_HTTPDATE_RE = re.compile(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\.\d+)? [+-]\d{4})\]")
NOT_PAGE_RE = re.compile(r"\.(css|js|class|gif|jpg|jpeg|png|bmp|ico|rss|xml|swf|woff2|ttf|eot)$", re.IGNORECASE)


# --------------------------------------------------------------------------- input discovery

def server_of(rel):
    parts = [p.lower() for p in PurePosixPath(rel).parts]
    for p in reversed(parts[:-1]):
        if p in WEB_DIRS:
            return WEB_DIRS[p]
    low = rel.lower()
    for key in ("nginx", "lighttpd", "apache", "httpd"):
        if key in low:
            return WEB_DIRS.get(key, "apache")
    return "web"


def collect(ev, profile, args):
    items = []
    for folder in WEB_DIRS:
        rel = ev.root_path(f"var/log/{folder}")
        if not ev.is_dir(rel):
            continue
        for path in ev.walk(rel, max_depth=2):
            if NAME_RE.search(PurePosixPath(path).name) and ev.size(path) > 0:
                items.append(path)
    for extra in args.web_log or []:
        rel = ev.root_path(extra.lstrip("/"))
        if ev.exists(rel):
            items.append(rel)
        else:
            print(f"  --web-log {extra}: not found in the evidence ({rel})")
    return sorted(set(items), key=rotation_sort_key)


def add_arguments(ap):
    ap.add_argument("--web-log", action="append",
                    help="Extra web server log to load, as a path on the evidence host"
                         " (e.g. /srv/www/logs/shop_access.log); repeatable")


# --------------------------------------------------------------------------- parsing helpers

def unescape(text):
    return text.replace('\\"', '"').replace("\\\\", "\\") if text else text


def http_time(text):
    m = HTTP_TIME_RE.match(text.strip())
    if not m or m.group(2).lower() not in MONTHS:
        return None
    day, mon, year, hh, mm, ss, frac, sign, oh, om = m.groups()
    offset = dt.timedelta(hours=int(oh), minutes=int(om))
    tz = dt.timezone(offset if sign == "+" else -offset)
    try:
        return dt.datetime(int(year), MONTHS[mon.lower()], int(day), int(hh), int(mm), int(ss),
                           int((frac or "0").ljust(6, "0")), tzinfo=tz)
    except ValueError:
        return None


def local_time(text, fmt, profile):
    """Naive local text -> aware datetime in the host's zone, or None."""
    frac = 0
    m = re.search(r"\.(\d{1,6})(?= |$)", text)
    if m:
        frac = int(m.group(1).ljust(6, "0"))
        text = text[:m.start()] + text[m.end():]
    text = re.sub(r"\s+", " ", text.strip())
    parts = text.split(" ")
    if fmt == "apache":  # Tue Mar 18 16:00:56 2025 (month name parsed by hand: no locale)
        if len(parts) != 5 or parts[1].lower() not in MONTHS:
            return None
        try:
            hh, mm, ss = map(int, parts[3].split(":"))
            naive = dt.datetime(int(parts[4]), MONTHS[parts[1].lower()], int(parts[2]), hh, mm, ss, frac)
        except ValueError:
            return None
    else:
        try:
            naive = dt.datetime.strptime(text, fmt).replace(microsecond=frac)
        except ValueError:
            return None
    return naive.replace(tzinfo=profile.tz or dt.timezone.utc)


def set_client(doc, text):
    if not text or text == "-":
        return
    host, port = split_host_port(text)
    if is_ip(host):
        set_field(doc, "source.ip", host)
    else:
        set_field(doc, "source.address", host)
    set_field(doc, "source.port", port)


def set_request(doc, request):
    """'GET /a/b.php?x=1 HTTP/1.1' -> http.request.method, url.*, http.version."""
    request = unescape(request or "")
    m = REQUEST_RE.match(request)
    if not m:
        if request and request != "-":
            set_field(doc, "sof-elk.rawrequest", request)
        return
    method, target = m.group("method").upper(), m.group("target")
    set_field(doc, "http.request.method", method)
    set_field(doc, "http.version", m.group("version"))
    set_field(doc, "url.original", target)
    if method == "CONNECT":
        host, port = split_host_port(target)
        set_field(doc, "url.domain", host)
        set_field(doc, "destination.port", port)
        set_field(doc, "url.path", "(Tunnel setup request)")
        return
    path, query = target, None
    if "://" in target:
        try:
            parts = urlsplit(target)
            set_field(doc, "url.scheme", parts.scheme.lower() or None)
            set_field(doc, "url.domain", parts.hostname)
            set_field(doc, "destination.port", parts.port)
            path, query = parts.path or "/", parts.query or None
        except ValueError:
            pass
    elif "?" in target:
        path, _, query = target.partition("?")
    set_field(doc, "url.path", path)
    set_field(doc, "url.query", query)
    name = path.rsplit("/", 1)[-1]
    if "." in name and len(name.rsplit(".", 1)[1]) <= 10:
        set_field(doc, "url.extension", name.rsplit(".", 1)[1].lower())
    doc.setdefault("tags", []).append("not_page" if NOT_PAGE_RE.search(path) else "page")


def to_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- line parsers

def parse_access(line, server):
    m = ACCESS_RE.match(line)
    vhost = None
    if not m:
        m = VHOST_ACCESS_RE.match(line)
        if m:
            vhost = m
    if not m:
        return None
    stamp = http_time(m.group("time"))
    if stamp is None:
        return None
    doc = {}
    set_client(doc, m.group("client"))
    ident = m.group("ident")
    if ident != "-":
        # lighttpd's default access log writes the requested host name where NCSA has identd.
        set_field(doc, "url.domain" if server == "lighttpd" else "client.user.name", ident)
    user = unescape(m.group("user").strip('"'))
    if user not in ("-", ""):
        set_field(doc, "server.user.name", user)
    set_request(doc, m.group("request"))
    status = to_int(m.group("status"))
    set_field(doc, "http.response.status_code", status)
    set_field(doc, "destination.bytes", to_int(m.group("bytes")) if m.group("bytes") != "-" else 0)
    set_field(doc, "http.request.referrer", unescape(m.group("referrer")))
    set_field(doc, "user_agent.original", unescape(m.group("agent")))
    extra = (m.group("extra") or "").strip()
    set_field(doc, "httpd.extra", extra)
    if vhost:
        set_field(doc, "url.domain", vhost.group("vhost"))
        if not doc.get("destination", {}).get("port"):
            set_field(doc, "destination.port", to_int(vhost.group("vport")))
    if status:
        set_field(doc, "event.outcome", "failure" if status >= 400 else "success")
    return stamp, False, "access", doc


def parse_ssl_request(line, server):
    m = SSL_REQUEST_RE.match(line)
    if not m:
        return None
    stamp = http_time(m.group("time"))
    if stamp is None:
        return None
    doc = {}
    set_client(doc, m.group("client"))
    if m.group("proto") != "-":
        set_field(doc, "tls.protocol", m.group("proto"))
    if m.group("cipher") != "-":
        set_field(doc, "tls.cipher", m.group("cipher"))
    set_request(doc, m.group("request"))
    set_field(doc, "destination.bytes", to_int(m.group("bytes")) if m.group("bytes") != "-" else 0)
    return stamp, False, "access", doc


def error_message(doc, msg):
    m = re.match(r"^(AH\d{5}): ?(.*)$", msg, re.DOTALL)
    if m:
        set_field(doc, "error.code", m.group(1))
        msg = m.group(2)
    m = re.search(r", referer: (\S+)$", msg)
    if m:
        set_field(doc, "http.request.referrer", m.group(1))
        msg = msg[:m.start()]
    set_field(doc, "error.message", msg)


def parse_apache_error(line, server, profile):
    m = APACHE_ERROR_RE.match(line)
    if not m:
        return None
    stamp = local_time(m.group("time"), "apache", profile)
    if stamp is None:
        return None
    doc = {}
    set_field(doc, "log.level", m.group("level"))
    set_field(doc, "apache.error.module", m.group("module") or None)
    set_field(doc, "process.pid", to_int(m.group("pid")))
    set_field(doc, "process.thread.id", to_int(m.group("tid")))
    set_client(doc, m.group("client"))
    error_message(doc, m.group("msg"))
    return stamp, True, "error", doc


def parse_nginx_error(line, server, profile):
    m = NGINX_ERROR_RE.match(line)
    if not m:
        return None
    stamp = local_time(m.group("time"), "%Y/%m/%d %H:%M:%S", profile)
    if stamp is None:
        return None
    doc = {}
    set_field(doc, "log.level", m.group("level"))
    set_field(doc, "process.pid", to_int(m.group("pid")))
    set_field(doc, "process.thread.id", to_int(m.group("tid")))
    set_field(doc, "httpd.connection_id", to_int(m.group("conn")))
    msg = m.group("msg")
    first = NGINX_CTX_RE.search(msg)
    if first:
        for key, value in NGINX_CTX_RE.findall(msg[first.start():]):
            value = unescape(value[1:-1]) if value.startswith('"') else value
            if key == "client":
                set_client(doc, value)
            elif key == "server":
                set_field(doc, "httpd.server_name", value)
            elif key == "request":
                set_request(doc, value)
            elif key == "host":
                set_field(doc, "url.domain", split_host_port(value)[0])
            elif key == "referrer":
                set_field(doc, "http.request.referrer", value)
            elif key == "upstream":
                set_field(doc, "httpd.upstream", value)
        msg = msg[:first.start()]
    set_field(doc, "error.message", msg)
    return stamp, True, "error", doc


def parse_lighttpd_error(line, server, profile):
    m = LIGHTTPD_ERROR_RE.match(line)
    if not m:
        return None
    stamp = local_time(m.group("time"), "%Y-%m-%d %H:%M:%S", profile)
    if stamp is None:
        return None
    doc = {}
    set_field(doc, "error.message", m.group("msg"))
    set_field(doc, "apache.error.module", m.group("src"))
    return stamp, True, "error", doc


def parse_partial(line, server):
    """SOF-ELK's fallback: any line with an access-log date still loads, tagged partial_httpd_log."""
    m = ANY_HTTPDATE_RE.search(line)
    if not m:
        return None
    stamp = http_time(m.group(1))
    if stamp is None:
        return None
    doc = {"tags": ["partial_httpd_log"], "message": line}
    head = line[:m.start()].split()
    if head:
        set_client(doc, head[0] if is_ip(split_host_port(head[0])[0]) else None)
    return stamp, False, "access", doc


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    rel = item
    server = server_of(rel)
    # The family is the path on the evidence host without the rotation suffix, so the same line
    # in access.log (one collection) and access.log.1 (a later one) gets the same _id.
    family = f"{ev.evidence_path(str(PurePosixPath(rel).parent))}/{rotation_family(PurePosixPath(rel).name)}"
    seen = parse.seen
    with ev.open_text(rel) as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            result = (parse_access(line, server) or parse_ssl_request(line, server)
                      or parse_apache_error(line, server, profile) or parse_nginx_error(line, server, profile)
                      or parse_lighttpd_error(line, server, profile) or parse_partial(line, server))
            if result is None:
                yield None, "line in no known web log format"
                continue
            stamp, local, kind, doc = result
            doc["@timestamp"] = iso_utc(stamp)
            dataset = f"{server}.{kind}"
            set_field(doc, "event.kind", "event")
            set_field(doc, "event.category", "web")
            set_field(doc, "event.type", "access" if kind == "access" else "error")
            set_field(doc, "event.dataset", dataset)
            if local:
                set_field(doc, "event.timezone", profile.tz_name or "UTC")
            set_field(doc, "labels.type", "httpdlog")
            set_field(doc, "log.file.path", rel)
            set_field(doc, "log.offset", offset)
            key = hashlib.sha1(line.encode("utf-8", "replace")).digest()
            n = seen.get((family, key), 0)
            seen[(family, key)] = n + 1
            yield [dataset, family, key.hex(), n], doc


parse.seen = {}

HTTPD = LogSource("httpd", "httpdlog", DATASETS, collect, parse, str)
HTTPD.add_arguments = add_arguments


def main(argv=None):
    return run_sources([HTTPD], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())
