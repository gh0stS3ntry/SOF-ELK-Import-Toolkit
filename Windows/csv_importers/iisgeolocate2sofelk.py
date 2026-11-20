#!/usr/bin/env python3
"""Load Microsoft IIS access logs into SOF-ELK as httpdlog-<hostname>.

Input (a folder is searched recursively; .gz files are read too):
  * iisGeolocate CSV output (Eric Zimmerman's iisGeolocate, `--csv`): one
    <run timestamp>_<log name>_Chunk<N>.csv per IIS log, holding the log's own W3C columns
    (whatever its #Fields line listed) plus GeoCity and GeoCountry for the client address.
    iisGeolocate's side files are recognised: !UniqueIPs.csv (a summary, not loaded),
    *_ConsoleLog.txt (not loaded) and BadDataRows_REVIEW_ME.txt (its rows are counted and
    reported, because iisGeolocate left them out of the CSVs).
  * Raw IIS W3C extended logs (u_ex*.log, ex*.log): "#Fields:" header and one space-separated
    request per line. The same request loaded from the raw log and from iisGeolocate's CSV gets
    the same _id, so loading both does not duplicate it (the CSV adds the geolocation).

The index family is SOF-ELK's web access log family (httpdlog-*), like ALB/ELB, CloudFront,
Apache, nginx and lighttpd logs, so one ES|QL query (FROM httpdlog-*) and the hunting pack's
web access log checklist cover IIS too. Field names follow SOF-ELK's IIS parsing
(configfiles/6100-httpd.conf, 8004-postprocess-httpd.conf):

    date + time (UTC)    -> @timestamp (W3C extended logs are always written in UTC)
    s-sitename           -> service.name (W3SVC1, ...)
    s-computername       -> host.hostname
    s-ip, s-port         -> destination.ip, destination.port
    c-ip                 -> source.ip
    cs-username          -> client.user.name
    cs-method            -> http.request.method
    cs-uri-stem          -> url.path (+ url.extension)
    cs-uri-query         -> url.query;  url.original = path?query as logged
    cs-host              -> url.domain
    cs-version           -> http.version ("HTTP/1.1" -> "1.1", as the other web importers)
    cs(User-Agent)       -> user_agent.original (IIS writes spaces as "+"; they are turned back
                            into spaces so user agents read like other web logs)
    cs(Referer)          -> http.request.referrer
    cs(Cookie)           -> http.request.cookie
    sc-status            -> http.response.status_code
    sc-substatus         -> http.response.substatus_code
    sc-win32-status      -> process.exit_code (as SOF-ELK) and iis.win32_status
    sc-bytes / cs-bytes  -> destination.bytes / source.bytes (response / request size)
    time-taken (ms)      -> iis.time_taken.ms and event.duration (nanoseconds)
    X-Forwarded-For and similar custom fields -> xff.ip (each valid address)
    GeoCity, GeoCountry  -> source.geo.city_name, source.geo.country_name ("NA", which
                            iisGeolocate writes for private and unknown addresses, is left out)

Every document also gets host.name (--hostname), host.os.type "windows", event.dataset
"iis.access", event.kind "event", event.category "web", log.file.path, iis.source_format
("iisgeolocate" or "w3c") and case (--case). Columns not listed above (custom logging fields,
crypt-*, ...) are kept under iis.unmapped.<name>. Values that do not fit their field type are
kept as "column=value" strings in iis.malformed. "-" values are left out.

Like the other httpdlog importers, no index template is installed for httpdlog-*: the index is
created from Windows/index_templates/index-httpdlog.json (merged with the common component). An
httpdlog-<hostname> index made by another toolkit web importer is extended, not replaced.

Example:
  python3 Windows/csv_importers/iisgeolocate2sofelk.py C:\\cases\\IR-42\\iisgeolocate --hostname WEB01 --case IR-42 --dry-run
"""
import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib import error

import sof_elk_index_templates as templates

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, resolve_index  # noqa: E402

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:  # Windows: C long is 32-bit
    csv.field_size_limit(2**31 - 1)

PREFIX = "httpdlog"
SCHEMA = "httpdlog"
DATASET = "iis.access"
TZ_ARG_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

# W3C field (lower case) -> (target field, conversion). Fields handled in build() are not listed.
SIMPLE = {
    "s-sitename": ("service.name", "keyword"),
    "s-computername": ("host.hostname", "keyword"),
    "s-ip": ("destination.ip", "ip"),
    "s-port": ("destination.port", "int"),
    "c-ip": ("source.ip", "ip"),
    "cs-username": ("client.user.name", "keyword"),
    "cs-method": ("http.request.method", "upper"),
    "cs-host": ("url.domain", "keyword"),
    "cs(referer)": ("http.request.referrer", "keyword"),
    "cs(cookie)": ("http.request.cookie", "keyword"),
    "sc-status": ("http.response.status_code", "int"),
    "sc-substatus": ("http.response.substatus_code", "int"),
    "sc-bytes": ("destination.bytes", "int"),
    "cs-bytes": ("source.bytes", "int"),
}
HANDLED = {"date", "time", "cs-uri-stem", "cs-uri-query", "cs-version", "cs(user-agent)",
           "sc-win32-status", "time-taken", "geocity", "geocountry"}
# Custom logging fields that carry the original client address behind a proxy or load balancer.
XFF_FIELDS = {"x-forwarded-for", "cs(x-forwarded-for)", "x-forwarded-for-ip", "originalip",
              "x-original-for", "cs(x-original-for)", "true-client-ip", "cs(true-client-ip)",
              "x-real-ip", "cs(x-real-ip)", "cf-connecting-ip", "cs(cf-connecting-ip)"}
GEO_FIELDS = {"geocity": "source.geo.city_name", "geocountry": "source.geo.country_name"}
# Not part of a request: left out of the _id so the raw log and iisGeolocate's CSV agree.
ID_EXCLUDED = set(GEO_FIELDS)
# A CSV or log is IIS W3C when its columns include these.
SIGNATURE = {"date", "time", "cs-method", "cs-uri-stem"}


def is_iis_columns(cols):
    """IIS request columns. CloudFront standard logs are W3C too, but have x-edge-* columns
    (they belong to AWS/cloudfrontaccess2sofelk.py)."""
    return SIGNATURE <= cols and not any(c.startswith("x-edge") for c in cols)
INT_RE = re.compile(r"^-?\d{1,19}$")
XFF_SPLIT_RE = re.compile(r"[,\s]+")
RUN_PREFIX_RE = re.compile(r"^\d{14}_")
CHUNK_RE = re.compile(r"_Chunk\d+$", re.IGNORECASE)
SIDE_FILES = {"!uniqueips.csv": "iisGeolocate unique IP summary",
              "badrows_review_me.txt": "iisGeolocate bad rows",
              "baddatarows_review_me.txt": "iisGeolocate bad rows"}


# --------------------------------------------------------------------------- helpers

def set_field(doc, dotted, value):
    if value is None or value == [] or value == "":
        return
    parts = dotted.split(".")
    cur = doc
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def get_field(doc, dotted):
    cur = doc
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def snake(name):
    s = re.sub(r"[^0-9A-Za-z]+", "_", name).strip("_").lower()
    return s or "field"


def valid_ip(value):
    value = value.strip().strip("[]")
    if value.count(":") == 1 and "." in value:      # 203.0.113.7:51234
        value = value.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def to_int(value):
    return int(value) if INT_RE.match(value) else None


def sanitize_hostname(hostname):
    host = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("-._")
    if not host:
        raise ValueError(f"--hostname '{hostname}' has no usable characters")
    return host


def log_name(path):
    """u_ex22120305 for both 20261120085119_u_ex22120305_Chunk1.csv and u_ex22120305.log."""
    name = path.name
    for suffix in (".gz",):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return CHUNK_RE.sub("", RUN_PREFIX_RE.sub("", stem)).lower()


def open_text(path):
    raw = path.open("rb")
    if path.name.lower().endswith(".gz"):
        raw = gzip.GzipFile(fileobj=raw)
    return io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="")


def stamp(date, time):
    """W3C date + time (UTC) -> ISO 8601 with milliseconds, or None."""
    text = f"{date.strip()} {time.strip()}"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            value = dt.datetime.strptime(text, fmt)
            return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- record -> document

def build(pairs, meta):
    """[(lower-case W3C field, value)] -> (document or None, problem)."""
    values = {}
    for field, value in pairs:
        if value is None:
            continue
        value = value.strip()
        if value in ("", "-"):
            continue
        values.setdefault(field, value)
    doc, malformed = {}, []

    ts = stamp(values.get("date", ""), values.get("time", "")) if "date" in values and "time" in values else None
    if not ts:
        return None, "row without a usable date and time"
    doc["@timestamp"] = ts

    path, query = values.get("cs-uri-stem"), values.get("cs-uri-query")
    set_field(doc, "url.path", path)
    set_field(doc, "url.query", query)
    if path:
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            set_field(doc, "url.extension", last.rsplit(".", 1)[1].lower()[:32] or None)
        set_field(doc, "url.original", path + (f"?{query}" if query else ""))
    if "cs-version" in values:
        v = values["cs-version"]
        set_field(doc, "http.version", v[5:] if v.upper().startswith("HTTP/") else v)
    if "cs(user-agent)" in values:
        set_field(doc, "user_agent.original", values["cs(user-agent)"].replace("+", " "))
    if "sc-win32-status" in values:
        code = to_int(values["sc-win32-status"])
        if code is None:
            malformed.append(f"sc-win32-status={values['sc-win32-status']}")
        else:
            set_field(doc, "process.exit_code", code)
            set_field(doc, "iis.win32_status", code)
    if "time-taken" in values:
        ms = to_int(values["time-taken"])
        if ms is None:
            malformed.append(f"time-taken={values['time-taken']}")
        else:
            set_field(doc, "iis.time_taken.ms", ms)
            set_field(doc, "event.duration", ms * 1_000_000)
    for field, target in GEO_FIELDS.items():
        value = values.get(field)
        if value and value.upper() != "NA":
            # iisGeolocate writes spaces in names as "_" (United_States); GeoIP names have spaces
            set_field(doc, target, value.replace("_", " "))

    xff = []
    for field, value in values.items():
        if field in SIMPLE:
            target, conv = SIMPLE[field]
            if conv == "int":
                out = to_int(value)
            elif conv == "ip":
                out = valid_ip(value)
            elif conv == "upper":
                out = value.upper()
            else:
                out = value
            if out is None:
                malformed.append(f"{field}={value}")
            else:
                set_field(doc, target, out)
        elif field in HANDLED:
            continue
        else:
            if field in XFF_FIELDS:
                xff += [ip for ip in (valid_ip(p) for p in XFF_SPLIT_RE.split(value.replace("+", " "))) if ip]
            set_field(doc, "iis.unmapped." + snake(field), value)
    if xff:
        set_field(doc, "xff.ip", list(dict.fromkeys(xff)))
    if malformed:
        set_field(doc, "iis.malformed", malformed)

    set_field(doc, "host.name", meta["host"])
    set_field(doc, "host.os.type", "windows")
    doc["event"] = {**doc.get("event", {}), "dataset": DATASET, "kind": "event", "category": "web"}
    set_field(doc, "log.file.path", meta["path"])
    set_field(doc, "iis.source_format", meta["format"])
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc, None


# --------------------------------------------------------------------------- readers

def sniff(path):
    """('iisgeolocate' | 'w3c' | 'side' | None, detail) for one file."""
    lower = path.name.lower()
    if lower in SIDE_FILES:
        return "side", SIDE_FILES[lower]
    if lower.endswith("_consolelog.txt"):
        return "side", "iisGeolocate console log"
    try:
        with open_text(path) as fh:
            head = fh.read(1 << 16)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        return None, f"unreadable ({exc})"
    lines = head.splitlines()
    for line in lines[:20]:
        if line.lower().startswith("#fields:"):
            cols = {c.lower() for c in line[8:].split()}
            if any(c.startswith("x-edge") for c in cols):
                return None, "CloudFront access log (use AWS/cloudfrontaccess2sofelk.py)"
            return ("w3c", "") if is_iis_columns(cols) else (None, "W3C log without IIS request fields")
        if line.startswith("#"):
            continue
        break
    if lines:
        try:
            header = next(csv.reader([lines[0]]))
        except csv.Error:
            header = []
        cols = {c.strip().lower() for c in header}
        if is_iis_columns(cols):
            return "iisgeolocate", ""
    return None, "not an IIS W3C log or iisGeolocate CSV"


def read_csv_records(path):
    with open_text(path) as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if not header:
            return
        cols = [c.strip().lower() for c in header]
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            pairs = list(zip(cols, row))
            for i, value in enumerate(row[len(cols):], start=len(cols)):
                pairs.append((f"field_{i + 1}", value))
            yield pairs


def read_w3c_records(path):
    fields = None
    with open_text(path) as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.lower().startswith("#fields:"):
                    fields = [c.lower() for c in line[8:].split()]
                continue
            if not fields:
                yield None
                continue
            cells = line.split(" ")
            pairs = list(zip(fields, cells))
            for i, value in enumerate(cells[len(fields):], start=len(fields)):
                pairs.append((f"field_{i + 1}", value))
            yield pairs


def records(path, fmt):
    return read_csv_records(path) if fmt == "iisgeolocate" else read_w3c_records(path)


def bad_rows(path):
    """Rows in iisGeolocate's BadDataRows_REVIEW_ME.txt (its first line is a header)."""
    try:
        with open_text(path) as fh:
            return max(0, sum(1 for line in fh if line.strip()) - 1)
    except OSError:
        return 0


def doc_id(host, name, pairs, seen):
    """Stable _id: host + IIS log name + the request's own fields (+ occurrence number)."""
    key = [host, name] + sorted((f, (v or "").strip()) for f, v in pairs
                                if f not in ID_EXCLUDED and (v or "").strip() not in ("", "-"))
    raw = json.dumps(key, ensure_ascii=False)
    n = seen.get(raw, 0)
    seen[raw] = n + 1
    return hashlib.sha1(f"{raw}|{n}".encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- Elasticsearch

class ES(EsClient):
    def call(self, method, path, body=None, ctype="application/json"):
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        return self.request(method, path, body, ctype)

    def prepare_index(self, index, body):
        """Create the index from the merged body, or extend an httpdlog index a toolkit web
        importer made (AWS/alb2sofelk.py, cloudfrontaccess2sofelk.py, Linux/httpd2sofelk.py)."""
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            status, resp = self.call("PUT", f"/{index}", body)
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
            return "created"
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        mapping = next(iter(resp.values()), {}).get("mappings", {})
        if mapping.get("_meta", {}).get("toolkit_schema") != SCHEMA:
            sys.exit(f"Index '{index}' exists but was not created by a toolkit web log importer (for"
                     f" example by SOF-ELK's Logstash pipeline), so its field types may differ.\n"
                     f"Delete it and reload:  curl -X DELETE '{self.url}/{index}'\n"
                     f"or load into a new index with --index <prefix>-<hostname>.")
        new = {"_meta": mapping.get("_meta", body["mappings"]["_meta"]),
               "properties": body["mappings"]["properties"]}
        status, resp = self.call("PUT", f"/{index}/_mapping", new)
        if status >= 300:
            sys.exit(f"Index '{index}' mapping does not match the IIS fields ({status}):"
                     f" {json.dumps(resp)[:500]}\nDelete the index and reload.")
        return "appending"

    def send(self, lines, stats):
        if not lines:
            return
        status, resp = self.bulk(lines)
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    err = res["error"]
                    print(f"    ! {err.get('reason', err) if isinstance(err, dict) else err}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def host_count(self, index, host):
        self.call("POST", f"/{index}/_refresh")
        status, resp = self.call("POST", f"/{index}/_count", {"query": {"bool": {"filter": [
            {"term": {"host.name": host}}, {"term": {"event.dataset": DATASET}}]}}})
        return resp.get("count") if status < 300 else None


# --------------------------------------------------------------------------- main

def find_files(paths):
    """Input files, each with the path recorded in log.file.path: relative to the folder given
    on the command line (as the AWS and Linux importers do), or as given for a single file."""
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            found = sorted((x for x in p.rglob("*") if x.is_file()), key=lambda x: str(x).lower())
            files += [(x, x.relative_to(p).as_posix()) for x in found]
        elif p.is_file():
            files.append((p, str(p)))
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description="Load IIS access logs (iisGeolocate CSV output or raw W3C"
                                             " u_ex*.log files) into SOF-ELK (index httpdlog-<hostname>)")
    ap.add_argument("paths", nargs="+", help="iisGeolocate output folders, CSVs or IIS .log files"
                                             " (folders are searched recursively; .gz is fine)")
    ap.add_argument("--hostname", required=True, help="The IIS server the logs came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None, help="Override target index; must end in -<hostname>"
                                                  " (default: httpdlog-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="Accepted for wrapper compatibility; IIS W3C logs are UTC, so it is not used")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show the files, column -> field mapping and sample documents; send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    add_client_arguments(ap)
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    if args.local_tz and not TZ_ARG_RE.match(args.local_tz.strip()):
        sys.exit(f"--local-tz must look like +08:00 or -0500, got '{args.local_tz}'")
    try:
        host = sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = resolve_index(PREFIX, host, args.index)
    _component, _index_tpl, body = templates.load("httpdlog")

    files = find_files(args.paths)
    selected, skipped, side, bad = [], [], [], 0
    for f, rel in files:
        fmt, detail = sniff(f)
        if fmt in ("iisgeolocate", "w3c"):
            selected.append((f, rel, fmt))
        elif fmt == "side":
            side.append((f, detail))
            if "bad rows" in detail:
                bad += bad_rows(f)
        else:
            skipped.append((f, detail))
    if not selected:
        sys.exit("No iisGeolocate CSVs or IIS W3C logs found.")

    counts = {"iisgeolocate": 0, "w3c": 0}
    for _f, _rel, fmt in selected:
        counts[fmt] += 1
    print(f"{len(selected)} file(s) -> index '{index}' (host '{host}'): "
          f"{counts['iisgeolocate']} iisGeolocate CSV(s), {counts['w3c']} raw W3C log(s)")
    for f, detail in side:
        print(f"  not loaded: {f.name} ({detail})")
    if skipped:
        print(f"  skipped {len(skipped)} other file(s)" + (": " + ", ".join(f.name for f, _ in skipped[:5])
                                                          + (" ..." if len(skipped) > 5 else "")))
    if bad:
        print(f"  WARNING: iisGeolocate could not parse {bad} row(s); they are only in"
              f" BadDataRows_REVIEW_ME.txt and are not loaded. Review them by hand.")
    if args.local_tz:
        print("  note: --local-tz ignored; IIS W3C log times are UTC.")

    ingest = {"ok": 0, "errors": 0, "updated": 0}
    es = None
    if not args.dry_run:
        es = ES(args.es, args.user, args.password, args.insecure)
        try:
            status, info = es.call("GET", "/")
        except error.URLError as exc:
            sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {exc.reason}")
        if status >= 300:
            sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
        print(f"\nConnected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")
        print(f"Index '{index}': {es.prepare_index(index, body)}")

    rows = docs = 0
    problems, unmapped, computer_names, samples = {}, set(), set(), []
    seen_by_log = {}
    lines = []
    for f, rel, fmt in selected:
        name = log_name(f)
        seen = seen_by_log.setdefault(name, {})
        meta = {"host": host, "path": rel, "format": fmt, "case": args.case}
        file_rows = 0
        for pairs in records(f, fmt):
            rows += 1
            file_rows += 1
            if pairs is None:
                problems["W3C line before any #Fields header"] = problems.get("W3C line before any #Fields header", 0) + 1
                continue
            doc, problem = build(pairs, meta)
            if doc is None:
                problems[problem] = problems.get(problem, 0) + 1
                continue
            docs += 1
            unmapped.update((get_field(doc, "iis.unmapped") or {}).keys())
            if get_field(doc, "host.hostname"):
                computer_names.add(get_field(doc, "host.hostname"))
            if args.dry_run:
                if len(samples) < args.sample_docs:
                    samples.append(doc)
                continue
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id(host, name, pairs, seen)}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
            if len(lines) >= args.batch_size * 2:
                es.send(lines, ingest)
        if not args.dry_run:
            es.send(lines, ingest)
        print(f"  {f.name}: {file_rows} row(s)")

    print(f"\n{rows} row(s) read, {docs} document(s) built.")
    for problem, n in sorted(problems.items()):
        print(f"  skipped {n} row(s): {problem}")
    if unmapped:
        print(f"Columns kept under iis.unmapped.*: {', '.join(sorted(unmapped))}")
    others = {c for c in computer_names if c.lower() != host}
    if others:
        print(f"note: s-computername in the logs is {', '.join(sorted(computer_names))}, not '{host}';"
              f" check that --hostname is the right server.")

    if args.dry_run:
        print("\nColumn -> field:")
        for field, (target, _conv) in SIMPLE.items():
            print(f"  {field:<18} -> {target}")
        for field, target in (("date + time", "@timestamp"), ("cs-uri-stem", "url.path, url.extension"),
                              ("cs-uri-query", "url.query"), ("cs-version", "http.version"),
                              ("cs(user-agent)", "user_agent.original"),
                              ("sc-win32-status", "process.exit_code, iis.win32_status"),
                              ("time-taken", "iis.time_taken.ms, event.duration (ns)"),
                              ("geocity / geocountry", "source.geo.city_name / country_name")):
            print(f"  {field:<18} -> {target}")
        print("\nSample document(s):")
        for doc in samples:
            print("  " + json.dumps(doc, ensure_ascii=False)[:1200])
        print("\nDry run only - nothing sent.")
        return 0

    new = ingest["ok"] - ingest["updated"]
    print(f"Done: {new} new document(s), {ingest['updated']} already in index (re-run),"
          f" {ingest['errors']} error(s).")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == docs else "DOES NOT MATCH"
        print(f"Index check: '{index}' holds {in_index} IIS document(s) for host '{host}'"
              f" ({verdict} the {docs} built).")
        if in_index > docs:
            print("  More documents than rows: other logs of this host were loaded earlier, or the same"
                  " requests came from raw logs and CSVs whose rows differ.")
    print("In Kibana, use the 'httpdlog-*' data view (time field @timestamp) and filter on"
          " event.dataset : iis.access.")
    return 1 if ingest["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
