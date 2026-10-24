#!/usr/bin/env python3
"""Load NirSoft BrowsingHistoryView CSV/TXT/TSV exports into browsinghistory-<hostname>.

Field extraction, type inference, date-order checks, URL/user enrichment, stable IDs, and
Elasticsearch bulk loading follow the original bhv2sofelk.py importer. `forensic_tag` is omitted.
"""
import argparse
import base64
import codecs
import csv
import datetime as dt
import hashlib
import json
import re
import ssl
import sys
from pathlib import Path
from urllib import error, request
from urllib.parse import urlsplit

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

FORENSIC_TAG = "BrowsingHistory"

# BrowsingHistoryView's default column order, used only when the export has no header line
DEFAULT_COLUMNS = [
    "URL", "Title", "Visit Time", "Visit Count", "Visited From", "Visit Type",
    "Visit Duration", "Web Browser", "User Profile", "Browser Profile", "URL Length",
    "Typed Count", "History File", "Record ID",
]
KNOWN_HEADERS = {c.lower() for c in DEFAULT_COLUMNS}

# ISO-style: 2026-10-08 09:12:44(.fff)(Z|+08:00)
ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})?$")
# Regional: 10/08/2026 9:12:44 AM, 08.10.2026 21:12, 2026/10/08 21:12:44
LOCALE_RE = re.compile(
    r"^(\d{1,4})[/.-](\d{1,2})[/.-](\d{1,4})[ T,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*([AaPp]\.?[Mm]\.?)?$")
INT_RE = re.compile(r"^-?\d{1,19}$")
BOOLS = {"true": True, "false": False, "yes": True, "no": False}
TZ_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

TIME_PRIORITY = ["visittime", "lastvisittime", "lastvisit", "visitdate", "time", "date", "timestamp"]
TIME_NAME_RE = re.compile(r"time|date|visit", re.I)
RESERVED = {"@timestamp", "forensic_tag", "host", "user", "url", "ingest", "case"}

ES_FAMILY = {
    "text": "string", "keyword": "string", "match_only_text": "string", "wildcard": "string",
    "long": "long", "integer": "long", "short": "long", "byte": "long",
    "date": "date", "date_nanos": "date", "boolean": "boolean",
}


# --------------------------------------------------------------------------- reading

def detect_encoding(path):
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            return "utf-16"
        if head.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        fh.seek(0)
        dec = codecs.getincrementaldecoder("utf-8")()
        try:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                dec.decode(chunk)
            dec.decode(b"", final=True)
            return "utf-8"
        except UnicodeDecodeError:
            return "cp1252"  # NirSoft's ANSI export on Western Windows


def sanitize_hostname(hostname):
    """Lower-case host name safe for an Elasticsearch index name."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def clean_fields(header):
    used, out = set(RESERVED), []
    for name in header:
        f = re.sub(r"[^\w]+", "_", name.strip()).strip("_") or "field"
        if f[0].isdigit():
            f = "f_" + f
        base, i = f, 2
        while f in used:
            f, i = f"{base}_{i}", i + 1
        used.add(f)
        out.append(f)
    return out


class Table:
    """A NirSoft export: encoding, delimiter and header (or lack of one) worked out once."""

    def __init__(self, path):
        self.path = path
        self.encoding = detect_encoding(path)
        with open(path, encoding=self.encoding, errors="replace", newline="") as fh:
            first = fh.readline()
        counts = {d: first.count(d) for d in (",", "\t", ";")}
        self.delimiter = max(counts, key=counts.get)
        first_row = next(csv.reader([first], delimiter=self.delimiter), [])
        names = {c.strip().lower() for c in first_row}
        self.has_header = bool(names & KNOWN_HEADERS) or not re.match(r"^[a-z][a-z0-9+.-]*:", first_row[0].strip().lower() if first_row else "")
        if self.has_header:
            self.raw_header = first_row
            self.note = None
        else:
            n = len(first_row)
            if n == len(DEFAULT_COLUMNS):
                self.raw_header = list(DEFAULT_COLUMNS)
                self.note = "no header line - assumed BrowsingHistoryView's default column order"
            else:
                self.raw_header = [f"col_{i + 1}" for i in range(n)]
                self.note = (f"no header line and {n} columns (default layout has"
                             f" {len(DEFAULT_COLUMNS)}) - columns named col_1..col_{n}")
        self.fields = clean_fields(self.raw_header)

    def rows(self):
        with open(self.path, encoding=self.encoding, errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter=self.delimiter)
            if self.has_header:
                next(reader, None)
            for row in reader:
                if any(c.strip() for c in row):
                    yield row


# --------------------------------------------------------------------------- dates

def resolve_order(ev):
    """Day/month order from evidence. Returns 'ymd'|'dmy'|'mdy'|'conflict'|None (ambiguous)."""
    if ev["ymd"] and not (ev["day_first"] or ev["month_first"] or ev["other"]):
        return "ymd"
    if ev["day_first"] and ev["month_first"]:
        return "conflict"
    if ev["day_first"]:
        return "dmy"
    if ev["month_first"]:
        return "mdy"
    return None


def to_utc(y, mo, d, h, mi, ss, frac, offset):
    """Local wall-clock parts + offset ('Z' or +HH:MM) -> '2026-09-13T14:05:10.000Z', or None."""
    try:
        if offset == "Z":
            tzinfo = dt.timezone.utc
        else:
            sign = 1 if offset[0] == "+" else -1
            tzinfo = dt.timezone(sign * dt.timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
        local = dt.datetime(int(y), int(mo), int(d), h, int(mi), int(ss or 0),
                            int(frac) * 1000, tzinfo=tzinfo)
    except ValueError:
        return None
    u = local.astimezone(dt.timezone.utc)
    return u.strftime("%Y-%m-%dT%H:%M:%S.") + f"{u.microsecond // 1000:03d}Z"


def parse_datetime(value, order, tz):
    """Any supported date string -> ISO 8601 in UTC ('...Z'), or None."""
    v = value.strip()
    m = ISO_RE.match(v)
    if m:
        y, mo, d, hh, mi, ss, frac, z = m.groups()
        h = int(hh)
        offset = tz if not z else ("Z" if z == "Z" else (z if ":" in z else z[:3] + ":" + z[3:]))
    else:
        m = LOCALE_RE.match(v)
        if not m or not order:
            return None
        a, b, c, hh, mi, ss, frac, ampm = m.groups()
        if order == "ymd" or len(a) == 4:
            y, mo, d = a, b, c
        elif order == "dmy":
            d, mo, y = a, b, c
        else:
            mo, d, y = a, b, c
        if len(y) == 2:
            y = "20" + y
        h = int(hh)
        if ampm:
            pm = ampm[0].lower() == "p"
            if h == 12:
                h = 0
            if pm:
                h += 12
        offset = tz
    frac = (frac or "")[:3].ljust(3, "0")
    return to_utc(y, mo, d, h, mi, ss, frac, offset)


# --------------------------------------------------------------------------- inference

def new_stat():
    return {"filled": 0, "boolean": True, "long": True, "date": True, "bad": None,
            "ymd": 0, "day_first": 0, "month_first": 0, "other": 0, "iso": 0}


def scan(table, stats):
    count = 0
    for row in table.rows():
        count += 1
        for i, f in enumerate(table.fields):
            v = row[i].strip() if i < len(row) else ""
            if not v:
                continue
            s = stats.setdefault(f, new_stat())
            s["filled"] += 1
            if s["boolean"] and v.lower() not in BOOLS:
                s["boolean"] = False
            if s["long"] and not INT_RE.match(v):
                s["long"] = False
            if ISO_RE.match(v):
                s["iso"] += 1
                continue
            m = LOCALE_RE.match(v)
            if not m:
                s["date"] = False
                if s["bad"] is None:
                    s["bad"] = v[:60]
                continue
            a, b = m.group(1), m.group(2)
            if len(a) == 4:
                s["ymd"] += 1
            elif int(a) > 12:
                s["day_first"] += 1
            elif int(b) > 12:
                s["month_first"] += 1
            else:
                s["other"] += 1
    return count


def decide_types(stats, forced_order):
    """field -> (type, order). Dates keep their day/month order for parsing."""
    types = {}
    for f, s in stats.items():
        if not s["filled"]:
            types[f] = ("string", None)
        elif s["boolean"]:
            types[f] = ("boolean", None)
        elif s["long"]:
            types[f] = ("long", None)
        elif s["date"]:
            if s["iso"] == s["filled"]:
                types[f] = ("date", "iso")
            else:
                order = forced_order or resolve_order(s)
                types[f] = ("date", order)  # order may be None / 'conflict' -> handled by check
        else:
            types[f] = ("string", None)
    return types


def pick_time_field(types):
    dates = [f for f, (t, o) in types.items() if t == "date"]
    lower = {f.lower().replace("_", ""): f for f in dates}
    for name in TIME_PRIORITY:
        if name in lower:
            return lower[name]
    return dates[0] if dates else None


# --------------------------------------------------------------------------- documents

def user_from_profile(value):
    v = value.strip().rstrip("\\/")
    if not v:
        return None
    return re.split(r"[\\/]", v)[-1].lower() or None


def build_doc(row, fields, write, renames, ts_field, tz, meta, ingest_time):
    doc, ts = {}, None
    for i, f in enumerate(fields):
        raw = row[i] if i < len(row) else ""
        v = raw.strip()
        if not v:
            continue
        t, order = write[f]
        val = raw
        if t == "date":
            val = parse_datetime(v, None if order == "iso" else order, tz) or raw
            if f == ts_field and val != raw:
                ts = val
                doc[f"{renames.get(f, f)}_local"] = v  # as NirSoft showed it, before conversion
        elif t == "long":
            val = int(v)
        elif t == "boolean":
            val = BOOLS[v.lower()]
        doc[renames.get(f, f)] = val

    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": meta["host"]}
    if meta["user_col"] is not None and meta["user_col"] < len(row):
        user = user_from_profile(row[meta["user_col"]])
        if user:
            doc["user"] = {"name": user}
    if meta["url_col"] is not None and meta["url_col"] < len(row):
        try:
            u = urlsplit(row[meta["url_col"]].strip())
            url = {}
            if u.scheme:
                url["scheme"] = u.scheme.lower()
            if u.hostname:
                url["domain"] = u.hostname.lower()
            if url:
                doc["url"] = url
        except ValueError:
            pass
    doc["ingest"] = {"source_file": meta["source_file"],
                     "timestamp_source": ts_field if ts else "ingest_time"}
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc


# --------------------------------------------------------------------------- check

def timestamp_check(tables, stats, types, ts_field, tz, rows_total, forced_order=None):
    """Print the timestamp report. Returns True if it's safe to load."""
    ok = True
    print("\nTimestamp check")
    for t in tables:
        enc = {"utf-16": "UTF-16", "utf-8-sig": "UTF-8 (BOM)", "utf-8": "UTF-8", "cp1252": "ANSI"}[t.encoding]
        delim = {",": "comma", "\t": "tab", ";": "semicolon"}[t.delimiter]
        print(f"  file: {t.path.name}  [{enc}, {delim}-delimited]")
        if t.note:
            print(f"    WARN {t.note}")
    for f, (typ, order) in types.items():
        if typ != "date":
            continue
        s = stats[f]
        if order == "iso":
            desc = "ISO format"
        elif order in ("dmy", "mdy", "ymd"):
            if forced_order:
                how = "from --date-order"
                against = {"dmy": s["month_first"], "mdy": s["day_first"], "ymd": 0}[order]
                if against:
                    how += (f"; WARNING {against} value(s) are impossible that way and will not be"
                            f" searchable as dates")
            else:
                how = (f"detected: {s['day_first'] or s['month_first'] or s['ymd']} value(s)"
                       f" only make sense that way")
            desc = {"dmy": "day/month/year", "mdy": "month/day/year", "ymd": "year/month/day"}[order] + f" ({how})"
        elif order == "conflict":
            desc = "MIXED day-first and month-first values"
            ok = False
        else:
            desc = "AMBIGUOUS: every date has day and month <= 12"
            ok = False
        mark = "OK  " if order in ("iso", "dmy", "mdy", "ymd") else "STOP"
        star = "  <- @timestamp" if f == ts_field else ""
        print(f"  {mark} {f}: {desc}, times read as {tz}{star}")
        if order is None:
            print("       Can't tell 08/10 = 8 Oct from 10 Aug. Re-run with --date-order dmy (e.g. SG/UK"
                  " regional settings) or --date-order mdy (US) to match the machine that ran"
                  " BrowsingHistoryView.")
        elif order == "conflict":
            print("       Some values only work day-first and others only month-first: the file mixes"
                  " formats. Check the export; use --date-order to force one reading.")
    if ts_field:
        filled = stats[ts_field]["filled"]
        if filled < rows_total:
            print(f"    - {rows_total - filled} row(s) have no {ts_field} -> those use ingest time")
    else:
        print("  WARN no date column found -> every row uses ingest time")
    for f, s in stats.items():
        if types[f][0] != "date" and TIME_NAME_RE.search(f) and s["filled"] and (s["iso"] or s["ymd"] or s["day_first"] or s["month_first"] or s["other"]):
            n = s["iso"] + s["ymd"] + s["day_first"] + s["month_first"] + s["other"]
            print(f"    - {f}: {n}/{s['filled']} values are dates, the rest aren't"
                  f" (e.g. \"{s['bad']}\") -> stored as text")
    if tz == "Z":
        print("  note: --tz UTC assumes BrowsingHistoryView's GMT/UTC time option was ON")
    else:
        print(f"  note: --tz {tz} must be the clock of the machine that RAN BrowsingHistoryView"
              f" (not necessarily the suspect host)")
    return ok


# --------------------------------------------------------------------------- Elasticsearch

META_PROPS = {
    "@timestamp": {"type": "date"},
    "host": {"properties": {"name": {"type": "keyword"}}},
    "user": {"properties": {"name": {"type": "keyword"}}},
    "url": {"properties": {"domain": {"type": "keyword"}, "scheme": {"type": "keyword"}}},
    "ingest": {"properties": {"source_file": {"type": "keyword"},
                              "timestamp_source": {"type": "keyword"}}},
    "case": {"type": "keyword"},
}


class ES:
    def __init__(self, url, user=None, password=None, insecure=False):
        self.url = url.rstrip("/")
        self.headers = {}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, method, path, body=None, ctype="application/json"):
        data = body.encode("utf-8") if body is not None else None
        req = request.Request(self.url + path, data=data, method=method,
                              headers={**self.headers, "Content-Type": ctype})
        try:
            with request.urlopen(req, timeout=300, context=self.ctx) as r:
                status, raw = r.status, r.read()
        except error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, (json.loads(raw) if raw else {})
        except ValueError:
            return status, {"raw": raw.decode("utf-8", "replace")}

    def existing_fields(self, index):
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            return None
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        props = next(iter(resp.values()), {}).get("mappings", {}).get("properties", {})
        return {f: m.get("type", "object") for f, m in props.items()}

    def create_index(self, index, props):
        body = {
            "settings": {"number_of_replicas": 0, "index.mapping.total_fields.limit": 2000,
                         "index.mapping.ignore_malformed": True},
            "mappings": {
                "date_detection": False, "numeric_detection": False,
                "dynamic_templates": [{"strings": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
                }}],
                "properties": {**props, **META_PROPS},
            },
        }
        status, resp = self.call("PUT", f"/{index}", json.dumps(body))
        if status >= 300:
            sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")

    def add_fields(self, index, props):
        if props:
            status, resp = self.call("PUT", f"/{index}/_mapping", json.dumps({"properties": props}))
            if status >= 300:
                sys.exit(f"Could not update mapping of {index} ({status}): {json.dumps(resp)[:500]}")

    def bulk(self, lines, stats):
        if not lines:
            return
        status, resp = self.call("POST", "/_bulk", "\n".join(lines) + "\n", "application/x-ndjson")
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    print(f"    ! {res['error'].get('reason', res['error'])}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def host_count(self, index, host):
        self.call("POST", f"/{index}/_refresh")
        q = {"query": {"term": {"host.name": host}}}
        status, resp = self.call("POST", f"/{index}/_count", json.dumps(q))
        return resp.get("count") if status < 300 else None


def fit_existing(types, existing):
    """Adjust types to an existing index. Returns (write, renames)."""
    write, renames = {}, {}
    for f, (t, order) in types.items():
        if existing is None or f not in existing:
            write[f] = (t, order)
            continue
        fam = ES_FAMILY.get(existing[f], "other")
        if fam == t:
            write[f] = (t, order)
        elif fam == "string":
            write[f] = ("string", None)
        else:
            renames[f] = f"{f}_text"
            write[f] = ("string", None)
    return write, renames


def mapping_props(write, renames, skip=()):
    return {renames.get(f, f): {"type": t} for f, (t, _) in write.items()
            if t != "string" and renames.get(f, f) not in skip}


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Load NirSoft BrowsingHistoryView CSVs into SOF-ELK.")
    ap.add_argument("paths", nargs="+", help="BrowsingHistory CSV file(s) or folders")
    ap.add_argument("--hostname", required=True, help="Host the browser history came from")
    ap.add_argument("--tz", required=True, metavar="+HH:MM|UTC",
                    help="UTC offset of the machine that RAN BrowsingHistoryView (e.g. +08:00),"
                         " or UTC if its GMT time option was on")
    ap.add_argument("--date-order", choices=["dmy", "mdy", "ymd"],
                    help="Force day/month order when it can't be detected")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None, help="Override target index (default: browsinghistory-<hostname>)")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true", help="Check and show samples; send nothing")
    # "--tz -05:00" would otherwise be read as an unknown option because of the leading minus
    argv = sys.argv[1:]
    for i, a in enumerate(argv[:-1]):
        if a == "--tz" and argv[i + 1].startswith("-"):
            argv[i:i + 2] = [f"--tz={argv[i + 1]}"]
            break
    args = ap.parse_args(argv)

    if args.tz.strip().upper() in ("UTC", "GMT", "Z", "+00:00", "0"):
        tz = "Z"
    else:
        m = TZ_RE.match(args.tz.strip())
        if not m or int(m.group(2)) > 14:
            sys.exit(f"--tz must look like +08:00, -0500 or UTC, got '{args.tz}'")
        tz = f"{m.group(1)}{int(m.group(2)):02d}:{m.group(3) or '00'}"

    try:
        host = sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = (args.index or f"browsinghistory-{host}").lower()
    if args.index and index != args.index:
        print(f"note: Elasticsearch index names must be lower-case, using '{index}'\n")

    files = []
    for p in map(Path, args.paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".csv", ".txt", ".tsv"))
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    tables = []
    for f in files:
        if f.stat().st_size == 0:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        tables.append(Table(f))
    if not tables:
        sys.exit("No CSV files found.")

    stats, rows_total = {}, 0
    for t in tables:
        rows_total += scan(t, stats)
    for t in tables:
        for f in t.fields:
            stats.setdefault(f, new_stat())
    types = decide_types(stats, args.date_order)
    ts_field = pick_time_field(types)
    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    print(f"{len(tables)} file(s), {rows_total} rows -> index '{index}', host={host}")
    safe = timestamp_check(tables, stats, types, ts_field, tz, rows_total, args.date_order)

    def meta_for(t):
        lower = [x.lower() for x in t.fields]
        return {"host": host, "case": args.case, "source_file": t.path.name,
                "user_col": lower.index("user_profile") if "user_profile" in lower else None,
                "url_col": lower.index("url") if "url" in lower else None}

    if args.dry_run:
        typed = {f: (t if t != "date" else f"date ({o})") for f, (t, o) in types.items() if t != "string"}
        print(f"\nTyped fields: {typed or 'none'}")
        print("\nSample documents:")
        shown = 0
        for t in tables:
            for row in t.rows():
                doc = build_doc(row, t.fields, types, {}, ts_field, tz, meta_for(t), ingest_time)
                print("  " + json.dumps(doc, ensure_ascii=False)[:700])
                shown += 1
                if shown == 2:
                    break
            if shown == 2:
                break
        print("\nDry run only - nothing sent." + ("" if safe else
              "  Fix the STOP item(s) above before loading."))
        return

    if not safe:
        sys.exit("\nNot loading: fix the STOP item(s) in the timestamp check first"
                 " (usually by adding --date-order).")

    es = ES(args.es, args.user, args.password, args.insecure)
    try:
        status, info = es.call("GET", "/")
    except error.URLError as e:
        sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {e.reason}")
    if status >= 300:
        sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
    print(f"\nConnected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    existing = es.existing_fields(index)
    write, renames = fit_existing(types, existing)
    if existing is None:
        es.create_index(index, mapping_props(write, renames))
        print(f"Created index '{index}'")
    else:
        es.add_fields(index, mapping_props(write, renames, skip=existing))
        print(f"Index '{index}' exists - appending")
        for f, new in sorted(renames.items()):
            print(f"  note: '{f}' is mapped as {existing[f]} in the index but this data doesn't fit;"
                  f" storing it as '{new}'")

    stats_b = {"ok": 0, "errors": 0, "updated": 0}
    lines, seen = [], {}
    for t in tables:
        meta = meta_for(t)
        for row in t.rows():
            content = dict(sorted(zip(t.raw_header, (c.strip() for c in row))))
            key = json.dumps([host, FORENSIC_TAG, content], ensure_ascii=False)
            n = seen.get(key, 0)
            seen[key] = n + 1
            doc_id = hashlib.sha1(f"{key}|{n}".encode()).hexdigest()
            doc = build_doc(row, t.fields, write, renames, ts_field, tz, meta, ingest_time)
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
            if len(lines) >= args.batch_size * 2:
                es.bulk(lines, stats_b)
    es.bulk(lines, stats_b)

    new = stats_b["ok"] - stats_b["updated"]
    print(f"\nDone: {rows_total} rows read -> {new} new documents, {stats_b['updated']} already in"
          f" index (re-run), {stats_b['errors']} errors.")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == rows_total else "DOES NOT MATCH"
        print(f"Index check: '{index}' holds {in_index} browsing history documents for host"
              f" '{host}' ({verdict} the {rows_total} rows read).")
    print(f"In Kibana, create a data view for '{index}' with @timestamp as the time field;"
          f" useful columns: user.name, url.domain, Title, Web_Browser, Visit_Count.")


if __name__ == "__main__":
    main()
