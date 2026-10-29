"""Shared engine for the AWS log importers (CloudTrail, VPC Flow, ALB, WAF).

Each importer describes its log type with an AwsLog object: the index prefix, which files
are its own, and a parse(fh, ctx) generator that turns one input file into documents. This
module does everything else the same way for all four:

  * finds input files (recursively), opening gzip by its magic bytes whatever the extension;
  * loads AWS/index_templates/ (component-toolkit-aws-common.json + index-<prefix>.json),
    installs them, creates or updates the target index and refuses an index made by
    something else (for example SOF-ELK's Logstash pipeline);
  * writes one index per evidence source, named <prefix>-<source> (aws-cloudtrail-prod);
  * adds the common fields (labels.evidence_source, case, event.dataset, cloud.provider,
    log.file.path, log.offset) and a deterministic _id, so re-runs overwrite;
  * sends everything through the shared retrying _bulk client in
    Windows/common/sof_elk_es_client.py.

Standard library only.
"""
from __future__ import annotations

import argparse
import copy
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

AWS_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = AWS_DIR / "index_templates"
COMMON_COMPONENT = "sofelk-toolkit-aws-common"

# The retrying bulk client is shared with the Windows importers.
sys.path.insert(0, str(AWS_DIR.parent / "Windows" / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, resolve_index  # noqa: E402

try:
    import csv
    csv.field_size_limit(sys.maxsize)
except OverflowError:  # Windows: C long is 32-bit
    csv.field_size_limit(2**31 - 1)

GZIP_MAGIC = b"\x1f\x8b"
INT64_MAX = 2**63 - 1


# --------------------------------------------------------------------------- small helpers

def set_field(doc, dotted, value):
    """doc["a"]["b"] = value for "a.b". None, "" and [] are not written."""
    if value is None or value == "" or value == []:
        return
    parts = dotted.split(".")
    for p in parts[:-1]:
        doc = doc.setdefault(p, {})
    doc[parts[-1]] = value


def get_field(doc, dotted):
    for p in dotted.split("."):
        if not isinstance(doc, dict) or p not in doc:
            return None
        doc = doc[p]
    return doc


def dig(obj, *path):
    """obj[path[0]][path[1]]... or None; integer steps index into lists."""
    for p in path:
        if isinstance(p, int):
            if not isinstance(obj, list) or len(obj) <= p:
                return None
        elif not isinstance(obj, dict):
            return None
        obj = obj[p] if isinstance(p, int) else obj.get(p)
        if obj is None:
            return None
    return obj


def snake(name):
    """camelCase / kebab-case / free-form name -> snake_case field name."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", str(name).strip())
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "field"


def valid_ip(value):
    """Normalised IP string, or None if value is not an IP address."""
    if not isinstance(value, str) or not value or value == "-":
        return None
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if abs(value) <= INT64_MAX else None
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,19}", value.strip()):
        v = int(value.strip())
        return v if abs(v) <= INT64_MAX else None
    return None


def to_float(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")


# Spreadsheet dates ("10/20/2026 1:05:00 PM", "20/10/2026 13:05"): Excel rewrites ISO times
# like this when a CSV is opened and saved. The day/month order is taken from --date-order.
SLASH_RE = re.compile(r"^(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?\s*([AaPp][Mm])?$")
SETTINGS = {"date_order": "mdy", "slash_dates": 0}


def iso(value):
    """ISO 8601 text (any precision, Z or offset; no offset = UTC) -> ISO 8601 with ms, or None.

    Also accepts spreadsheet-style M/D/YYYY h:mm[:ss] [AM|PM] (or D/M/YYYY with --date-order dmy),
    which is what a CSV looks like after Excel has re-saved it; such times are taken as UTC.
    """
    if not isinstance(value, str):
        return None
    m = ISO_RE.match(value.strip())
    if not m:
        return _slash_date(value.strip())
    date, time, frac, tz = m.groups()
    frac = (frac or "")[:3].ljust(3, "0")
    if not tz:
        tz = "Z"
    elif tz != "Z" and ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    if tz in ("+00:00", "-00:00"):
        tz = "Z"
    try:
        dt.datetime.fromisoformat(f"{date}T{time}")
    except ValueError:
        return None
    return f"{date}T{time}.{frac}{tz}"


def _slash_date(value):
    m = SLASH_RE.match(value)
    if not m:
        return None
    a, b, year, hour, minute, sec, frac, ampm = m.groups()
    month, day = (int(a), int(b)) if SETTINGS["date_order"] == "mdy" else (int(b), int(a))
    hour = int(hour)
    if ampm:
        hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
    try:
        stamp = dt.datetime(int(year), month, day, hour, int(minute), int(sec or 0))
    except ValueError:
        return None
    SETTINGS["slash_dates"] += 1
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + (frac or "")[:3].ljust(3, "0") + "Z"


def any_time(value, epoch_unit="s"):
    """A time that may be epoch seconds/milliseconds or text (ISO or spreadsheet style)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return epoch_to_iso(value, epoch_unit)
    if isinstance(value, str) and re.fullmatch(r"\d{9,13}(?:\.\d+)?", value.strip()):
        digits = value.strip().split(".")[0]
        return epoch_to_iso(value.strip(), "ms" if len(digits) >= 12 else "s")
    return iso(value) if isinstance(value, str) else None


def epoch_to_iso(value, unit="s"):
    """Epoch seconds (unit="s") or milliseconds (unit="ms") -> ISO 8601 UTC with ms, or None."""
    n = to_int(value)
    if n is None:
        f = to_float(value)
        if f is None:
            return None
        n = f
    seconds = n / 1000 if unit == "ms" else n
    try:
        stamp = dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def compact_json(value):
    """JSON text for an object kept as a string (SOF-ELK's json_encode), or None when empty."""
    if value in (None, "", {}, []):
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sanitize_source(value):
    """Evidence source label -> lower-case text safe for an Elasticsearch index name."""
    out = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower()).strip("._-")
    if not out:
        raise ValueError("--source must contain at least one letter or digit")
    return out


# Region and account from the S3 key layout AWS uses for log delivery:
#   AWSLogs/<account>/<service>/<region>/YYYY/MM/DD/...
S3_KEY_RE = re.compile(r"AWSLogs/(?:o-[a-z0-9]+/)?(\d{12})/([A-Za-z0-9]+)/([a-z]{2}(?:-gov)?-[a-z]+-\d)/")


def path_cloud_hints(path):
    """(account_id, service, region) from an AWS log-delivery S3 key in the path, else Nones."""
    m = S3_KEY_RE.search(Path(path).as_posix())
    return m.groups() if m else (None, None, None)


# --------------------------------------------------------------------------- file access

def open_text(path):
    """Text handle for a plain or gzip file (detected by magic bytes, not the extension)."""
    with open(path, "rb") as raw:
        magic = raw.read(2)
    if magic == GZIP_MAGIC:
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8-sig", errors="replace", newline="")
    return open(path, encoding="utf-8-sig", errors="replace", newline="")


def head_text(path, size=65536):
    """First characters of a file (decompressed if gzip), for format detection."""
    try:
        with open_text(path) as fh:
            return fh.read(size)
    except (OSError, EOFError, gzip.BadGzipFile):
        return ""


def find_files(paths):
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.is_file() and not x.name.startswith("."))
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    return files


def display_path(path, roots):
    """Path relative to the input folder it was found under (stable across machines)."""
    path = Path(path).resolve()
    for root in roots:
        root = Path(root).resolve()
        base = root if root.is_dir() else root.parent
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    return path.name


# --------------------------------------------------------------------------- CSV input
#
# AWS logs often arrive already converted to CSV: Athena query results, CloudWatch Logs Insights
# exports, SIEM or spreadsheet exports, json_normalize-style flattening. csv_records() turns any
# of these back into the native record shape, so the importers parse one structure:
#   * a column holding the whole record as JSON (Insights "@message", "CloudTrail event",
#     "_raw", ...) is used as is;
#   * otherwise column names become field paths: "userIdentity.arn", "httpRequest/clientIp" or
#     Athena's lower-case "useridentity" are matched to the native names case-insensitively;
#   * cell values that are JSON, or Athena/Presto struct text ("{type=IAMUser, arn=...}"),
#     are decoded into objects.

RAW_COLUMNS = {"message", "cloudtrailevent", "raw", "rawevent", "rawmessage", "event", "json",
               "logmessage", "eventjson", "record"}
CSV_DELIMITERS = ",\t;|"


def canon(name):
    """Comparison key for column and field names: lower case, letters and digits only."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def looks_like_csv_header(line, needed):
    """True if the first line of a file is a delimited header containing all `needed` names."""
    if not line or line.lstrip().startswith(("{", "[")):
        return False
    delim = max(CSV_DELIMITERS, key=line.count)
    if line.count(delim) < 1:
        return False
    cols = {canon(c) for c in next(csv.reader([line], delimiter=delim))}
    cols |= {canon(c.replace("/", ".").rsplit(".", 1)[-1]) for c in next(csv.reader([line], delimiter=delim))}
    return all(any(n in cols for n in (alt if isinstance(alt, tuple) else (alt,))) for alt in needed)


def csv_reader(fh, head=""):
    """DictReader with the delimiter sniffed from the header line (comma, tab, semicolon, pipe).

    head is text already read from fh (it may end mid-line)."""
    lines = _lines(head, fh)
    first = next(lines, "")
    delim = max(CSV_DELIMITERS, key=first.count)
    return csv.DictReader(_chain(first, lines), delimiter=delim)


def _lines(head, fh):
    if head and not head.endswith("\n"):
        head += fh.readline()
    yield from io.StringIO(head)
    yield from fh


def _chain(first, rest):
    yield first
    yield from rest


def parse_struct(text):
    """Athena/Presto/Hive struct or array text -> Python object, or None if it is not one.

    "{type=IAMUser, arn=arn:aws:iam::1:user/a, sessioncontext={attributes={mfaauthenticated=false}}}"
    Values are unquoted, so inside a struct a comma only ends a value when a "key=" follows
    (a header value may contain ", "); inside an array every comma separates elements.
    "null" becomes None.
    """
    text = text.strip()
    if not text or text[0] not in "{[" or text[-1] not in "}]":
        return None
    try:
        value, pos = _struct_value(text, 0)
    except (ValueError, IndexError):
        return None
    return value if pos == len(text) else None


KEY_RE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_@-]*)=")


def _struct_value(t, i):
    if t[i] == "{":
        out, i = {}, i + 1
        while i < len(t) and t[i] != "}":
            m = KEY_RE.match(t, i)
            if not m:
                raise ValueError("struct key expected")
            key, i = m.group(1), m.end()
            out[key], i = _struct_value(t, i) if i < len(t) and t[i] in "{[" else _struct_scalar(t, i, "}")
            if i < len(t) and t[i] == ",":
                i += 1
        return out, i + 1
    if t[i] == "[":
        out, i = [], i + 1
        while i < len(t) and t[i] != "]":
            while t[i] == " ":
                i += 1
            if t[i] in "{[":
                value, i = _struct_value(t, i)
            else:
                value, i = _struct_scalar(t, i, "]")
            out.append(value)
            if i < len(t) and t[i] == ",":
                i += 1
        return out, i + 1
    return _struct_scalar(t, i, "}")


def _struct_scalar(t, i, closer):
    start = i
    while i < len(t):
        ch = t[i]
        if ch == closer:
            break
        if ch == ",":
            rest = t[i + 1:]
            if closer == "}" and KEY_RE.match(rest):
                break
            if closer == "]":
                break
        i += 1
    value = t[start:i].strip()
    return (None if value.lower() == "null" else value), i


def decode_cell(value):
    """CSV cell -> JSON object, struct object, or the stripped text; None for empty / null."""
    if value is None:
        return None
    v = value.strip()
    if not v or v.lower() in ("null", "none", "nan"):
        return None
    if v[0] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            parsed = parse_struct(v)
            if parsed is not None:
                return parsed
    return v


def canonical_keys(obj, names, keep_case=()):
    """Rename dict keys to their native spelling (names: canon -> native), recursively.

    Keys listed in keep_case keep their children as they are (for example requestParameters,
    whose keys are the API's own parameter names)."""
    if isinstance(obj, list):
        return [canonical_keys(x, names, keep_case) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {}
    for key, value in obj.items():
        native = names.get(canon(key), key)
        out[native] = value if native in keep_case else canonical_keys(value, names, keep_case)
    return out


def csv_records(fh, names, aliases=None, keep_case=(), head=""):
    """Rows of a CSV export -> ("json", text) for a whole-record column, else ("record", dict).

    names    canon -> native field name, for every name used anywhere in the record
    aliases  canon(column) -> native path (tuple), for export-specific column names
    """
    aliases = aliases or {}
    reader = csv_reader(fh, head)
    columns = reader.fieldnames or []
    raw_col = next((c for c in columns if c and canon(c) in RAW_COLUMNS), None)
    for row in reader:
        if raw_col and (row.get(raw_col) or "").strip():
            yield "json", row[raw_col].strip()
            continue
        rec = {}
        for col, value in row.items():
            if col is None or col.lstrip().startswith("@"):  # Logs Insights @timestamp, @ptr, ...
                continue
            decoded = decode_cell(value if isinstance(value, str) else None)
            if decoded is None:
                continue
            key = canon(col)
            if key in aliases:
                path = list(aliases[key])
            else:
                path = [names.get(canon(p), p.strip()) for p in re.split(r"[./]", col) if p.strip()]
            if not path:
                continue
            node = rec
            for part in path[:-1]:
                node = node.setdefault(part, {}) if isinstance(node.get(part, {}), dict) else node
            if isinstance(node, dict) and path[-1] not in node:
                node[path[-1]] = canonical_keys(decoded, names, keep_case) if path[-1] not in keep_case else decoded
        if rec:
            yield "record", _index_lists(rec)


def _index_lists(obj):
    """{"0": a, "1": b} -> [a, b]: Logs Insights writes list items as httpRequest.headers.0.name."""
    if isinstance(obj, list):
        return [_index_lists(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {k: _index_lists(v) for k, v in obj.items()}
    if out and all(isinstance(k, str) and k.isdigit() for k in out):
        return [out[k] for k in sorted(out, key=int)]
    return out


# --------------------------------------------------------------------------- templates

def _load_json(name):
    path = TEMPLATE_DIR / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read index template {path}: {exc}")


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + copy.deepcopy(v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_templates(prefix):
    """(component, index_template, merged index body) for an index prefix like 'aws-waf'."""
    component = _load_json("component-toolkit-aws-common.json")
    index_tpl = _load_json(f"index-{prefix}.json")
    merged = _merge(component.get("template", {}), index_tpl.get("template", {}))
    return component, index_tpl, merged


def template_fields(mappings):
    """({"dotted.leaf": type}, {"open.prefix."}) from mapping properties."""
    exact, open_prefixes = {}, set()

    def walk(props, prefix):
        for name, spec in props.items():
            path = f"{prefix}{name}"
            if spec.get("dynamic") in (True, "true"):
                open_prefixes.add(path + ".")
            if "properties" in spec:
                walk(spec["properties"], path + ".")
            elif spec.get("type", "object") != "object":
                exact[path] = spec["type"]

    walk(mappings.get("properties", {}), "")
    return exact, open_prefixes


def unknown_fields(doc, exact, open_prefixes):
    """Leaf fields of doc that the template does not map (they would be silently dropped)."""
    out = []

    def walk(obj, prefix):
        for k, v in obj.items():
            path = f"{prefix}{k}"
            if any(path.startswith(p) for p in open_prefixes):
                continue
            if isinstance(v, dict):
                walk(v, path + ".")
            elif path not in exact:
                out.append(path)

    walk(doc, "")
    return out


# --------------------------------------------------------------------------- log type description

class AwsLog:
    """What one importer tells the engine.

    prefix       index prefix and template name, e.g. "aws-cloudtrail"
    namespace    field namespace for malformed/unmapped values, e.g. "aws.cloudtrail"
    title        human name for messages, e.g. "AWS CloudTrail"
    dataset      default event.dataset value
    detect       (path, head_text) -> True if the file is this log type's
    parse        (fh, ctx) -> iterator of (id_key, doc) or (None, "skip reason")
                 id_key is a string unique to the record (a record ID, or the raw line);
                 doc is the document without the common fields
    describe     list of "input format" lines for --help and the dry run
    index_template  False when <prefix>-* is a SOF-ELK index family (httpdlog-*): installing a
                 toolkit index template there would take over SOF-ELK's own monthly indexes,
                 so each index is created with the template body directly instead
    """

    def __init__(self, prefix, namespace, title, dataset, detect, parse, describe=(),
                 add_arguments=None, use_occurrence=True, index_template=True):
        self.prefix = prefix
        self.namespace = namespace
        self.title = title
        self.dataset = dataset
        self.detect = detect
        self.parse = parse
        self.describe = list(describe)
        self.add_arguments = add_arguments
        # Content-keyed records (VPC Flow, ALB) can legitimately repeat; number repeats so each
        # copy is kept while a re-run of the same files still overwrites instead of duplicating.
        self.use_occurrence = use_occurrence
        self.index_template = index_template


class Context:
    """Per-file state handed to AwsLog.parse()."""

    def __init__(self, args, path, rel_path):
        self.args = args
        self.path = Path(path)
        self.rel_path = rel_path
        self.account_hint, self.service_hint, self.region_hint = path_cloud_hints(rel_path)
        self.skipped = {}

    def skip(self, reason):
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


# --------------------------------------------------------------------------- Elasticsearch

class ES(EsClient):
    def call(self, method, path, body=None, ctype="application/json"):
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        return self.request(method, path, body, ctype)

    def install_templates(self, log, component, index_tpl):
        templates = [(f"/_component_template/{COMMON_COMPONENT}", component)]
        if log.index_template:
            templates.append((f"/_index_template/sofelk-toolkit-{log.prefix}", index_tpl))
        for path, body in templates:
            status, resp = self.call("PUT", path, body)
            if status >= 300:
                sys.exit(f"Could not install template {path} ({status}): {json.dumps(resp)[:500]}")

    def prepare_index(self, log, index, body):
        """Create the index from the template body, or extend an existing toolkit index."""
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
        if mapping.get("_meta", {}).get("toolkit_schema") != log.prefix:
            sys.exit(f"Index '{index}' exists but was not created by this importer (for example by"
                     f" SOF-ELK's Logstash pipeline or an earlier tool), so its field types may"
                     f" differ.\nDelete it and reload:  curl -X DELETE '{self.url}/{index}'\n"
                     f"or load into a new index with --index <prefix>-<source>.")
        new = {"_meta": body["mappings"]["_meta"],
               "dynamic_templates": body["mappings"].get("dynamic_templates", []),
               "properties": body["mappings"]["properties"]}
        status, resp = self.call("PUT", f"/{index}/_mapping", new)
        if status >= 300:
            sys.exit(f"Index '{index}' mapping does not match the current template ({status}):"
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
                    reason = res["error"].get("reason", res["error"]) if isinstance(res["error"], dict) else res["error"]
                    print(f"    ! {reason}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def source_count(self, index, source):
        self.call("POST", f"/{index}/_refresh")
        status, resp = self.call("POST", f"/{index}/_count",
                                 {"query": {"term": {"labels.evidence_source": source}}})
        return resp.get("count") if status < 300 else None


# --------------------------------------------------------------------------- main loop

def finish_doc(log, doc, ctx, source, offset):
    """Add the fields every AWS document carries."""
    doc.setdefault("event", {}).setdefault("dataset", log.dataset)
    set_field(doc, "labels.evidence_source", source)
    set_field(doc, "cloud.provider", "aws")
    if not get_field(doc, "cloud.account.id"):
        set_field(doc, "cloud.account.id", ctx.account_hint)
    if not get_field(doc, "cloud.region"):
        set_field(doc, "cloud.region", ctx.region_hint)
    set_field(doc, "log.file.path", ctx.rel_path)
    set_field(doc, "log.offset", offset)
    if ctx.args.case:
        doc["case"] = ctx.args.case
    return doc


def build_parser(log, description):
    ap = argparse.ArgumentParser(
        description=description,
        epilog="Input formats:\n  " + "\n  ".join(log.describe),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="Log files or folders (searched recursively; .gz is fine)")
    ap.add_argument("--source", required=True,
                    help="Evidence source label used in the index name and labels.evidence_source,"
                         " e.g. the AWS account ID or an environment name (prod, 123456789012)")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None,
                    help=f"Override the target index; must end in -<source> (default: {log.prefix}-<source>)")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Parse everything and show sample documents; send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    ap.add_argument("--date-order", choices=("mdy", "dmy"), default="mdy",
                    help="Day/month order of spreadsheet-style dates (10/20/2026 1:05 PM) in CSV"
                         " files re-saved by Excel; ISO 8601 and epoch times are not affected")
    if log.add_arguments:
        log.add_arguments(ap)
    add_client_arguments(ap)
    return ap


def run(log, description, argv=None):
    ap = build_parser(log, description)
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    SETTINGS["date_order"] = args.date_order
    try:
        source = sanitize_source(args.source)
    except ValueError as exc:
        sys.exit(str(exc))
    index = resolve_index(log.prefix, source, args.index)
    if not log.index_template and re.fullmatch(rf"{re.escape(log.prefix)}-\d{{4}}\.\d{{2}}", index):
        sys.exit(f"'{index}' looks like one of SOF-ELK's own monthly indexes; choose another --source.")

    component, index_tpl, body = load_templates(log.prefix)
    exact, open_prefixes = template_fields(body["mappings"])

    files, skipped_files = [], []
    for f in find_files(args.paths):
        if log.detect(f, head_text(f)):
            files.append(f)
        else:
            skipped_files.append(f)
    if skipped_files:
        print(f"Skipped {len(skipped_files)} file(s) that are not {log.title} logs:")
        for f in skipped_files[:20]:
            print(f"  - {f}")
        if len(skipped_files) > 20:
            print(f"  ... and {len(skipped_files) - 20} more")
        print()
    if not files:
        sys.exit(f"No {log.title} log files found.")
    print(f"{len(files)} {log.title} file(s) -> index '{index}' (source '{source}')")

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
        es.install_templates(log, component, index_tpl)
        if log.index_template:
            print(f"Installed index template 'sofelk-toolkit-{log.prefix}' ({log.prefix}-*)")
        else:
            print(f"No index template installed for {log.prefix}-* (SOF-ELK's own template stays in charge"
                  f" of its {log.prefix}-YYYY.MM indexes); the index is created with the toolkit mapping")
        print(f"Index '{index}': {es.prepare_index(log, index, body)}")

    total = {"records": 0, "ok": 0, "errors": 0, "updated": 0}
    skipped, unmapped_seen, samples = {}, {}, []
    seen_keys = {}
    lines = []
    for f in files:
        rel = display_path(f, args.paths)
        ctx = Context(args, f, rel)
        records = 0
        try:
            with open_text(f) as fh:
                for offset, (key, doc) in enumerate(log.parse(fh, ctx)):
                    if key is None:
                        ctx.skip(doc)
                        continue
                    records += 1
                    finish_doc(log, doc, ctx, source, offset)
                    for name in unknown_fields(doc, exact, open_prefixes):
                        unmapped_seen[name] = unmapped_seen.get(name, 0) + 1
                    n = 0
                    if log.use_occurrence:
                        n = seen_keys.get(key, 0)
                        seen_keys[key] = n + 1
                    doc_id = hashlib.sha1(json.dumps([log.prefix, source, key, n],
                                                     ensure_ascii=False).encode()).hexdigest()
                    if args.dry_run:
                        if len(samples) < args.sample_docs:
                            samples.append(doc)
                        continue
                    lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                    lines.append(json.dumps(doc, ensure_ascii=False))
                    if len(lines) >= args.batch_size * 2:
                        es.send(lines, total)
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            print(f"  ! {rel}: cannot read ({exc}); file skipped", file=sys.stderr)
            ctx.skip("unreadable file")
        for reason, n in ctx.skipped.items():
            skipped[reason] = skipped.get(reason, 0) + n
        total["records"] += records
        print(f"  {rel}: {records} record(s)"
              + (f", {sum(ctx.skipped.values())} skipped" if ctx.skipped else ""))
    if es is not None:
        es.send(lines, total)

    if SETTINGS["slash_dates"]:
        print(f"\nnote: {SETTINGS['slash_dates']} spreadsheet-style date(s) read as"
              f" {'month/day' if args.date_order == 'mdy' else 'day/month'}/year, UTC"
              " (--date-order). Excel drops seconds and time zones when it re-saves a CSV;"
              " export again from the source if exact times matter.")
    if skipped:
        print("\nLines/records not loaded:")
        for reason, n in sorted(skipped.items()):
            print(f"  {reason}: {n}")
    if unmapped_seen:
        print(f"\nWARNING: fields not in index-{log.prefix}.json (Elasticsearch will not index them):")
        for name, n in sorted(unmapped_seen.items()):
            print(f"  {name}: {n} document(s)")

    if args.dry_run:
        print(f"\n{total['records']} record(s) parsed. Sample document(s):")
        for doc in samples:
            print("  " + json.dumps(doc, ensure_ascii=False)[:1500])
        print("\nDry run only - nothing sent.")
        return 0

    new = total["ok"] - total["updated"]
    print(f"\nDone: {total['records']} record(s) read -> {new} new documents, {total['updated']}"
          f" already in index (re-run), {total['errors']} errors.")
    in_index = es.source_count(index, source)
    if in_index is not None:
        verdict = "matches" if in_index == total["records"] else "DOES NOT MATCH"
        print(f"Index check: '{index}' holds {in_index} documents for source '{source}'"
              f" ({verdict} the {total['records']} records read).")
        if in_index > total["records"]:
            print("  More documents than records: this index probably also holds an earlier load of"
                  " other files for the same source. That is expected when loading in parts.")
    print(f"In Kibana, use a '{log.prefix}-*' data view (time field @timestamp).")
    return 1 if total["errors"] else 0
