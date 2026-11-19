#!/usr/bin/env python3
"""Load Amazon CloudFront standard access logs into SOF-ELK as httpdlog-<source>.

CloudFront writes one gzip file per distribution and hour to S3
(<prefix>/<DistributionID>.YYYY-MM-DD-HH.<unique>.gz). Each file is W3C extended format:
two header lines, then one tab-separated line per viewer request:

    #Version: 1.0
    #Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status ...
    2026-10-20	01:02:03	SIN52-P1	2390	203.0.113.7	GET	d111111abcdef8.cloudfront.net	/admin	404 ...

Columns are taken from the #Fields line, not from a fixed position, so older files (24 or 26
fields), today's 33 fields and fields AWS adds later are all read. A file without its header
(cut or concatenated) is read in the documented field order. A #Fields line in the middle of a
file (several hourly files concatenated) switches to that line's columns.

The index family is SOF-ELK's web access log family (httpdlog-*), like ALB/ELB logs, so one
ES|QL query (FROM httpdlog-*) hunts across CloudFront, ALB, IIS, Apache and NGINX logs.
event.dataset is aws.cloudfront. SOF-ELK has no CloudFront parser, so the field names follow
its httpd parsing (configfiles/6100-httpd.conf IIS/W3C grok, 8004-postprocess-httpd.conf), which
is what the ALB importer uses too:

    date + time (UTC)     -> @timestamp
    c-ip, c-port          -> source.ip, source.port
    cs-method             -> http.request.method
    x-host-header         -> url.domain (the name the viewer asked for; cs(Host) if absent)
    cs-uri-stem           -> url.path (+ url.extension)
    cs-uri-query          -> url.query
    cs-protocol           -> url.scheme;  url.original is rebuilt as scheme://domain/path?query
    sc-status             -> http.response.status_code (000 = viewer closed the connection)
    cs(Referer)           -> http.request.referrer (URL-decoded)
    cs(User-Agent)        -> user_agent.original (URL-decoded, so it reads like other web logs)
    cs(Cookie)            -> http.request.cookie
    sc-bytes / cs-bytes   -> destination.bytes / source.bytes (response / request, as IIS and ALB)
    time-taken            -> event.duration (nanoseconds, as SOF-ELK) and aws.cloudfront.time_taken.sec
    x-forwarded-for       -> xff.ip (each valid IP) and aws.cloudfront.x_forwarded_for (as logged)
    ssl-protocol / -cipher -> tls.protocol / tls.cipher
    cs-protocol-version   -> http.version ("HTTP/2.0" -> "2.0", as ALB)
    sc-content-type       -> http.response.mime_type
    sc-content-len        -> http.response.body.bytes
    everything CloudFront-specific -> aws.cloudfront.* (edge_location, edge_result_type,
    edge_response_result_type, edge_detailed_result_type, request_id, distribution_domain,
    fle_status, fle_encrypted_fields, time_to_first_byte.sec, range_start, range_end)

The distribution ID comes from the file name (aws.cloudfront.distribution_id). Fields not in the
list above (AWS adds new ones from time to time) are kept under aws.cloudfront.unmapped.<name>.
"-" values are left out.

CSV (comma, tab, semicolon or pipe separated) is read too, for logs that were already converted:
  * Athena query results over the cloudfront_standard_logs table (location, request_ip,
    uri, status, user_agent, query_string, result_type, request_id, host_header, ...);
  * exports that keep the W3C field names as columns (x-edge-location, cs-uri-stem, ...);
  * a column holding the raw log line (CloudWatch Logs Insights "@message", "_raw", ...),
    read in the documented field order.

Not read: CloudFront real-time logs (Kinesis) and standard logging v2 output in JSON or Parquet.

Example:
  python3 AWS/cloudfrontaccess2sofelk.py /cases/IR-42/cloudfront-logs --source 123456789012 --dry-run
"""
import re
import sys
from urllib.parse import unquote

from sof_elk_aws_common import (RAW_COLUMNS, AwsLog, any_time, canon, csv_reader, first_line, iso,
                                looks_like_csv_header, run, set_field, snake, split_row, to_float,
                                to_int, valid_ip)

# The documented field order of standard (legacy) access logs. Fields were only ever appended,
# so a headerless line of any age lines up with the start of this list.
FIELDS = [
    "date", "time", "x-edge-location", "sc-bytes", "c-ip", "cs-method", "cs(Host)", "cs-uri-stem",
    "sc-status", "cs(Referer)", "cs(User-Agent)", "cs-uri-query", "cs(Cookie)", "x-edge-result-type",
    "x-edge-request-id", "x-host-header", "cs-protocol", "cs-bytes", "time-taken", "x-forwarded-for",
    "ssl-protocol", "ssl-cipher", "x-edge-response-result-type", "cs-protocol-version", "fle-status",
    "fle-encrypted-fields", "c-port", "time-to-first-byte", "x-edge-detailed-result-type",
    "sc-content-type", "sc-content-len", "sc-range-start", "sc-range-end",
]
CF = "aws.cloudfront."

# field -> (target, conversion). Fields handled in build() (date, time, c-ip, the URL parts,
# user agent, referrer, x-forwarded-for, time-taken, protocol version) are not listed here.
SIMPLE = {
    "x-edge-location": (CF + "edge_location", "keyword"),
    "sc-bytes": ("destination.bytes", "int"),
    "cs-method": ("http.request.method", "upper"),
    "cs(Host)": (CF + "distribution_domain", "keyword"),
    "sc-status": ("http.response.status_code", "int"),
    "cs(Cookie)": ("http.request.cookie", "keyword"),
    "x-edge-result-type": (CF + "edge_result_type", "keyword"),
    "x-edge-request-id": (CF + "request_id", "keyword"),
    "cs-bytes": ("source.bytes", "int"),
    "ssl-protocol": ("tls.protocol", "keyword"),
    "ssl-cipher": ("tls.cipher", "keyword"),
    "x-edge-response-result-type": (CF + "edge_response_result_type", "keyword"),
    "fle-status": (CF + "fle_status", "keyword"),
    "fle-encrypted-fields": (CF + "fle_encrypted_fields", "int"),
    "c-port": ("source.port", "int"),
    "time-to-first-byte": (CF + "time_to_first_byte.sec", "float"),
    "x-edge-detailed-result-type": (CF + "edge_detailed_result_type", "keyword"),
    "sc-content-type": ("http.response.mime_type", "keyword"),
    "sc-content-len": ("http.response.body.bytes", "int"),
    "sc-range-start": (CF + "range_start", "int"),
    "sc-range-end": (CF + "range_end", "int"),
}
HANDLED = {"date", "time", "c-ip", "cs-uri-stem", "cs-uri-query", "x-host-header", "cs-protocol",
           "cs(Referer)", "cs(User-Agent)", "time-taken", "x-forwarded-for", "cs-protocol-version",
           "timestamp", "timestamp(ms)", "DistributionId"}
KNOWN = set(SIMPLE) | HANDLED

# CSV columns (canon: lower case, letters and digits only) -> log field. The W3C names
# themselves, plus the column names of the Athena cloudfront_standard_logs table.
CSV_FIELDS = {canon(f): f for f in FIELDS}
CSV_FIELDS.update({
    "location": "x-edge-location", "bytes": "sc-bytes", "requestip": "c-ip", "clientip": "c-ip",
    "method": "cs-method", "host": "cs(Host)", "uri": "cs-uri-stem", "status": "sc-status",
    "referrer": "cs(Referer)", "referer": "cs(Referer)", "useragent": "cs(User-Agent)",
    "querystring": "cs-uri-query", "cookie": "cs(Cookie)", "resulttype": "x-edge-result-type",
    "requestid": "x-edge-request-id", "hostheader": "x-host-header", "requestprotocol": "cs-protocol",
    "requestbytes": "cs-bytes", "responseresulttype": "x-edge-response-result-type",
    "httpversion": "cs-protocol-version", "clientport": "c-port",
    "timestamp": "timestamp", "timestampms": "timestamp(ms)", "distributionid": "DistributionId",
})
# Athena partition columns: not part of the log.
CSV_IGNORED = {"year", "month", "day", "hour", "dt", "partitionday", "distribution"}
# Columns that only a CloudFront log has; a CSV header needs two of them.
CSV_SIGNATURE = {"xedgelocation", "xedgerequestid", "xedgeresulttype", "xhostheader", "csuristem",
                 "location", "requestid", "resulttype", "hostheader", "uri", "querystring"}

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
EDGE_RE = re.compile(r"^[A-Z]{3}\d+(?:-[A-Za-z0-9]+)*$")
# <DistributionID>.YYYY-MM-DD-HH.<unique>[.gz]; S3 may add its own prefix before the ID.
FILE_RE = re.compile(r"(?:^|[/_.-])(E[A-Z0-9]{5,20})\.\d{4}-\d{2}-\d{2}-\d{2}\.[0-9A-Za-z]+(?:\.gz)?$")
XFF_SPLIT_RE = re.compile(r"[,\s]+")


def _decode(value):
    """CloudFront URL-encodes spaces and other special characters in some fields; decode once."""
    return unquote(value) if "%" in value else value


def build(pairs, distribution_id=None):
    """(field, value) pairs from one log line or CSV row -> document."""
    doc, malformed = {}, []
    values = {}
    for field, value in pairs:
        if value is None:
            continue
        value = value.strip()
        if value in ("-", ""):
            continue
        values[field] = value

    date, time = values.get("date"), values.get("time")
    stamp = None
    if date and time:
        stamp = iso(f"{date}T{time}Z") or iso(f"{date} {time}")
    elif date:   # spreadsheet exports sometimes merge both into the date column
        stamp = iso(date)
    if stamp is None:
        for name, unit in (("timestamp(ms)", "ms"), ("timestamp", "s")):
            if values.get(name):
                stamp = any_time(values[name], unit)
                if stamp:
                    break
    if stamp:
        doc["@timestamp"] = stamp
    elif date or time:
        malformed.append(f"date time={date or ''} {time or ''}".strip())

    if "c-ip" in values:
        ip = valid_ip(values["c-ip"])
        if ip:
            set_field(doc, "source.ip", ip)
        else:
            malformed.append(f"c-ip={values['c-ip']}")

    scheme = values.get("cs-protocol", "").lower() or None
    domain = values.get("x-host-header") or values.get("cs(Host)")
    path, query = values.get("cs-uri-stem"), values.get("cs-uri-query")
    set_field(doc, "url.scheme", scheme)
    set_field(doc, "url.domain", domain)
    set_field(doc, "url.path", path)
    set_field(doc, "url.query", query)
    if path:
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            set_field(doc, "url.extension", last.rsplit(".", 1)[1].lower()[:32] or None)
        if domain:
            set_field(doc, "url.original", f"{scheme or 'https'}://{domain}{path}" + (f"?{query}" if query else ""))

    if "cs(Referer)" in values:
        set_field(doc, "http.request.referrer", _decode(values["cs(Referer)"]))
    if "cs(User-Agent)" in values:
        set_field(doc, "user_agent.original", _decode(values["cs(User-Agent)"]))
    if "cs-protocol-version" in values:
        v = values["cs-protocol-version"]
        set_field(doc, "http.version", v[5:] if v.upper().startswith("HTTP/") else v)
    if "time-taken" in values:
        sec = to_float(values["time-taken"])
        if sec is None:
            malformed.append(f"time-taken={values['time-taken']}")
        else:
            set_field(doc, CF + "time_taken.sec", sec)
            set_field(doc, "event.duration", int(round(sec * 1_000_000_000)))
    if "x-forwarded-for" in values:
        raw = _decode(values["x-forwarded-for"])
        set_field(doc, CF + "x_forwarded_for", raw)
        set_field(doc, "xff.ip", [ip for ip in (valid_ip(p) for p in XFF_SPLIT_RE.split(raw)) if ip])

    for field, value in values.items():
        if field in SIMPLE:
            target, conv = SIMPLE[field]
            if conv == "int":
                out = to_int(value)
            elif conv == "float":
                out = to_float(value)
            elif conv == "upper":
                out = value.upper()
            else:
                out = value
            if out is None:
                malformed.append(f"{field}={value}")
            else:
                set_field(doc, target, out)
        elif field not in KNOWN:
            set_field(doc, CF + "unmapped." + snake(field), value)

    set_field(doc, CF + "distribution_id", values.get("DistributionId") or distribution_id)
    doc["event"] = {**doc.get("event", {}), "dataset": "aws.cloudfront", "kind": "event", "category": "web"}
    if malformed:
        set_field(doc, CF + "malformed", malformed)
    return doc


def distribution_from_path(path):
    m = FILE_RE.search(str(path).replace("\\", "/"))
    return m.group(1) if m else None


def fields_line(line):
    """Column names from a '#Fields:' line, or None."""
    if not line.lower().startswith("#fields:"):
        return None
    return line[len("#fields:"):].split()


def is_log_line(cells):
    """True for a tab-separated CloudFront access log line (date, time, edge location, ...)."""
    return (len(cells) >= 12 and bool(DATE_RE.match(cells[0])) and bool(TIME_RE.match(cells[1]))
            and bool(EDGE_RE.match(cells[2])))


def parse_lines(lines, distribution_id, fields=None):
    fields = list(fields or FIELDS)
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if line.startswith("#"):
            names = fields_line(line)
            if names:
                fields = names
            continue
        cells = line.split("\t")
        if len(cells) < 2:
            yield None, "not a CloudFront access log line"
            continue
        pairs = list(zip(fields, cells))
        for i, value in enumerate(cells[len(fields):], start=len(fields)):
            pairs.append((f"field_{i + 1}", value))
        doc = build(pairs, distribution_id)
        if "@timestamp" not in doc:
            yield None, "CloudFront line without a usable date/time"
            continue
        yield doc.get("aws", {}).get("cloudfront", {}).get("request_id") or line, doc


def csv_columns(line):
    line = first_line(line)
    if not looks_like_csv_header(line, []):
        return None
    return split_row(line, max(",\t;|", key=line.count))


def is_csv_header(line):
    if line.lstrip().startswith("#") or is_log_line(first_line(line).split("\t")):
        return False
    cells = csv_columns(line)
    if not cells:
        return False
    cols = {canon(c) for c in cells}
    if cols & RAW_COLUMNS and not (cols & CSV_SIGNATURE):
        return False   # a raw-line column alone: only claimed after a look at the rows (detect)
    named = sum(1 for c in cols if c in CSV_FIELDS)
    return named >= 5 and len(cols & CSV_SIGNATURE) >= 2


def parse_csv(head, fh, distribution_id):
    reader = csv_reader(fh, head)
    columns = [c for c in (reader.fieldnames or []) if c is not None]
    raw_col = next((c for c in columns if canon(c) in RAW_COLUMNS), None)
    for row in reader:
        if raw_col and (row.get(raw_col) or "").strip():
            yield from parse_lines([row[raw_col].strip()], distribution_id)
            continue
        pairs = []
        for col in columns:
            value = row.get(col)
            if not isinstance(value, str) or value.strip().lower() in ("", "null", "none", "-"):
                continue
            key = canon(col)
            if key in CSV_IGNORED or col.lstrip().startswith("@"):
                continue
            pairs.append((CSV_FIELDS.get(key, col.strip()), value))
        if not pairs:
            continue
        doc = build(pairs, distribution_id)
        if "@timestamp" not in doc:
            yield None, "CSV row without a usable date/time"
            continue
        yield doc.get("aws", {}).get("cloudfront", {}).get("request_id") or "\t".join(v for _, v in pairs), doc


def parse(fh, ctx):
    distribution_id = distribution_from_path(ctx.path) or distribution_from_path(ctx.rel_path)
    head = fh.read(1 << 16)
    first = first_line(head.lstrip("﻿ \r\n"))
    if is_csv_header(first) or _raw_csv(head):
        yield from parse_csv(head.lstrip("﻿ \r\n"), fh, distribution_id)
        return
    yield from parse_lines(_lines(head, fh), distribution_id)


def _lines(head, fh):
    if head and not head.endswith("\n"):
        head += fh.readline()
    yield from head.splitlines()
    yield from fh


def _raw_csv(head):
    """A CSV whose only useful column holds raw CloudFront lines (Logs Insights @message)."""
    text = head.lstrip("﻿ \r\n")
    cells = csv_columns(text)
    if not cells or not ({canon(c) for c in cells} & RAW_COLUMNS):
        return False
    import csv
    try:
        rows = list(csv.reader(text.splitlines()[1:6], delimiter=max(",\t;|", key=first_line(text).count)))
    except csv.Error:
        return False
    return any(is_log_line(cell.split("\t")) for row in rows for cell in row)


def detect(path, head):
    text = head.lstrip("﻿ \r\n")
    lines = text.splitlines()[:10]
    for line in lines:
        names = fields_line(line)
        if names is not None:
            return any(n.startswith("x-edge-") for n in names)
        if line.startswith("#"):
            continue
        break
    data = next((ln for ln in lines if ln.strip() and not ln.startswith("#")), "")
    if is_log_line(data.split("\t")):
        return True
    return is_csv_header(first_line(text)) or _raw_csv(text)


LOG = AwsLog(
    prefix="httpdlog", namespace="aws.cloudfront", title="Amazon CloudFront access", dataset="aws.cloudfront",
    detect=detect, parse=parse, index_template=False,
    describe=[
        "CloudFront standard access logs as delivered to S3 (<DistributionID>.YYYY-MM-DD-HH.<id>.gz),"
        " W3C #Fields header + one tab-separated request per line",
        "CSV conversions: Athena cloudfront_standard_logs results, W3C-name columns, raw-line column",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load Amazon CloudFront standard access logs into SOF-ELK (index httpdlog-<source>)"))
