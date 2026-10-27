#!/usr/bin/env python3
"""Load AWS Application Load Balancer (and Classic ELB) access logs into SOF-ELK as aws-alb-<source>.

Field names follow SOF-ELK's ELB parsing (configfiles/6100-httpd.conf grok and
8004-postprocess-httpd.conf): elb -> aws.elb.name, client:port -> source.ip/source.port,
target:port -> backend.ip/backend.port, elb_status_code -> http.response.status_code,
target_status_code -> aws.elb.backend.http.response.status_code, received_bytes ->
source.bytes, sent_bytes -> destination.bytes, the request line -> http.request.method,
url.scheme/domain/path/query, destination.port, http.version and url.original,
user_agent -> user_agent.original, ssl_cipher/ssl_protocol -> tls.cipher/tls.protocol,
actions_executed / target:port_list / target_status_code_list split into lists, and "-"
values left out. aws.elb.type (http, https, h2, grpcs, ws, wss) is added, plus the fields
AWS appended after SOF-ELK's grok was written (transformed_host, transformed_uri,
request_transform_status).

Inputs (plain or .gz, any file name): the native access log files AWS writes to S3
(AWSLogs/<account>/elasticloadbalancing/<region>/...), one request per line, for ALB and for
Classic Load Balancers. Network Load Balancer (TLS) logs and ALB connection logs are a
different format and are reported as skipped.

CSV (comma, tab, semicolon or pipe separated) is read too, for logs that were already converted:
  * Athena query results over the alb_access_logs / elb_logs tables (client_ip + client_port,
    request_verb + request_url + request_proto, lambda_error_reason, elb_name, ...);
  * exports that keep the native field names as columns (client:port, request, ...);
  * a column holding the raw log line (CloudWatch Logs Insights "@message", "_raw", ...).
Columns that match no log field are kept under aws.elb.unmapped.

Example:
  python3 AWS/alb2sofelk.py /cases/IR-42/elasticloadbalancing --source 123456789012 --dry-run
"""
import csv
import re
import sys
from urllib.parse import urlsplit

from sof_elk_aws_common import (RAW_COLUMNS, AwsLog, canon, csv_reader, iso, looks_like_csv_header,
                                run, set_field, snake, to_float, to_int, valid_ip)

ALB_FIELDS = [
    "type", "time", "elb", "client:port", "target:port", "request_processing_time",
    "target_processing_time", "response_processing_time", "elb_status_code",
    "target_status_code", "received_bytes", "sent_bytes", "request", "user_agent",
    "ssl_cipher", "ssl_protocol", "target_group_arn", "trace_id", "domain_name",
    "chosen_cert_arn", "matched_rule_priority", "request_creation_time", "actions_executed",
    "redirect_url", "error_reason", "target:port_list", "target_status_code_list",
    "classification", "classification_reason", "conn_trace_id", "transformed_host",
    "transformed_uri", "request_transform_status",
]
CLB_FIELDS = [
    "time", "elb", "client:port", "backend:port", "request_processing_time",
    "backend_processing_time", "response_processing_time", "elb_status_code",
    "backend_status_code", "received_bytes", "sent_bytes", "request", "user_agent",
    "ssl_cipher", "ssl_protocol",
]
ALB_TYPES = {"http", "https", "h2", "grpcs", "ws", "wss"}
TOKEN_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')
ISO_START_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
REQUEST_RE = re.compile(r"^([A-Za-z]+) (\S+) (?:HTTP/)?([\d.]+|-)$")
ARN_RE = re.compile(r"^arn:aws[a-z-]*:elasticloadbalancing:([a-z0-9-]+):(\d{12}):")

# field -> (target, conversion)
SIMPLE = {
    "elb": ("aws.elb.name", "keyword"),
    "request_processing_time": ("aws.elb.request_processing_time.sec", "float"),
    "target_processing_time": ("aws.elb.backend_processing_time.sec", "float"),
    "backend_processing_time": ("aws.elb.backend_processing_time.sec", "float"),
    "response_processing_time": ("aws.elb.response_processing_time.sec", "float"),
    "elb_status_code": ("http.response.status_code", "int"),
    "target_status_code": ("aws.elb.backend.http.response.status_code", "int"),
    "backend_status_code": ("aws.elb.backend.http.response.status_code", "int"),
    "received_bytes": ("source.bytes", "int"),
    "sent_bytes": ("destination.bytes", "int"),
    "user_agent": ("user_agent.original", "keyword"),
    "ssl_cipher": ("tls.cipher", "keyword"),
    "ssl_protocol": ("tls.protocol", "keyword"),
    "target_group_arn": ("aws.elb.target_group.arn", "keyword"),
    "trace_id": ("aws.elb.trace_id", "keyword"),
    "domain_name": ("aws.elb.domain_name", "keyword"),
    "chosen_cert_arn": ("aws.elb.chosen_cert_arn", "keyword"),
    "matched_rule_priority": ("aws.elb.matched_rule_priority", "int"),
    "request_creation_time": ("aws.elb.request_creation_time", "date"),
    "redirect_url": ("aws.elb.redirect_url", "keyword"),
    "error_reason": ("aws.elb.error.reason", "keyword"),
    "classification": ("aws.elb.classification", "keyword"),
    "classification_reason": ("aws.elb.classification_reason", "keyword"),
    "conn_trace_id": ("aws.elb.conn_trace_id", "keyword"),
    "transformed_host": ("aws.elb.transformed_host", "keyword"),
    "transformed_uri": ("aws.elb.transformed_uri", "keyword"),
    "request_transform_status": ("aws.elb.request_transform_status", "keyword"),
    "type": ("aws.elb.type", "keyword"),
}
LISTS = {"actions_executed": ("aws.elb.action_executed", ","),
         "target:port_list": ("aws.elb.target_port", " "),
         "target_status_code_list": ("aws.elb.target_status_code", " ")}

# CSV columns (compared lower case, letters and digits only) -> log field. Athena's split
# columns (client_ip/client_port, request_verb/url/proto) are joined back in csv_row().
CSV_FIELDS = {canon(f): f for f in ALB_FIELDS + CLB_FIELDS}
CSV_FIELDS.update({
    "requesttimestamp": "time", "timestamp": "time", "elbname": "elb",
    "clientresponsetime": "response_processing_time", "elbresponsecode": "elb_status_code",
    "backendresponsecode": "backend_status_code", "lambdaerrorreason": "error_reason",
    "targetportlist": "target:port_list", "useragent": "user_agent",
})
CSV_PARTS = {"clientip": ("client", "ip"), "requestip": ("client", "ip"),
             "clientport": ("client", "port"), "requestport": ("client", "port"),
             "targetip": ("target", "ip"), "backendip": ("target", "ip"),
             "targetport": ("target", "port"), "backendport": ("target", "port"),
             "requestverb": ("request", "verb"), "requesturl": ("request", "url"), "url": ("request", "url"),
             "requestproto": ("request", "proto"), "protocol": ("request", "proto")}
CSV_BACKEND_COLUMNS = {"backendip", "backendport", "backendprocessingtime", "backendstatuscode",
                       "backendresponsecode", "elbresponsecode", "clientresponsetime"}


def tokenize(line):
    return [q.replace('\\"', '"') if q is not None else bare
            for q, bare in ((m.group(1), m.group(2)) for m in TOKEN_RE.finditer(line))]


def ip_port(value):
    """"10.0.0.1:443" or "[2001:db8::1]:443" -> (ip, port) or (None, None)."""
    if not value or value == "-" or ":" not in value:
        return None, None
    host, _, port = value.rpartition(":")
    return valid_ip(host), to_int(port)


def request_fields(doc, request):
    """SOF-ELK request-line split: method, scheme, domain, port, path, query, version."""
    if request in ("- - - ", "- - -", "-", ""):
        return
    m = REQUEST_RE.match(request)
    if not m:
        set_field(doc, "sof-elk.rawrequest", request)
        return
    method, url, version = m.groups()
    set_field(doc, "http.request.method", method.upper())
    if version != "-":
        set_field(doc, "http.version", version)
    set_field(doc, "url.original", url)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        set_field(doc, "sof-elk.rawrequest", request)
        return
    set_field(doc, "url.scheme", parts.scheme or None)
    set_field(doc, "url.domain", parts.hostname)
    set_field(doc, "destination.port", port)
    set_field(doc, "url.path", parts.path or None)
    set_field(doc, "url.query", parts.query or None)
    last = (parts.path or "").rsplit("/", 1)[-1]
    if "." in last:
        set_field(doc, "url.extension", last.rsplit(".", 1)[1].lower()[:32] or None)


def build(fields, tokens, classic):
    doc, malformed = {}, []
    extra = tokens[len(fields):]
    for field, value in zip(fields, tokens):
        if value in ("-", ""):
            continue
        if field == "time":
            stamp = iso(value)
            if stamp:
                doc["@timestamp"] = stamp
            else:
                malformed.append(f"time={value}")
        elif field == "client:port":
            ip, port = ip_port(value)
            set_field(doc, "source.ip", ip)
            set_field(doc, "source.port", port)
            if ip is None:
                malformed.append(f"client:port={value}")
        elif field in ("target:port", "backend:port"):
            ip, port = ip_port(value)
            set_field(doc, "backend.ip", ip)
            set_field(doc, "backend.port", port)
            if ip is None:
                malformed.append(f"{field}={value}")
        elif field == "request":
            request_fields(doc, value)
        elif field in LISTS:
            target, sep = LISTS[field]
            parts = [p for p in value.split(sep) if p and p != "-"]
            set_field(doc, target, parts)
        elif field in SIMPLE:
            target, conv = SIMPLE[field]
            if conv == "int":
                out = to_int(value)
            elif conv == "float":
                out = to_float(value)
            elif conv == "date":
                out = iso(value)
            else:
                out = value
            if out is None:
                malformed.append(f"{field}={value}")
            else:
                set_field(doc, target, out)
    for i, value in enumerate(extra, start=len(fields)):
        if value not in ("-", ""):
            set_field(doc, f"aws.elb.unmapped.field_{i + 1}", value)
    m = ARN_RE.match(doc.get("aws", {}).get("elb", {}).get("target_group", {}).get("arn", ""))
    if m:
        set_field(doc, "cloud.region", m.group(1))
        set_field(doc, "cloud.account.id", m.group(2))
    doc["event"] = {"dataset": "aws.elb_classic" if classic else "aws.alb", "kind": "event",
                    "category": "web"}
    if malformed:
        set_field(doc, "aws.elb.malformed", malformed)
    return doc


def classify(tokens):
    """'alb', 'classic', or a skip reason."""
    if len(tokens) >= 12 and tokens[0] in ALB_TYPES and ISO_START_RE.match(tokens[1]):
        return "alb"
    if len(tokens) >= 12 and ISO_START_RE.match(tokens[0]) and ":" in tokens[2]:
        return "classic"
    if tokens and tokens[0] == "tls":
        return "Network Load Balancer (TLS listener) log line - not supported"
    if tokens and ISO_START_RE.match(tokens[0]):
        return "ALB connection log line - not supported"
    return "not an ALB/ELB access log line"


def csv_row(row, columns):
    """One CSV row -> ("line", raw log line) or ("fields", fields, tokens, classic, unmapped)."""
    values = {c: (row.get(c) or "").strip() for c in columns if c is not None}
    for col, value in values.items():
        if canon(col) in RAW_COLUMNS and value:
            return ("line", value)
    fields, parts, unmapped = {}, {}, {}
    for col, value in values.items():
        if value.lower() in ("", "null", "none"):
            continue
        key = canon(col)
        if key in CSV_PARTS and not (key.endswith("port") and ":" in value):
            parts[CSV_PARTS[key]] = value
        elif key in CSV_FIELDS:
            fields[CSV_FIELDS[key]] = value
        elif not col.lstrip().startswith("@"):
            unmapped[col] = value
    classic = "type" not in fields and bool({canon(c) for c in columns if c} & CSV_BACKEND_COLUMNS)
    for side, name in (("client", "client:port"), ("target", "backend:port" if classic else "target:port")):
        if (side, "ip") in parts and name not in fields:
            ip = parts[(side, "ip")]
            fields[name] = f"[{ip}]:{parts.get((side, 'port'), '')}" if ":" in ip else f"{ip}:{parts.get((side, 'port'), '')}"
    if classic and "target:port" in fields:
        fields["backend:port"] = fields.pop("target:port")
    if "request" not in fields and ("request", "url") in parts:
        fields["request"] = " ".join((parts.get(("request", "verb"), "-"), parts[("request", "url")],
                                      parts.get(("request", "proto"), "-")))
    if classic:
        fields = {("backend_processing_time" if f == "target_processing_time" else
                   "backend_status_code" if f == "target_status_code" else f): v for f, v in fields.items()}
    return ("fields", list(fields), list(fields.values()), classic, unmapped)


def parse_csv(head, fh):
    reader = csv_reader(fh, head)
    columns = reader.fieldnames or []
    for row in reader:
        out = csv_row(row, columns)
        if out[0] == "line":
            yield from parse_lines([out[1]])
            continue
        _, fields, tokens, classic, unmapped = out
        if not fields:
            continue
        doc = build(fields, tokens, classic)
        for col, value in unmapped.items():
            set_field(doc, "aws.elb.unmapped." + snake(col), value)
        if "@timestamp" not in doc:
            yield None, "CSV row without a usable time column"
            continue
        yield "\t".join(tokens), doc


def is_csv_header(line):
    if not looks_like_csv_header(line, []) or classify(tokenize(line)) in ("alb", "classic"):
        return False
    cols = {canon(c) for c in next(csv.reader([line], delimiter=max(",\t;|", key=line.count)))}
    if cols & RAW_COLUMNS:
        return True
    named = sum(1 for c in cols if c in CSV_FIELDS or c in CSV_PARTS)
    return named >= 4 and bool(cols & {"elb", "elbname", "elbstatuscode", "elbresponsecode"})


def parse(fh, ctx):
    head = fh.read(1 << 16)
    first = head.lstrip("\ufeff").split("\n", 1)[0].rstrip("\r")
    if is_csv_header(first):
        yield from parse_csv(head.lstrip("\ufeff"), fh)
        return
    yield from parse_lines(_lines(head, fh))


def _lines(head, fh):
    if head and not head.endswith("\n"):
        head += fh.readline()
    yield from head.splitlines()
    yield from fh


def parse_lines(lines):
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        tokens = tokenize(line)
        kind = classify(tokens)
        if kind == "alb":
            yield line, build(ALB_FIELDS, tokens, classic=False)
        elif kind == "classic":
            yield line, build(CLB_FIELDS, tokens, classic=True)
        else:
            yield None, kind


def detect(path, head):
    p = path.as_posix().lower()
    if "elasticloadbalancing" in p and "/connectionlogs" not in p:
        return True
    first = head.lstrip("\ufeff \r\n").split("\n", 1)[0].rstrip("\r")
    if classify(tokenize(first)) in ("alb", "classic"):
        return True
    if is_csv_header(first):
        cols = {canon(c) for c in next(csv.reader([first], delimiter=max(",\t;|", key=first.count)))}
        if not cols & RAW_COLUMNS:
            return True
        return any(classify(tokenize(line)) in ("alb", "classic")
                   for row in csv.reader(head.splitlines()[1:6], delimiter=max(",\t;|", key=first.count))
                   for line in row)
    return False


LOG = AwsLog(
    prefix="aws-alb", namespace="aws.elb", title="AWS ALB/ELB access", dataset="aws.alb",
    detect=detect, parse=parse,
    describe=[
        "ALB access logs as delivered to S3 (.log / .log.gz), one request per line",
        "Classic Load Balancer access logs (same delivery)",
        "CSV conversions: Athena alb_access_logs / elb_logs results, native-name columns, raw-line column",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load AWS ALB / Classic ELB access logs into SOF-ELK (index aws-alb-<source>)"))
