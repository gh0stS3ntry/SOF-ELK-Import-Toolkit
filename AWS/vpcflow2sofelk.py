#!/usr/bin/env python3
"""Load AWS VPC Flow Logs into SOF-ELK as aws-vpcflow-<source>.

Field names follow SOF-ELK's VPC Flow parsing in configfiles/2050-netflow.conf: srcaddr ->
source.ip, bytes -> source.bytes, protocol -> network.iana_number, start/end ->
netflow.flow_start (also @timestamp) / netflow.flow_end, action -> aws.vpcflow.action,
pkt-srcaddr -> original_source.ip, az-id -> cloud.availability_zone, tcp-flags ->
netflow.tcp_control_bits + network.tcp_flags, and so on. Like SOF-ELK, NODATA and SKIPDATA
records are not loaded, destination.bytes/packets are 0 (a flow record counts one direction)
and netflow.flow_duration is end - start in seconds. network.transport and
network.community_id are added so flows can be joined with other network data.

Every record format version (2 to 8) and custom formats are read by field name:
  * S3 delivery in text format (.log.gz): the first line is the header naming the fields;
  * CloudWatch Logs exports (no header; optionally timestamp-prefixed lines): the default
    version 2 format is assumed unless --fields names the custom format;
  * `aws logs filter-log-events` JSON or CloudWatch subscription payloads ({"logEvents": [...]});
  * CSV (comma, tab, semicolon or pipe separated) when the logs were already converted: Athena
    query results (account_id, log_status, ...), CloudWatch Logs Insights exports (srcAddr,
    dstPort, logStatus, ... or a single @message column holding the raw line), spreadsheet
    exports with descriptive headers (Source address, Start time, ...). start/end may be epoch
    seconds or ISO / spreadsheet date text; columns starting with "@" (@timestamp, @ptr) are ignored.
Parquet delivery is not supported (it needs a non-standard library); choose text format or
convert with Athena first.

Example:
  python3 AWS/vpcflow2sofelk.py /cases/IR-42/vpcflowlogs --source 123456789012 --dry-run
"""
import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import re
import struct
import sys

from sof_elk_aws_common import (RAW_COLUMNS, AwsLog, canon, csv_reader, epoch_to_iso, iso,
                                looks_like_csv_header, run, set_field, snake, to_int, valid_ip)

DEFAULT_FIELDS = ("version account-id interface-id srcaddr dstaddr srcport dstport protocol "
                  "packets bytes start end action log-status").split()
KNOWN_FIELDS = set(DEFAULT_FIELDS) | set(
    "vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr region az-id "
    "sublocation-type sublocation-id pkt-src-aws-service pkt-dst-aws-service flow-direction "
    "traffic-path reject-reason ecs-cluster-arn ecs-cluster-name ecs-container-instance-arn "
    "ecs-container-instance-id ecs-container-id ecs-second-container-id ecs-service-name "
    "ecs-task-definition-arn ecs-task-arn ecs-task-id".split())
TRANSPORT = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp",
             51: "ah", 58: "ipv6-icmp", 89: "ospf", 103: "pim", 132: "sctp"}
# field -> (target, conversion); conversions: keyword, int, ip
SIMPLE = {
    "version": ("aws.vpcflow.version", "int"),
    "interface-id": ("aws.vpcflow.interface_id", "keyword"),
    "srcaddr": ("source.ip", "ip"),
    "dstaddr": ("destination.ip", "ip"),
    "srcport": ("source.port", "int"),
    "dstport": ("destination.port", "int"),
    "packets": ("source.packets", "int"),
    "bytes": ("source.bytes", "int"),
    "action": ("aws.vpcflow.action", "keyword"),
    "log-status": ("aws.vpcflow.log_status", "keyword"),
    "vpc-id": ("aws.vpcflow.vpc_id", "keyword"),
    "subnet-id": ("aws.vpcflow.subnet_id", "keyword"),
    "instance-id": ("aws.vpcflow.instance_id", "keyword"),
    "type": ("aws.vpcflow.type", "keyword"),
    "pkt-srcaddr": ("original_source.ip", "ip"),
    "pkt-dstaddr": ("original_destination.ip", "ip"),
    "region": ("cloud.region", "keyword"),
    "az-id": ("cloud.availability_zone", "keyword"),
    "sublocation-type": ("aws.vpcflow.sublocation.type", "keyword"),
    "sublocation-id": ("aws.vpcflow.sublocation.id", "keyword"),
    "pkt-src-aws-service": ("aws.vpcflow.source.service", "keyword"),
    "pkt-dst-aws-service": ("aws.vpcflow.destination_service", "keyword"),
    "flow-direction": ("network.direction", "keyword"),
    "traffic-path": ("aws.vpcflow.traffic_path", "keyword"),
    "reject-reason": ("aws.vpcflow.reason", "keyword"),
}
# CSV column (compared lower case, letters and digits only) -> field name. Covers the native
# names written any way (account_id, accountId, log-status) plus descriptive export headers.
COLUMN_FIELDS = {canon(f): f for f in KNOWN_FIELDS}
COLUMN_FIELDS.update({
    "sourceaddress": "srcaddr", "sourceip": "srcaddr", "srcip": "srcaddr",
    "destinationaddress": "dstaddr", "destinationip": "dstaddr", "dstip": "dstaddr", "destaddr": "dstaddr",
    "sourceport": "srcport", "destinationport": "dstport", "destport": "dstport",
    "protocolnumber": "protocol", "bytestransferred": "bytes", "packetcount": "packets",
    "starttime": "start", "endtime": "end", "logstatus": "log-status", "status": "log-status",
    "eni": "interface-id", "eniid": "interface-id", "networkinterfaceid": "interface-id",
    "accountid": "account-id", "awsaccountid": "account-id", "tcpflags": "tcp-flags",
    "flowdirection": "flow-direction", "direction": "flow-direction", "azid": "az-id",
    "rejectreason": "reject-reason", "trafficpath": "traffic-path",
})
TS_PREFIX_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s+")
HEADER_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def tcp_flags(value):
    """SOF-ELK tcp_flags_expand.rb: integer -> (names, hex)."""
    names = [n for bit, n in ((0x80, "cwr"), (0x40, "ece"), (0x20, "urg"), (0x10, "ack"),
                              (0x08, "psh"), (0x04, "rst"), (0x02, "syn"), (0x01, "fin")) if value & bit]
    return names, "0x" + format(value, "02X")


def community_id(src, dst, proto, sport, dport, seed=0):
    """Community ID v1 (https://github.com/corelight/community-id-spec) for a flow tuple."""
    try:
        s, d = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    except ValueError:
        return None
    if len(s) != len(d):
        return None
    ports = proto in (6, 17, 132) and sport is not None and dport is not None
    sp, dp = (sport, dport) if ports else (0, 0)
    if (s, sp) > (d, dp):
        s, d, sp, dp = d, s, dp, sp
    data = struct.pack("!H", seed) + s + d + struct.pack("!BB", proto, 0)
    if ports:
        data += struct.pack("!HH", sp, dp)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def build(fields, values):
    """One record (field names + values) -> document, or (None, skip reason)."""
    rec = {f: v for f, v in zip(fields, values) if v not in ("-", "")}
    if rec.get("log-status") in ("NODATA", "SKIPDATA"):
        return None, f"{rec['log-status']} record (no traffic in the window, or records skipped)"
    doc, malformed = {}, []
    for field, value in rec.items():
        if field in SIMPLE:
            target, conv = SIMPLE[field]
            if conv == "int":
                out = to_int(value)
            elif conv == "ip":
                out = valid_ip(value)
            else:
                out = value
            if out is None:
                malformed.append(f"{field}={value}")
            else:
                set_field(doc, target, out)
        elif field == "account-id":
            if value != "unknown":  # SOF-ELK drops "unknown"
                set_field(doc, "aws.vpcflow.account_id", value)
                set_field(doc, "cloud.account.id", value)
        elif field == "protocol":
            proto = to_int(value)
            if proto is None:
                malformed.append(f"protocol={value}")
            else:
                set_field(doc, "network.iana_number", proto)
                set_field(doc, "network.transport", TRANSPORT.get(proto, str(proto)))
        elif field in ("start", "end"):
            stamp = epoch_to_iso(value) if re.fullmatch(r"\d+(?:\.\d+)?", value) else iso(value)
            if stamp is None:
                malformed.append(f"{field}={value}")
            else:
                set_field(doc, "netflow.flow_start" if field == "start" else "netflow.flow_end", stamp)
        elif field == "tcp-flags":
            pass  # below, once the protocol is known
        elif field.startswith("ecs-"):
            set_field(doc, "aws.vpcflow.ecs." + snake(field[4:]), value)
        else:
            set_field(doc, "aws.vpcflow.unmapped." + snake(field), value)

    proto = doc.get("network", {}).get("iana_number")
    if "tcp-flags" in rec and proto == 6:  # SOF-ELK keeps TCP flags for TCP only
        bits = to_int(rec["tcp-flags"])
        if bits is None:
            malformed.append(f"tcp-flags={rec['tcp-flags']}")
        else:
            names, hexval = tcp_flags(bits)
            set_field(doc, "netflow.tcp_control_bits", bits)
            set_field(doc, "network.tcp_flags", names)
            set_field(doc, "network.tcp_flags_hex", hexval)

    start, end = (doc.get("netflow", {}).get(k) for k in ("flow_start", "flow_end"))
    if start and end:
        delta = dt.datetime.fromisoformat(end.replace("Z", "+00:00")) - \
            dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
        doc["netflow"]["flow_duration"] = delta.total_seconds()
    doc.setdefault("netflow", {})["delta_flow_count"] = 1
    if doc.get("netflow", {}).get("flow_start"):
        doc["@timestamp"] = doc["netflow"]["flow_start"]
    elif doc.get("netflow", {}).get("flow_end"):
        doc["@timestamp"] = doc["netflow"]["flow_end"]
    for side in ("source", "destination"):
        doc.setdefault(side, {})
    doc["destination"].setdefault("bytes", 0)
    doc["destination"].setdefault("packets", 0)
    src, dst = doc["source"].get("ip"), doc["destination"].get("ip")
    if src and dst and proto is not None:
        set_field(doc, "network.community_id", community_id(
            src, dst, proto, doc["source"].get("port"), doc["destination"].get("port")))
    doc["event"] = {"dataset": "aws.vpcflow", "kind": "event", "category": "network"}
    set_field(doc, "event.action", rec.get("action", "").lower() or None)
    if rec.get("action") in ("ACCEPT", "REJECT"):
        doc["event"]["outcome"] = "success" if rec["action"] == "ACCEPT" else "failure"
    if malformed:
        set_field(doc, "aws.vpcflow.malformed", malformed)
    return doc, None


def header_fields(line):
    """Field list if line is a VPC Flow header row (space or comma separated), else None."""
    tokens = next(csv.reader([line])) if "," in line else line.split()
    names = [t.strip().strip('"').lower().replace("_", "-") for t in tokens]
    if len(names) >= 3 and all(HEADER_TOKEN_RE.match(n) for n in names) \
            and sum(n in KNOWN_FIELDS for n in names) >= max(3, len(names) // 2):
        return names, "," in line
    return None


def csv_columns(line):
    """Field names for a delimited CSV header (not the space-separated S3 header), else None.

    Returns [(column, field or None)], or "raw" when a column holds the whole record line."""
    if not looks_like_csv_header(line, []):  # needs a , tab ; or | (the S3 header is space separated)
        return None
    reader = csv_reader(iter([line]))
    cols = reader.fieldnames or []
    mapped = [(c, COLUMN_FIELDS.get(canon(c))) for c in cols]
    if sum(1 for _, f in mapped if f) >= 3:
        return mapped
    if any(canon(c) in RAW_COLUMNS for c in cols):
        return "raw"
    return None


def messages(fh):
    """Yield raw record lines (str) or CSV rows ([(field, value)]) from a text, CSV or JSON file."""
    head = fh.read(1 << 16)
    first = head.lstrip("\ufeff\r\n").split("\n", 1)[0].rstrip("\r")
    columns = csv_columns(first) if not first.lstrip().startswith("{") else None
    if columns:
        reader = csv_reader(fh, head.lstrip("\ufeff\r\n"))
        raw = next((c for c in reader.fieldnames if canon(c) in RAW_COLUMNS), None)
        for row in reader:
            if columns == "raw":
                yield (row.get(raw) or "").strip()
                continue
            yield [(field or col, (row.get(col) or "").strip()) for col, field in columns
                   if col is not None and not col.lstrip().startswith("@")]
        return
    if head.lstrip().startswith("{"):
        text = head + fh.read()
        decoder, pos, objs = json.JSONDecoder(), 0, []
        text = text.strip()
        while pos < len(text):  # one JSON document, or several concatenated (Firehose)
            try:
                obj, end = decoder.raw_decode(text, pos)
            except ValueError:
                yield None
                return
            objs.append(obj)
            pos = end
            while pos < len(text) and text[pos].isspace():
                pos += 1
        for obj in objs:
            events = (obj.get("events") or obj.get("logEvents") or []) if isinstance(obj, dict) else []
            if isinstance(obj, dict) and "message" in obj and not events:
                events = [obj]
            for ev in events:
                msg = ev.get("message") if isinstance(ev, dict) else None
                if isinstance(msg, str):
                    yield msg
        return
    buffer = head
    while True:
        *lines, buffer = buffer.split("\n")
        yield from lines
        more = fh.read(1 << 20)
        if not more:
            break
        buffer += more
    if buffer:
        yield buffer


def parse(fh, ctx):
    fields = ctx.args.fields.split() if ctx.args.fields else None
    is_csv = False
    for line in messages(fh):
        if line is None:
            yield None, "JSON file that is not CloudWatch Logs output"
            return
        if isinstance(line, list):  # CSV row: [(field, value)]
            pairs = [(f, "" if v.lower() in ("null", "none") else v) for f, v in line]
            if not any(v for _, v in pairs):
                continue
            doc, reason = build([f for f, _ in pairs], [v for _, v in pairs])
            if doc is None:
                yield None, reason
            else:
                yield "\t".join(v for _, v in pairs), doc
            continue
        line = line.rstrip("\r")
        if not line.strip():
            continue
        header = header_fields(line)
        if header:
            fields, is_csv = header
            continue
        if fields is None:
            fields = DEFAULT_FIELDS
        line = TS_PREFIX_RE.sub("", line)
        values = next(csv.reader([line])) if is_csv else line.split()
        values = [v.strip() for v in values]
        if len(values) != len(fields):
            yield None, f"{len(values)} values for {len(fields)} fields (use --fields for a custom format)"
            continue
        doc, reason = build(fields, values)
        if doc is None:
            yield None, reason
        else:
            yield line, doc


def detect(path, head):
    if "vpcflowlogs" in path.as_posix().lower():
        return True
    first = head.lstrip("\ufeff\r\n ").split("\n", 1)[0].rstrip("\r")
    if header_fields(first):
        return True
    columns = csv_columns(first)
    if columns and (columns != "raw" or "eni-" in head[:65536]):
        return True
    sample = TS_PREFIX_RE.sub("", first).split()
    if len(sample) == len(DEFAULT_FIELDS) and sample[0].isdigit() and sample[2].startswith("eni-"):
        return True
    return '"message"' in head[:4096] and "eni-" in head[:65536]


def add_arguments(ap):
    ap.add_argument("--fields", metavar="'version account-id ...'",
                    help="Space-separated field names of a custom log format, for files without a"
                         " header line (CloudWatch Logs). Default: the version 2 format")


LOG = AwsLog(
    prefix="aws-vpcflow", namespace="aws.vpcflow", title="AWS VPC Flow", dataset="aws.vpcflow",
    detect=detect, parse=parse, add_arguments=add_arguments,
    describe=[
        "S3 text delivery (.log / .log.gz) with its header line: any version or custom format",
        "CloudWatch Logs export lines (default v2 format, or --fields), timestamp prefix allowed",
        "`aws logs filter-log-events` JSON / CloudWatch subscription payloads",
        "CSV conversions: Athena results, Logs Insights exports (named columns or @message),"
        " spreadsheet exports; comma, tab, semicolon or pipe separated",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load AWS VPC Flow Logs into SOF-ELK (index aws-vpcflow-<source>)"))
