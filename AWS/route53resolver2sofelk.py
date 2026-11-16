#!/usr/bin/env python3
"""Load Amazon Route 53 Resolver query logs into SOF-ELK as aws-route53-<source>.

Field names follow SOF-ELK's own Route 53 parsing (configfiles/6014-passivedns.conf, which loads
Resolver query logs into its logstash-* indexes): query_name -> dns.question.name, query_type ->
dns.question.type, query_class -> dns.question.class, rcode -> dns.response.code, answers[].Rdata
/ Class -> dns.answers.data / dns.answers.class, srcaddr / srcport -> source.ip / source.port,
transport -> network.transport (lower case), account_id / vpc_id -> aws.route53.account_id /
vpc_id, srcids.instance -> aws.route53.instance, srcids.resolver_endpoint ->
aws.route53.resolver_instance, resolver_network_interface -> aws.route53.resolver_network_interface,
query_timestamp -> @timestamp.

Differences from SOF-ELK, so that one query is one document:
  * SOF-ELK splits a record into one document per answer; here the answers are lists
    (dns.answers.data, .type, .class) and the A/AAAA answers are also in dns.resolved_ip.
  * SOF-ELK writes each answer's Type into dns.question.type; here it is dns.answers.type.
  * The trailing dot is removed from names (as SOF-ELK does for passive DNS); the name as
    logged is kept in aws.route53.query_name.
Route 53 Resolver DNS Firewall fields (firewall_rule_action, firewall_rule_group_id,
firewall_domain_list_id, firewall_protection) go to aws.route53.firewall.*, and
dns.question.registered_domain / top_level_domain / subdomain are added for stacking.

Inputs (plain or .gz, any file name):
  * query logs delivered to S3 or exported from CloudWatch Logs: one JSON record per line
    (optionally timestamp-prefixed); `aws logs filter-log-events` output;
  * Amazon Security Lake exports (OCSF DNS Activity, class 4003): JSON or Athena CSV;
  * CSV conversions: Athena results over the query log table (answers / srcids as struct text
    or JSON), flattened exports (srcids.instance, answers.0.Rdata), or a raw-JSON column
    ("@message", "_raw", ...).

Example:
  python3 AWS/route53resolver2sofelk.py /cases/IR-42/route53 --source 123456789012 --dry-run
"""
import sys

from sof_elk_aws_common import (AwsLog, canon, cloudwatch_messages, compact_json, csv_records,
                                first_line, iso, iter_json, looks_like_csv_header, run, set_field,
                                snake, to_int, valid_ip)
import sof_elk_ocsf as ocsf

NATIVE_KEYS = ["version", "account_id", "region", "vpc_id", "query_timestamp", "query_name",
               "query_type", "query_class", "rcode", "answers", "Rdata", "Type", "Class", "srcaddr",
               "srcport", "transport", "srcids", "instance", "resolver_endpoint",
               "resolver_network_interface", "firewall_rule_action", "firewall_rule_group_id",
               "firewall_domain_list_id", "firewall_protection"]
CSV_NAMES = {canon(k): k for k in NATIVE_KEYS}
KNOWN = {"version", "account_id", "region", "vpc_id", "query_timestamp", "query_name", "query_type",
         "query_class", "rcode", "answers", "srcaddr", "srcport", "transport", "srcids",
         "resolver_network_interface", "firewall_rule_action", "firewall_rule_group_id",
         "firewall_domain_list_id", "firewall_protection"}
# Multi-label public suffixes common enough to matter for registered_domain.
SUFFIX2 = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
           "com.sg", "com.my", "com.cn", "com.hk", "com.tw", "co.in", "com.br", "co.za",
           "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net"}


def text(value):
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else str(value)


def domain_parts(name):
    labels = [l for l in name.lower().split(".") if l]
    if len(labels) < 2 or valid_ip(name):
        return None, None, None
    two = ".".join(labels[-2:])
    if two in SUFFIX2 and len(labels) >= 3:
        tld, reg_n = two, 3
    else:
        tld, reg_n = labels[-1], 2
    registered = ".".join(labels[-reg_n:])
    sub = ".".join(labels[:-reg_n]) or None
    return registered, tld, sub


def build(rec):
    doc, malformed = {}, []
    ts = iso(text(rec.get("query_timestamp")))
    if ts:
        doc["@timestamp"] = ts
    elif rec.get("query_timestamp"):
        malformed.append(f"query_timestamp={rec.get('query_timestamp')}")
    r53 = "aws.route53."
    name = text(rec.get("query_name"))
    set_field(doc, r53 + "query_name", name)
    clean = name.rstrip(".") if name else None
    set_field(doc, "dns.question.name", clean.lower() if clean else None)
    if clean:
        registered, tld, sub = domain_parts(clean)
        set_field(doc, "dns.question.registered_domain", registered)
        set_field(doc, "dns.question.top_level_domain", tld)
        set_field(doc, "dns.question.subdomain", sub)
    set_field(doc, "dns.question.type", text(rec.get("query_type")))
    set_field(doc, "dns.question.class", text(rec.get("query_class")))
    set_field(doc, "dns.response.code", text(rec.get("rcode")))
    answers = rec.get("answers") if isinstance(rec.get("answers"), list) else []
    data, types, classes, ips = [], [], [], []
    for a in answers:
        if not isinstance(a, dict):
            continue
        rdata = text(a.get("Rdata") or a.get("rdata"))
        if rdata:
            data.append(rdata.rstrip(".") if not valid_ip(rdata) else rdata)
            if valid_ip(rdata):
                ips.append(valid_ip(rdata))
        types.append(text(a.get("Type") or a.get("type")) or "")
        classes.append(text(a.get("Class") or a.get("class")) or "")
    set_field(doc, "dns.answers.data", data)
    set_field(doc, "dns.answers.type", [t for t in types if t])
    set_field(doc, "dns.answers.class", [c for c in classes if c])
    set_field(doc, "dns.answers.ip", ips)
    set_field(doc, "dns.resolved_ip", sorted(set(ips)))
    set_field(doc, "dns.type", "query")
    src = text(rec.get("srcaddr"))
    set_field(doc, "source.ip", valid_ip(src))
    if src and not valid_ip(src):
        malformed.append(f"srcaddr={src}")
    set_field(doc, "source.port", to_int(rec.get("srcport")))
    transport = text(rec.get("transport"))
    set_field(doc, "network.transport", transport.lower() if transport else None)
    set_field(doc, "network.protocol", "dns")
    account = text(rec.get("account_id"))
    set_field(doc, r53 + "account_id", account)
    set_field(doc, "cloud.account.id", account)
    set_field(doc, "cloud.region", text(rec.get("region")))
    set_field(doc, r53 + "vpc_id", text(rec.get("vpc_id")))
    set_field(doc, r53 + "version", text(rec.get("version")))
    srcids = rec.get("srcids") if isinstance(rec.get("srcids"), dict) else {}
    set_field(doc, r53 + "instance", text(srcids.get("instance")))
    set_field(doc, r53 + "resolver_instance", text(srcids.get("resolver_endpoint")))
    set_field(doc, r53 + "resolver_network_interface", text(rec.get("resolver_network_interface")))
    for key in ("firewall_rule_action", "firewall_rule_group_id", "firewall_domain_list_id",
                "firewall_protection"):
        set_field(doc, r53 + "firewall." + key[len("firewall_"):], text(rec.get(key)))
    rcode = text(rec.get("rcode"))
    doc["event"] = {"dataset": "aws.route53", "kind": "event", "category": "network"}
    set_field(doc, "event.action", "dns-query")
    if rcode:
        doc["event"]["outcome"] = "success" if rcode == "NOERROR" else "failure"
    fw = text(rec.get("firewall_rule_action"))
    if fw:
        set_field(doc, "event.type", "denied" if fw.upper() in ("BLOCK", "DENY") else "allowed")
    for key, value in rec.items():
        if key not in KNOWN and value not in (None, "", {}, []):
            set_field(doc, r53 + "unmapped." + snake(key),
                      compact_json(value) if isinstance(value, (dict, list)) else text(value))
    if malformed:
        set_field(doc, r53 + "malformed", malformed)
    return doc


def is_record(obj):
    return isinstance(obj, dict) and "query_name" in obj and ("query_timestamp" in obj or "srcaddr" in obj)


def record_key(rec):
    return compact_json({k: rec.get(k) for k in ("query_timestamp", "query_name", "query_type", "srcaddr",
                                                  "srcport", "vpc_id", "account_id", "rcode")})


def records(obj):
    msgs = cloudwatch_messages(obj)
    if msgs is not None:
        for m in msgs:
            yield from records(m) if m is not None else [None]
    elif isinstance(obj, list):
        for item in obj:
            yield from records(item)
    elif is_record(obj):
        yield obj
    else:
        yield None


def is_csv_header(line):
    return looks_like_csv_header(line, [("queryname", "message", "raw", "event", "json")])


def parse(fh, ctx):
    head = fh.read(1 << 16)
    if is_csv_header(first_line(head)):
        for kind, value in csv_records(fh, CSV_NAMES, head=head.lstrip("﻿")):
            objs = list(iter_json(_Text(value))) if kind == "json" else [value]
            for obj in objs:
                for rec in records(obj):
                    yield (record_key(rec), build(rec)) if rec else (None, "CSV row without query_name")
        return
    for obj in iter_json(fh, head):
        for rec in records(obj):
            yield (record_key(rec), build(rec)) if rec else (None, "JSON value is not a Route 53 Resolver query log record")


class _Text:
    def __init__(self, value):
        self.value = value

    def read(self, _size=-1):
        value, self.value = self.value, ""
        return value


def from_ocsf(r):
    rec = ocsf.to_route53(r)
    if not rec.get("query_name"):
        return None, "Security Lake DNS record without query.hostname"
    return record_key(rec), build(rec)


def detect(path, head):
    h = head[:65536].replace('\\"', '"')  # also inside CloudWatch "message" strings
    if '"query_name"' in h and ('"query_timestamp"' in h or '"srcaddr"' in h) and '"rcode"' in h:
        return True
    first = first_line(h)
    return looks_like_csv_header(first, ["queryname", ("querytimestamp", "srcaddr")]) or \
        (looks_like_csv_header(first, ["message"]) and "query_name" in h)


LOG = AwsLog(
    prefix="aws-route53", namespace="aws.route53", title="AWS Route 53 Resolver query",
    dataset="aws.route53", detect=detect, parse=parse, use_occurrence=False, ocsf=("route53", from_ocsf),
    describe=[
        "Resolver query logs delivered to S3 or exported from CloudWatch Logs (JSON per line, .gz fine)",
        "`aws logs filter-log-events` / subscription JSON",
        "Amazon Security Lake exports (OCSF DNS Activity 4003): JSON or Athena CSV",
        "CSV conversions: Athena results, flattened (srcids.instance) or raw-JSON column",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load Amazon Route 53 Resolver query logs into SOF-ELK (index aws-route53-<source>)"))
