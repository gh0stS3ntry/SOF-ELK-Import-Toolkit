"""Amazon Security Lake (OCSF) records -> the native AWS log records the importers already parse.

Security Lake stores every AWS source it collects as OCSF (Open Cybersecurity Schema Framework)
events: source version 1 uses OCSF 1.0.0-rc.2, source version 2 (asl_version "2_0") OCSF 1.1.0.
Exports of those tables (Athena query results as CSV or JSON, `UNLOAD ... FORMAT JSON`, JSON
dumps) do not look like the native logs, so each importer would otherwise skip them.

This module recognises an OCSF record, decides which AWS source it came from, and rebuilds the
native record from it (eventName from api.operation, srcaddr from src_endpoint.ip, ...). The
importer then runs its usual build() on that record, so a Security Lake event and the same event
from the native log land in the same index with the same fields (and, for CloudTrail, the same
document ID: eventID). Original fields that OCSF has no place for are in OCSF `unmapped`, under
their native names; they are copied back as well.

  Security Lake source                     OCSF class (uid)                    importer / index
  CloudTrail management, S3 data, Lambda   API Activity 6003 (v1 also          cloudtrail2sofelk.py
    data events                              Account Change 3001,               aws-cloudtrail-<source>
                                             Authentication 3002, ...)
  VPC Flow Logs                            Network Activity 4001               vpcflow2sofelk.py, aws-vpcflow-<source>
  AWS WAF logs                             HTTP Activity 4002                  waf2sofelk.py, aws-waf-<source>
  Route 53 Resolver query logs             DNS Activity 4003                   route53resolver2sofelk.py, aws-route53-<source>
  Security Hub findings                    Security Finding 2001 (v1);         securityhub2sofelk.py, aws-securityhub-<source>
                                             Detection/Vulnerability/
                                             Compliance Finding 2002-2004 (v2)
  EKS audit logs                           API Activity 6003 (product EKS)     eksaudit2sofelk.py, kubernetes-<source>

Every document built from Security Lake also gets aws.securitylake.* (ASL and OCSF versions,
class, activity, product), so the two origins can be told apart.

Security Lake's own S3 objects are Apache Parquet, which the Python standard library cannot read;
query them with Athena (CSV download, or UNLOAD ... WITH (format = 'JSON')) first.

Standard library only.
"""
from __future__ import annotations

import datetime as dt
import json
import re

SOURCES = ("cloudtrail", "vpcflow", "waf", "route53", "securityhub", "eks")
SOURCE_TITLES = {
    "cloudtrail": "CloudTrail", "vpcflow": "VPC Flow Logs", "waf": "AWS WAF",
    "route53": "Route 53 Resolver", "securityhub": "Security Hub findings", "eks": "EKS audit logs",
}
SOURCE_SCRIPTS = {
    "cloudtrail": "cloudtrail2sofelk.py", "vpcflow": "vpcflow2sofelk.py", "waf": "waf2sofelk.py",
    "route53": "route53resolver2sofelk.py", "securityhub": "securityhub2sofelk.py",
    "eks": "eksaudit2sofelk.py",
}
FINDING_CLASSES = {2001, 2002, 2003, 2004, 2005, 2006}
API_CLASSES = {3001, 3002, 3003, 3004, 3005, 3006, 6003}
CLASS_SOURCE = {4001: "vpcflow", 4002: "waf", 4003: "route53"}

# Unmapped keys whose remainder is one map key, not a path ("annotations.authorization.k8s.io/decision")
MAP_ROOTS = ("annotations.", "user.extra.", "requestParameters.", "responseElements.",
             "additionalEventData.", "serviceEventDetails.", "ProductFields.", "UserDefinedFields.")


# --------------------------------------------------------------------------- small helpers

def g(obj, path, default=None):
    """Value at a dotted path, or default. Lists are not descended."""
    for part in path.split("."):
        if not isinstance(obj, dict):
            return default
        obj = obj.get(part)
        if obj is None:
            return default
    return obj


def first(*values):
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def text(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


def to_int(value):
    try:
        return int(float(value)) if value not in (None, "") and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def json_value(value):
    """JSON text (api.request.data, unmapped values) -> object; anything else unchanged."""
    if isinstance(value, str):
        v = value.strip()
        if v[:1] in ("{", "[") or v in ("true", "false", "null"):
            try:
                return json.loads(v)
            except ValueError:
                return value
    return value


def ms_iso(value):
    """OCSF time (epoch milliseconds, or Athena time_dt text) -> ISO 8601 UTC with Z."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,}(?:\.\d+)?", value)):
        n = float(value)
        if n > 1e14:      # microseconds
            n /= 1e6
        elif n > 1e11:    # milliseconds (OCSF)
            n /= 1e3
        try:
            stamp = dt.datetime.fromtimestamp(n, dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"
    if isinstance(value, str):
        v = value.strip().replace(" ", "T", 1)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?", v):
            v += "Z"  # Security Lake time_dt is UTC without a zone
        return v
    return None


def ms_epoch_s(value):
    """OCSF epoch milliseconds (or date text) -> epoch seconds as text (VPC Flow start/end)."""
    n = to_int(value)
    if n is not None:
        return str(n // 1000 if n > 1e11 else n)
    stamp = ms_iso(value)
    if stamp:
        try:
            return str(int(dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()))
        except ValueError:
            return None
    return None


def put(rec, path, value):
    """Set rec[path...] (path is a list) unless value is empty or the key is already there."""
    if value in (None, "", [], {}):
        return
    node = rec
    for part in path[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            if nxt is not None:
                return
            nxt = node[part] = {}
        node = nxt
    node.setdefault(path[-1], value)


def overlay_unmapped(rec, unmapped, skip=()):
    """Copy OCSF `unmapped` (native field names, possibly dotted) into the native record."""
    if isinstance(unmapped, str):
        unmapped = json_value(unmapped)
    if not isinstance(unmapped, dict):
        return
    for key, value in unmapped.items():
        if not isinstance(key, str) or key in skip:
            continue
        value = json_value(value)
        root = next((r for r in MAP_ROOTS if key.startswith(r)), None)
        if root:
            path = root[:-1].split(".") + [key[len(root):]]
        else:
            path = [p for p in key.split(".") if p]
        if path:
            put(rec, path, value)


# --------------------------------------------------------------------------- recognition

def is_ocsf(obj):
    return isinstance(obj, dict) and "class_uid" in obj and (
        isinstance(obj.get("metadata"), dict) or "category_uid" in obj or "asl_version" in obj)


def source_of(rec):
    """Which AWS source an OCSF record came from (one of SOURCES), or None."""
    if not is_ocsf(rec):
        return None
    cls = to_int(rec.get("class_uid"))
    name = str(g(rec, "metadata.product.name") or "").lower()
    if cls in FINDING_CLASSES or "security hub" in name or "securityhub" in name:
        return "securityhub"
    if "cloudtrail" in name:
        return "cloudtrail"
    if "eks" in name or "kubernetes" in name:
        return "eks"
    if "route" in name and "53" in name:
        return "route53"
    if "waf" in name:
        return "waf"
    if "vpc" in name or "flow log" in name:
        return "vpcflow"
    if cls in CLASS_SOURCE:
        return CLASS_SOURCE[cls]
    if cls in API_CLASSES:
        svc = str(g(rec, "api.service.name") or "")
        if "k8s" in svc or "kubernetes" in svc or g(rec, "unmapped.auditID") or g(rec, "unmapped.stage"):
            return "eks"
        return "cloudtrail"
    return None


HEAD_JSON_RE = re.compile(r'"class_uid"\s*:\s*"?(\d+)')
HEAD_NAME_RE = re.compile(r'"product"\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"]+)"')


def head_is_ocsf(head):
    """True if the start of a file looks like OCSF records (JSON or a CSV/struct-text export)."""
    h = head[:65536]
    low = h[:4096].lower()
    if '"class_uid"' in h and ('"metadata"' in h or '"category_uid"' in h or '"asl_version"' in h):
        return True
    first = re.split(r"\r\n|\r|\n", h.lstrip("﻿"), maxsplit=1)[0].lower()
    cols = {re.sub(r"[^a-z0-9_]", "", c) for c in re.split(r"[,\t;|]", first)}
    return "class_uid" in cols and ("metadata" in cols or "category_uid" in cols) and "{" not in first[:1] \
        and bool(low)


def head_sources(head, reader=None):
    """Sources (SOURCES names) of the OCSF records found at the start of a file.

    reader(head) yields records from the head text (sof_elk_aws_common.ocsf_head_records); when it
    finds none (a big pretty-printed JSON array, say), the product names and class UIDs in the text
    decide instead."""
    found = set()
    if reader is not None:
        for rec in reader(head):
            src = source_of(rec)
            if src:
                found.add(src)
    if found:
        return found
    for name in HEAD_NAME_RE.findall(head):
        src = source_of({"class_uid": 0, "metadata": {"product": {"name": name}}})
        if src:
            found.add(src)
    if not found:
        for cls in HEAD_JSON_RE.findall(head):
            src = source_of({"class_uid": int(cls), "metadata": {}})
            if src:
                found.add(src)
    return found


def provenance(rec, source):
    """aws.securitylake.* fields for a document built from an OCSF record."""
    return {k: v for k, v in {
        "asl_version": text(rec.get("asl_version")),
        "ocsf_version": text(g(rec, "metadata.version")),
        "class_uid": to_int(rec.get("class_uid")),
        "class_name": text(rec.get("class_name")),
        "category_uid": to_int(rec.get("category_uid")),
        "type_uid": to_int(rec.get("type_uid")),
        "activity_name": text(rec.get("activity_name")),
        "severity": text(rec.get("severity")),
        "product_name": text(g(rec, "metadata.product.name")),
        "product_feature": text(g(rec, "metadata.product.feature.name")),
        "event_day": text(rec.get("eventday")),
        "source": source,
    }.items() if v is not None}


def account_of(rec):
    return text(first(g(rec, "cloud.account.uid"), g(rec, "cloud.account_uid"), rec.get("accountid")))


def region_of(rec):
    return text(first(g(rec, "cloud.region"), rec.get("region")))


def _list(value):
    value = json_value(value)
    if isinstance(value, list):
        return value
    return [] if value in (None, "") else [value]


# --------------------------------------------------------------------------- CloudTrail

def to_cloudtrail(r):
    """OCSF API Activity (and v1 IAM classes) from CloudTrail -> native CloudTrail record."""
    rec = {}
    put(rec, ["eventVersion"], text(g(r, "metadata.product.version")))
    put(rec, ["eventID"], text(g(r, "metadata.uid")))
    put(rec, ["eventType"], text(g(r, "metadata.event_code")))
    put(rec, ["eventTime"], ms_iso(first(r.get("time"), r.get("time_dt"))))
    put(rec, ["eventName"], text(g(r, "api.operation")))
    put(rec, ["eventSource"], text(g(r, "api.service.name")))
    put(rec, ["requestID"], text(g(r, "api.request.uid")))
    put(rec, ["requestParameters"], json_value(g(r, "api.request.data")))
    put(rec, ["responseElements"], json_value(g(r, "api.response.data")))
    put(rec, ["errorCode"], text(g(r, "api.response.error")))
    put(rec, ["errorMessage"], text(g(r, "api.response.message")))
    put(rec, ["awsRegion"], region_of(r))
    put(rec, ["sourceIPAddress"], text(first(g(r, "src_endpoint.ip"), g(r, "src_endpoint.domain"))))
    put(rec, ["vpcEndpointId"], text(g(r, "src_endpoint.uid")))
    put(rec, ["userAgent"], text(g(r, "http_request.user_agent")))
    feature = text(g(r, "metadata.product.feature.name"))
    put(rec, ["eventCategory"], feature)

    user = g(r, "actor.user", {}) or {}
    ui = ["userIdentity"]
    put(rec, ui + ["type"], text(user.get("type")))
    put(rec, ui + ["arn"], text(user.get("uid")))
    put(rec, ui + ["principalId"], text(user.get("uid_alt")))
    put(rec, ui + ["userName"], text(user.get("name")))
    put(rec, ui + ["accountId"], text(first(g(user, "account.uid"), user.get("account_uid"))))
    put(rec, ui + ["accessKeyId"], text(user.get("credential_uid")))
    put(rec, ui + ["invokedBy"], text(g(r, "actor.invoked_by")))
    session = g(r, "actor.session", {}) or {}
    sc = ui + ["sessionContext"]
    put(rec, sc + ["sessionIssuer", "arn"], text(session.get("issuer")))
    put(rec, sc + ["attributes", "creationDate"],
        ms_iso(first(session.get("created_time"), session.get("created_time_dt"))))
    mfa = session.get("is_mfa")
    if mfa is not None:
        put(rec, sc + ["attributes", "mfaAuthenticated"], text(mfa).lower())
    put(rec, ui + ["webIdFederationData", "federatedProvider"], text(g(r, "actor.idp.name")))

    put(rec, ["tlsDetails", "tlsVersion"], text(g(r, "tls.version")))
    put(rec, ["tlsDetails", "cipherSuite"], text(g(r, "tls.cipher")))
    put(rec, ["tlsDetails", "clientProvidedHostHeader"],
        text(first(g(r, "tls.sni"), g(r, "http_request.url.hostname"))))

    resources = []
    for res in _list(r.get("resources")):
        if isinstance(res, dict):
            item = {k: v for k, v in {
                "ARN": text(res.get("uid")), "type": text(res.get("type")),
                "accountId": text(first(res.get("account_uid"), g(res, "owner.account.uid"), g(res, "account.uid"))),
            }.items() if v}
            if item:
                resources.append(item)
    put(rec, ["resources"], resources)

    overlay_unmapped(rec, r.get("unmapped"))
    put(rec, ["recipientAccountId"], account_of(r))
    if feature and "managementEvent" not in rec:
        put(rec, ["managementEvent"], "true" if feature.lower() == "management" else "false")
    # v1 Authentication class (ConsoleLogin) may carry no api.operation
    if "eventName" not in rec and to_int(r.get("class_uid")) == 3002:
        rec["eventName"] = "ConsoleLogin"
    if rec.get("eventName") == "ConsoleLogin" and str(r.get("status") or "") in ("Success", "Failure"):
        put(rec, ["responseElements", "ConsoleLogin"], r["status"])
    if str(r.get("status") or "").lower() == "failure" and "errorCode" not in rec and rec.get("eventName") != "ConsoleLogin":
        put(rec, ["errorCode"], text(first(r.get("status_detail"), r.get("status_code"), "Failure")))
    return rec


# --------------------------------------------------------------------------- VPC Flow

DIRECTION = {"inbound": "ingress", "outbound": "egress", "1": "ingress", "2": "egress"}
ACCEPT = {"allowed": "ACCEPT", "accept": "ACCEPT", "1": "ACCEPT", "denied": "REJECT", "reject": "REJECT",
          "blocked": "REJECT", "2": "REJECT"}


def to_vpcflow(r):
    """OCSF Network Activity from VPC Flow Logs -> {native field name: value text}."""
    s, d = g(r, "src_endpoint", {}) or {}, g(r, "dst_endpoint", {}) or {}
    ci, tr = g(r, "connection_info", {}) or {}, g(r, "traffic", {}) or {}

    def ep(key):
        return text(first(s.get(key), d.get(key)))

    action = str(first(r.get("action"), r.get("disposition"), r.get("action_id")) or "").lower()
    direction = str(first(ci.get("direction"), ci.get("direction_id")) or "").lower()
    fields = {
        "version": text(g(r, "metadata.product.version")),
        "account-id": account_of(r),
        "interface-id": ep("interface_uid"),
        "srcaddr": text(s.get("ip")), "dstaddr": text(d.get("ip")),
        "srcport": text(s.get("port")), "dstport": text(d.get("port")),
        "protocol": text(ci.get("protocol_num")),
        "packets": text(tr.get("packets")), "bytes": text(tr.get("bytes")),
        "start": ms_epoch_s(r.get("start_time")), "end": ms_epoch_s(r.get("end_time")),
        "action": ACCEPT.get(action),
        "log-status": text(first(r.get("status_code"), "OK" if r.get("status") == "Success" else None)),
        "vpc-id": ep("vpc_uid"), "subnet-id": ep("subnet_uid"), "instance-id": ep("instance_uid"),
        "tcp-flags": text(ci.get("tcp_flags")),
        "type": text(ci.get("protocol_ver")),
        "pkt-srcaddr": text(first(*(_list(s.get("intermediate_ips")) or [None]))),
        "pkt-dstaddr": text(first(*(_list(d.get("intermediate_ips")) or [None]))),
        "region": region_of(r),
        "az-id": text(g(r, "cloud.zone")),
        "pkt-src-aws-service": text(s.get("svc_name")),
        "pkt-dst-aws-service": text(d.get("svc_name")),
        "flow-direction": DIRECTION.get(direction),
        "traffic-path": text(ci.get("boundary_id")),
    }
    fields = {k: v for k, v in fields.items() if v not in (None, "")}
    unmapped = json_value(r.get("unmapped"))
    if isinstance(unmapped, dict):
        for key, value in unmapped.items():
            name = str(key).lower().replace("_", "-")
            if name not in fields and value not in (None, ""):
                fields[name] = text(value)
    return fields


# --------------------------------------------------------------------------- WAF

WAF_ACTION = {"allowed": "ALLOW", "allow": "ALLOW", "denied": "BLOCK", "blocked": "BLOCK", "block": "BLOCK",
              "count": "COUNT", "captcha": "CAPTCHA", "challenge": "CHALLENGE"}


def to_waf(r):
    """OCSF HTTP Activity from AWS WAF -> native WAF log record."""
    rec = {}
    overlay_unmapped(rec, r.get("unmapped"))
    put(rec, ["timestamp"], to_int(r.get("time")) or ms_iso(r.get("time_dt")))
    put(rec, ["webaclId"], text(first(g(r, "metadata.product.feature.uid"), g(r, "firewall_rule.policy.uid"))))
    action = first(r.get("disposition"), r.get("action"))
    put(rec, ["action"], WAF_ACTION.get(str(action or "").lower(), text(action)))
    put(rec, ["terminatingRuleId"], text(g(r, "firewall_rule.uid")))
    put(rec, ["terminatingRuleType"], text(g(r, "firewall_rule.type")))
    put(rec, ["httpSourceName"], text(g(r, "dst_endpoint.svc_name")))
    put(rec, ["httpSourceId"], text(g(r, "dst_endpoint.uid")))
    put(rec, ["responseCodeSent"], to_int(g(r, "http_response.code")))
    put(rec, ["ja3Fingerprint"], text(g(r, "tls.ja3_hash.value")))
    req = ["httpRequest"]
    put(rec, req + ["clientIp"], text(g(r, "src_endpoint.ip")))
    put(rec, req + ["country"], text(g(r, "src_endpoint.location.country")))
    put(rec, req + ["httpMethod"], text(g(r, "http_request.http_method")))
    put(rec, req + ["uri"], text(g(r, "http_request.url.path")))
    put(rec, req + ["args"], text(g(r, "http_request.url.query_string")))
    put(rec, req + ["host"], text(g(r, "http_request.url.hostname")))
    put(rec, req + ["scheme"], text(g(r, "http_request.url.scheme")))
    put(rec, req + ["httpVersion"], text(g(r, "http_request.version")))
    put(rec, req + ["requestId"], text(g(r, "http_request.uid")))
    headers = [{"name": text(h.get("name")), "value": text(h.get("value")) or ""}
               for h in _list(g(r, "http_request.http_headers")) if isinstance(h, dict) and h.get("name")]
    put(rec, req + ["headers"], headers)
    labels = [l if isinstance(l, dict) else {"name": text(l)} for l in _list(g(r, "metadata.labels"))]
    put(rec, ["labels"], [l for l in labels if l.get("name")])
    return rec


# --------------------------------------------------------------------------- Route 53 Resolver

def to_route53(r):
    """OCSF DNS Activity from Route 53 Resolver query logs -> native query log record."""
    rec = {}
    s, d = g(r, "src_endpoint", {}) or {}, g(r, "dst_endpoint", {}) or {}
    put(rec, ["version"], text(g(r, "metadata.product.version")))
    put(rec, ["account_id"], account_of(r))
    put(rec, ["region"], region_of(r))
    put(rec, ["vpc_id"], text(first(s.get("vpc_uid"), d.get("vpc_uid"))))
    put(rec, ["query_timestamp"], ms_iso(first(r.get("time"), r.get("time_dt"), r.get("query_time"))))
    put(rec, ["query_name"], text(g(r, "query.hostname")))
    put(rec, ["query_type"], text(g(r, "query.type")))
    put(rec, ["query_class"], text(g(r, "query.class")))
    put(rec, ["rcode"], text(r.get("rcode")))
    answers = []
    for a in _list(r.get("answers")):
        if isinstance(a, dict):
            item = {k: v for k, v in {"Rdata": text(a.get("rdata")), "Type": text(a.get("type")),
                                      "Class": text(a.get("class"))}.items() if v}
            if item:
                answers.append(item)
    put(rec, ["answers"], answers)
    put(rec, ["srcaddr"], text(s.get("ip")))
    put(rec, ["srcport"], text(s.get("port")))
    put(rec, ["transport"], text(g(r, "connection_info.protocol_name")))
    put(rec, ["srcids", "instance"], text(s.get("instance_uid")))
    put(rec, ["srcids", "resolver_endpoint"], text(d.get("instance_uid")))
    put(rec, ["resolver_network_interface"], text(d.get("interface_uid")))
    put(rec, ["firewall_rule_action"], text(first(r.get("disposition"), r.get("action"))
                                            if g(r, "firewall_rule.uid") else None))
    put(rec, ["firewall_rule_group_id"], text(g(r, "firewall_rule.uid")))
    put(rec, ["firewall_domain_list_id"], text(g(r, "firewall_rule.condition")))
    overlay_unmapped(rec, r.get("unmapped"))
    return rec


# --------------------------------------------------------------------------- Security Hub

def to_securityhub(r):
    """OCSF Security/Detection Finding from Security Hub -> ASFF finding (native field names)."""
    fi = first(g(r, "finding_info"), g(r, "finding")) or {}
    rec = {}
    put(rec, ["Id"], text(fi.get("uid")))
    put(rec, ["Title"], text(fi.get("title")))
    put(rec, ["Description"], text(fi.get("desc")))
    put(rec, ["Types"], [text(t) for t in _list(fi.get("types")) if t])
    put(rec, ["CreatedAt"], ms_iso(first(fi.get("created_time"), fi.get("created_time_dt"))))
    put(rec, ["UpdatedAt"], ms_iso(first(fi.get("modified_time"), fi.get("modified_time_dt"),
                                         r.get("time"), r.get("time_dt"))))
    put(rec, ["FirstObservedAt"], ms_iso(first(fi.get("first_seen_time"), fi.get("first_seen_time_dt"))))
    put(rec, ["LastObservedAt"], ms_iso(first(fi.get("last_seen_time"), fi.get("last_seen_time_dt"))))
    put(rec, ["ProductArn"], text(first(fi.get("product_uid"), g(r, "metadata.product.uid"))))
    put(rec, ["GeneratorId"], text(first(g(fi, "analytic.uid"), g(fi, "analytic.name"))))
    put(rec, ["ProductName"], text(g(r, "metadata.product.name")))
    put(rec, ["CompanyName"], text(g(r, "metadata.product.vendor_name")))
    put(rec, ["Severity", "Label"], text(r.get("severity")).upper() if r.get("severity") else None)
    put(rec, ["AwsAccountId"], account_of(r))
    put(rec, ["Region"], region_of(r))
    put(rec, ["Compliance", "Status"], text(g(r, "compliance.status")))
    put(rec, ["Compliance", "SecurityControlId"], text(g(r, "compliance.control")))
    put(rec, ["Workflow", "Status"], text(r.get("status")).upper() if r.get("status") else None)
    put(rec, ["RecordState"], text(r.get("state")))
    put(rec, ["Remediation", "Recommendation", "Text"], text(g(r, "remediation.desc")))
    refs = _list(g(r, "remediation.references"))
    put(rec, ["Remediation", "Recommendation", "Url"], text(refs[0]) if refs else None)
    put(rec, ["SourceUrl"], text(fi.get("src_url")))
    resources = []
    for res in _list(r.get("resources")):
        if isinstance(res, dict):
            item = {k: v for k, v in {
                "Id": text(res.get("uid")), "Type": text(res.get("type")),
                "Region": text(res.get("region")), "Partition": text(res.get("cloud_partition")),
                "Details": json_value(res.get("data")),
            }.items() if v not in (None, "", {})}
            if item:
                resources.append(item)
    put(rec, ["Resources"], resources)
    overlay_unmapped(rec, r.get("unmapped"))
    return rec


# --------------------------------------------------------------------------- EKS audit

def to_k8s_audit(r):
    """OCSF API Activity from EKS audit logs -> Kubernetes audit.k8s.io Event."""
    rec = {}
    overlay_unmapped(rec, r.get("unmapped"))
    put(rec, ["kind"], "Event")
    put(rec, ["auditID"], text(first(g(r, "api.request.uid"), g(r, "metadata.uid"))))
    put(rec, ["verb"], text(g(r, "api.operation")))
    put(rec, ["requestURI"], text(g(r, "http_request.url.path")))
    put(rec, ["user", "username"], text(g(r, "actor.user.name")))
    put(rec, ["user", "uid"], text(g(r, "actor.user.uid")))
    groups = [text(x.get("name") if isinstance(x, dict) else x) for x in _list(g(r, "actor.user.groups"))]
    put(rec, ["user", "groups"], [x for x in groups if x])
    put(rec, ["impersonatedUser", "username"], text(g(r, "actor.invoked_by")))
    ips = [text(g(r, "src_endpoint.ip"))] + [text(x) for x in _list(g(r, "src_endpoint.intermediate_ips"))]
    put(rec, ["sourceIPs"], [x for x in ips if x])
    put(rec, ["userAgent"], text(g(r, "http_request.user_agent")))
    resources = [x for x in _list(r.get("resources")) if isinstance(x, dict)]
    if resources:
        res = resources[0]
        put(rec, ["objectRef", "resource"], text(res.get("type")))
        put(rec, ["objectRef", "name"], text(res.get("name")))
        put(rec, ["objectRef", "namespace"], text(first(res.get("namespace"), g(res, "group.name"))))
        put(rec, ["objectRef", "uid"], text(res.get("uid")))
    put(rec, ["responseStatus", "code"], to_int(first(g(r, "api.response.code"), g(r, "http_response.code"))))
    put(rec, ["responseStatus", "message"], text(g(r, "api.response.message")))
    put(rec, ["requestObject"], json_value(g(r, "api.request.data")))
    put(rec, ["responseObject"], json_value(g(r, "api.response.data")))
    put(rec, ["requestReceivedTimestamp"], ms_iso(first(r.get("start_time"), r.get("time"), r.get("time_dt"))))
    put(rec, ["stageTimestamp"], ms_iso(first(r.get("end_time"), r.get("time"))))
    return rec
