#!/usr/bin/env python3
"""Load Amazon EKS (Kubernetes) audit logs into SOF-ELK as kubernetes-<source>.

The documents follow SOF-ELK's own Kubernetes audit parsing (configfiles/1952-preprocess-kubernetes.conf
and 6952-kubernetes.conf), so they sit next to SOF-ELK's kubernetes-YYYY.MM indexes and one
`FROM kubernetes-*` query covers both: the audit event is kept under k8s.* with its native names
(k8s.auditID, k8s.stage, k8s.level, k8s.user.username, k8s.objectRef.resource, ...), and

  requestReceivedTimestamp -> @timestamp      sourceIPs   -> source.ip (list)
  verb                     -> http.request.method (upper case), event.action (as logged)
  requestURI               -> url.path        userAgent   -> user_agent.original
  responseStatus.code      -> http.response.status_code

Added for hunting: user.name (user.username), event.outcome (status code below 400 = success),
kubernetes.namespace (objectRef.namespace), k8s.annotations.* (authorization decision and reason,
pod security, ...). requestObject / responseObject are large and free-form, so they are kept as
JSON text in k8s.flattened.request_object / response_object (SOF-ELK indexes them as objects,
dropping their metadata); user.extra likewise goes to k8s.flattened.user_extra.

Like the ALB importer and httpdlog-*, no index template is installed for kubernetes-* (it would
take over SOF-ELK's own monthly indexes): the importer creates kubernetes-<source> itself with
the mapping in index_templates/index-kubernetes.json.

Inputs (plain or .gz, any file name):
  * EKS control plane audit logs exported from CloudWatch Logs (log group /aws/eks/<cluster>/cluster,
    streams kube-apiserver-audit-*): one JSON event per line, optionally timestamp-prefixed;
    `aws logs filter-log-events` output; JSON arrays or Kubernetes EventList objects ({"items": [...]});
  * Amazon Security Lake exports (OCSF API Activity 6003 from Amazon EKS): JSON or Athena CSV;
  * CSV: a column holding the whole event as JSON (Logs Insights "@message", ...), or flattened
    columns (objectRef.resource, user.username, ...).

Example:
  python3 AWS/eksaudit2sofelk.py /cases/IR-42/eks-audit --source prod-cluster --dry-run
"""
import sys

from sof_elk_aws_common import (AwsLog, canon, cloudwatch_messages, compact_json, csv_records,
                                first_line, iso, iter_json, looks_like_csv_header, run, set_field,
                                to_int, valid_ip)
import sof_elk_ocsf as ocsf

NATIVE_KEYS = ["kind", "apiVersion", "level", "auditID", "stage", "requestURI", "verb", "user",
               "username", "uid", "groups", "extra", "impersonatedUser", "sourceIPs", "userAgent",
               "objectRef", "resource", "namespace", "name", "apiGroup", "subresource",
               "resourceVersion", "responseStatus", "status", "reason", "code", "message",
               "requestObject", "responseObject", "requestReceivedTimestamp", "stageTimestamp",
               "annotations", "metadata"]
CSV_NAMES = {canon(k): k for k in NATIVE_KEYS}
KEEP_CASE = ("annotations", "extra", "requestObject", "responseObject")
KNOWN = {"kind", "apiVersion", "level", "auditID", "stage", "requestURI", "verb", "user",
         "impersonatedUser", "sourceIPs", "userAgent", "objectRef", "responseStatus", "requestObject",
         "responseObject", "requestReceivedTimestamp", "stageTimestamp", "annotations"}


def text(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return compact_json(value)
    return str(value)


def build(rec):
    doc, malformed = {}, []
    k = "k8s."
    received, stage_ts = iso(text(rec.get("requestReceivedTimestamp"))), iso(text(rec.get("stageTimestamp")))
    if received or stage_ts:
        doc["@timestamp"] = received or stage_ts
    for key, value in (("requestReceivedTimestamp", received), ("stageTimestamp", stage_ts)):
        if rec.get(key) and not value:
            malformed.append(f"{key}={rec.get(key)}")
        set_field(doc, k + key, value)
    for key in ("kind", "apiVersion", "level", "auditID", "stage"):
        set_field(doc, k + key, text(rec.get(key)))
    user = rec.get("user") if isinstance(rec.get("user"), dict) else {}
    set_field(doc, k + "user.username", text(user.get("username")))
    set_field(doc, k + "user.uid", text(user.get("uid")))
    groups = user.get("groups")
    set_field(doc, k + "user.groups", [text(g) for g in groups if g] if isinstance(groups, list) else text(groups))
    set_field(doc, k + "flattened.user_extra", compact_json(user.get("extra")))
    set_field(doc, "user.name", text(user.get("username")))
    imp = rec.get("impersonatedUser") if isinstance(rec.get("impersonatedUser"), dict) else {}
    set_field(doc, k + "impersonatedUser.username", text(imp.get("username")))
    set_field(doc, k + "impersonatedUser.groups",
              [text(g) for g in imp.get("groups") or [] if g] if isinstance(imp.get("groups"), list) else None)
    obj = rec.get("objectRef") if isinstance(rec.get("objectRef"), dict) else {}
    for key in ("resource", "namespace", "name", "apiGroup", "apiVersion", "subresource", "uid",
                "resourceVersion"):
        set_field(doc, k + "objectRef." + key, text(obj.get(key)))
    set_field(doc, "kubernetes.namespace", text(obj.get("namespace")))
    status = rec.get("responseStatus") if isinstance(rec.get("responseStatus"), dict) else {}
    for key in ("status", "reason", "message"):
        set_field(doc, k + "responseStatus." + key, text(status.get(key)))
    code = to_int(status.get("code"))
    set_field(doc, "http.response.status_code", code)
    annotations = rec.get("annotations")
    if isinstance(annotations, dict):
        set_field(doc, k + "annotations", {str(a): text(v) for a, v in annotations.items() if v not in (None, "")})
        set_field(doc, k + "authorization_decision", text(annotations.get("authorization.k8s.io/decision")))
        set_field(doc, k + "authorization_reason", text(annotations.get("authorization.k8s.io/reason")))
    ips = rec.get("sourceIPs")
    ips = ips if isinstance(ips, list) else ([ips] if ips else [])
    good = [valid_ip(text(i)) for i in ips]
    set_field(doc, "source.ip", [i for i in good if i])
    malformed += [f"sourceIPs={i}" for i, g in zip(ips, good) if not g]
    verb = text(rec.get("verb"))
    set_field(doc, "http.request.method", verb.upper() if verb else None)
    set_field(doc, "url.path", text(rec.get("requestURI")))
    set_field(doc, "user_agent.original", text(rec.get("userAgent")))
    set_field(doc, k + "flattened.request_object", compact_json(rec.get("requestObject")))
    set_field(doc, k + "flattened.response_object", compact_json(rec.get("responseObject")))
    doc["event"] = {"dataset": "aws.eks_audit", "kind": "event"}
    set_field(doc, "event.action", verb)
    if code is not None:
        doc["event"]["outcome"] = "success" if code < 400 else "failure"
    for key, value in rec.items():
        if key not in KNOWN and value not in (None, "", {}, []):
            set_field(doc, k + "unmapped." + key.replace(".", "_"), text(value))
    if malformed:
        set_field(doc, k + "malformed", malformed)
    return doc


def is_record(obj):
    return isinstance(obj, dict) and "auditID" in obj and ("verb" in obj or "stage" in obj)


def records(obj):
    msgs = cloudwatch_messages(obj)
    if msgs is not None:
        for m in msgs:
            yield from records(m) if m is not None else [None]
    elif isinstance(obj, list):
        for item in obj:
            yield from records(item)
    elif isinstance(obj, dict) and isinstance(obj.get("items"), list) and "auditID" not in obj:
        yield from records(obj["items"])
    elif is_record(obj):
        yield obj
    else:
        yield None


def record_key(rec):
    return f"{rec.get('auditID')}|{rec.get('stage')}"


class _Text:
    def __init__(self, value):
        self.value = value

    def read(self, _size=-1):
        value, self.value = self.value, ""
        return value


def is_csv_header(line):
    return looks_like_csv_header(line, [("auditid", "message", "raw", "event", "json")])


def parse(fh, ctx):
    head = fh.read(1 << 16)
    if is_csv_header(first_line(head)):
        for kind, value in csv_records(fh, CSV_NAMES, keep_case=KEEP_CASE, head=head.lstrip("﻿")):
            objs = list(iter_json(_Text(value))) if kind == "json" else [value]
            for obj in objs:
                for rec in records(obj):
                    yield (record_key(rec), build(rec)) if rec else (None, "CSV row that is not an audit event")
        return
    for obj in iter_json(fh, head):
        for rec in records(obj):
            yield (record_key(rec), build(rec)) if rec else (None, "JSON value is not a Kubernetes audit event")


def from_ocsf(r):
    rec = ocsf.to_k8s_audit(r)
    if not rec.get("auditID"):
        return None, "Security Lake EKS record without an audit ID"
    doc = build(rec)
    set_field(doc, "cloud.account.id", ocsf.account_of(r))
    set_field(doc, "cloud.region", ocsf.region_of(r))
    return record_key(rec), doc


def detect(path, head):
    h = head[:65536].replace('\\"', '"')  # also inside CloudWatch "message" strings
    if '"auditID"' in h and ('"audit.k8s.io' in h or ('"verb"' in h and '"stage"' in h)):
        return True
    first = first_line(h)
    return looks_like_csv_header(first, ["auditid", ("verb", "stage")]) or \
        (looks_like_csv_header(first, ["message"]) and "auditID" in h)


LOG = AwsLog(
    prefix="kubernetes", namespace="k8s", title="Amazon EKS audit", dataset="aws.eks_audit",
    detect=detect, parse=parse, use_occurrence=False, index_template=False, ocsf=("eks", from_ocsf),
    describe=[
        "EKS audit logs exported from CloudWatch Logs (kube-apiserver-audit streams): JSON per line, .gz fine",
        "`aws logs filter-log-events` output, JSON arrays, Kubernetes EventList objects",
        "Amazon Security Lake exports (OCSF API Activity 6003 from Amazon EKS): JSON or Athena CSV",
        "CSV: a whole-event JSON column (@message), or flattened columns (objectRef.resource, ...)",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load Amazon EKS audit logs into SOF-ELK (index kubernetes-<source>)"))
