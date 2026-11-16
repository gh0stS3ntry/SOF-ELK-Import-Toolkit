#!/usr/bin/env python3
"""Load AWS Security Hub findings (ASFF) into SOF-ELK as aws-securityhub-<source>.

SOF-ELK has no Security Hub parser, so this importer defines the schema
(index-aws-securityhub.json), in the style of the other AWS indexes: ECS where a field exists,
aws.securityhub.* for the rest. One document per finding version: a finding that Security Hub
updated (new UpdatedAt) is a new document, so its history is kept; loading the same files again
overwrites instead of duplicating.

  UpdatedAt (else CreatedAt)          -> @timestamp; CreatedAt -> event.created
  Title / Description                 -> message, aws.securityhub.title / description
  Id, ProductArn, ProductName,        -> aws.securityhub.id, product_arn, product_name,
    CompanyName, GeneratorId, Types      company_name, generator_id, types
  Severity.Label / Normalized         -> aws.securityhub.severity.label / normalized, event.severity
  Compliance.Status / SecurityControlId, Workflow.Status, RecordState, VerificationState
                                      -> aws.securityhub.compliance.*, workflow_status, record_state, ...
  FirstObservedAt / LastObservedAt    -> aws.securityhub.first_observed_at / last_observed_at
  Resources[].Id / Type / Region      -> aws.securityhub.resource.id / type / region (lists)
  Network                             -> source.ip/port, destination.ip/port, network.direction/transport
  Process                             -> process.name, process.executable, process.pid
  Malware[].Name, ThreatIntelIndicators[].Value
                                      -> aws.securityhub.malware_names, threat_intel_values
  Remediation.Recommendation          -> aws.securityhub.remediation.text / url
  AwsAccountId / Region               -> cloud.account.id / cloud.region
Whole objects (Resources, ProductFields, Network, Action, UserDefinedFields, ...) are kept as
JSON text under aws.securityhub.flattened.*; other top-level fields go to aws.securityhub.unmapped.*.

Inputs (plain or .gz, any file name):
  * `aws securityhub get-findings` output ({"Findings": [...]}), EventBridge events
    ({"detail": {"findings": [...]}}), a JSON array of findings, or one finding per line;
  * Amazon Security Lake exports (OCSF Security Finding 2001 / Detection, Vulnerability and
    Compliance Finding 2002-2004): JSON or Athena CSV;
  * CSV: a column holding the whole finding as JSON, or flattened columns (Severity.Label, ...).

Example:
  python3 AWS/securityhub2sofelk.py /cases/IR-42/securityhub --source 123456789012 --dry-run
"""
import json
import sys

from sof_elk_aws_common import (AwsLog, canon, compact_json, csv_records, dig, first_line, iso,
                                iter_json, looks_like_csv_header, run, set_field, snake, to_float,
                                to_int, valid_ip)
import sof_elk_ocsf as ocsf

NATIVE_KEYS = [
    "SchemaVersion", "Id", "ProductArn", "ProductName", "CompanyName", "Region", "GeneratorId",
    "AwsAccountId", "AwsAccountName", "Types", "FirstObservedAt", "LastObservedAt", "CreatedAt",
    "UpdatedAt", "Severity", "Label", "Normalized", "Original", "Product", "Confidence",
    "Criticality", "Title", "Description", "Remediation", "Recommendation", "Text", "Url",
    "SourceUrl", "ProductFields", "UserDefinedFields", "Malware", "Network", "Process",
    "ThreatIntelIndicators", "Resources", "Compliance", "Status", "SecurityControlId",
    "VerificationState", "WorkflowState", "Workflow", "RecordState", "Action", "Vulnerabilities",
    "FindingProviderFields", "Sample", "GeneratorDetails", "ProcessedAt", "AwsAccountName",
    "Id", "Type", "Partition", "Details", "Tags", "Direction", "Protocol", "SourceIpV4",
    "SourceIpV6", "SourcePort", "DestinationIpV4", "DestinationIpV6", "DestinationPort",
    "Name", "Path", "Pid", "ParentPid", "Value",
]
CSV_NAMES = {canon(k): k for k in NATIVE_KEYS}
KEEP_CASE = ("ProductFields", "UserDefinedFields", "Details", "Tags")
KNOWN = {"SchemaVersion", "Id", "ProductArn", "ProductName", "CompanyName", "Region", "GeneratorId",
         "AwsAccountId", "AwsAccountName", "Types", "FirstObservedAt", "LastObservedAt", "CreatedAt",
         "UpdatedAt", "Severity", "Title", "Description", "Remediation", "SourceUrl", "ProductFields",
         "UserDefinedFields", "Malware", "Network", "Process", "ThreatIntelIndicators", "Resources",
         "Compliance", "VerificationState", "WorkflowState", "Workflow", "RecordState", "Action",
         "Vulnerabilities", "FindingProviderFields", "Confidence", "Criticality", "ProcessedAt"}
LABEL_SCORE = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}


def text(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return compact_json(value)
    return str(value)


def as_list(value):
    if isinstance(value, list):
        return value
    return [] if value in (None, "") else [value]


def build(rec):
    doc, malformed = {}, []
    sh = "aws.securityhub."
    updated, created = iso(text(rec.get("UpdatedAt"))), iso(text(rec.get("CreatedAt")))
    if updated or created:
        doc["@timestamp"] = updated or created
    for key in ("UpdatedAt", "CreatedAt", "FirstObservedAt", "LastObservedAt", "ProcessedAt"):
        value = rec.get(key)
        stamp = iso(text(value))
        if value and not stamp:
            malformed.append(f"{key}={value}")
        set_field(doc, sh + snake(key), stamp)
    set_field(doc, "event.created", created)
    for src in ("Id", "ProductArn", "ProductName", "CompanyName", "GeneratorId", "SchemaVersion",
                "RecordState", "VerificationState", "WorkflowState", "SourceUrl", "AwsAccountName"):
        set_field(doc, sh + snake(src), text(rec.get(src)))
    set_field(doc, sh + "types", [text(t) for t in as_list(rec.get("Types")) if t])
    title = text(rec.get("Title"))
    set_field(doc, sh + "title", title)
    set_field(doc, sh + "description", text(rec.get("Description")))
    set_field(doc, "message", title)
    sev = rec.get("Severity") if isinstance(rec.get("Severity"), dict) else {}
    label = text(sev.get("Label"))
    normalized = to_int(sev.get("Normalized"))
    if normalized is None and to_float(sev.get("Normalized")) is not None:
        normalized = int(to_float(sev.get("Normalized")))
    set_field(doc, sh + "severity.label", label.upper() if label else None)
    set_field(doc, sh + "severity.normalized", normalized)
    set_field(doc, sh + "severity.original", text(sev.get("Original")))
    set_field(doc, "event.severity", normalized if normalized is not None else LABEL_SCORE.get((label or "").upper()))
    set_field(doc, sh + "confidence", to_int(rec.get("Confidence")))
    set_field(doc, sh + "criticality", to_int(rec.get("Criticality")))
    comp = rec.get("Compliance") if isinstance(rec.get("Compliance"), dict) else {}
    set_field(doc, sh + "compliance.status", text(comp.get("Status")))
    set_field(doc, sh + "compliance.security_control_id", text(comp.get("SecurityControlId")))
    set_field(doc, sh + "workflow_status", text(dig(rec, "Workflow", "Status")))
    rem = dig(rec, "Remediation", "Recommendation") or {}
    if isinstance(rem, dict):
        set_field(doc, sh + "remediation.text", text(rem.get("Text")))
        set_field(doc, sh + "remediation.url", text(rem.get("Url")))
    account = text(rec.get("AwsAccountId"))
    set_field(doc, "cloud.account.id", account)
    set_field(doc, "cloud.region", text(rec.get("Region")))

    resources = [r for r in as_list(rec.get("Resources")) if isinstance(r, dict)]
    for src, dst in (("Id", "id"), ("Type", "type"), ("Region", "region"), ("Partition", "partition")):
        values = [text(r.get(src)) for r in resources if r.get(src)]
        set_field(doc, sh + "resource." + dst, values)

    net = rec.get("Network") if isinstance(rec.get("Network"), dict) else {}
    set_field(doc, "source.ip", valid_ip(text(net.get("SourceIpV4") or net.get("SourceIpV6"))))
    set_field(doc, "source.port", to_int(net.get("SourcePort")))
    set_field(doc, "source.domain", text(net.get("SourceDomain")))
    set_field(doc, "destination.ip", valid_ip(text(net.get("DestinationIpV4") or net.get("DestinationIpV6"))))
    set_field(doc, "destination.port", to_int(net.get("DestinationPort")))
    set_field(doc, "destination.domain", text(net.get("DestinationDomain")))
    direction = text(net.get("Direction"))
    set_field(doc, "network.direction", {"IN": "ingress", "OUT": "egress"}.get((direction or "").upper(), direction))
    proto = text(net.get("Protocol"))
    set_field(doc, "network.transport", proto.lower() if proto else None)
    proc = rec.get("Process") if isinstance(rec.get("Process"), dict) else {}
    set_field(doc, "process.name", text(proc.get("Name")))
    set_field(doc, "process.executable", text(proc.get("Path")))
    set_field(doc, "process.pid", to_int(proc.get("Pid")))
    set_field(doc, "process.parent.pid", to_int(proc.get("ParentPid")))
    set_field(doc, sh + "malware_names",
              [text(m.get("Name")) for m in as_list(rec.get("Malware")) if isinstance(m, dict) and m.get("Name")])
    set_field(doc, sh + "threat_intel_values",
              [text(t.get("Value")) for t in as_list(rec.get("ThreatIntelIndicators"))
               if isinstance(t, dict) and t.get("Value")])
    vulns = [v for v in as_list(rec.get("Vulnerabilities")) if isinstance(v, dict)]
    set_field(doc, "vulnerability.id", [text(v.get("Id")) for v in vulns if v.get("Id")])

    for src in ("Resources", "ProductFields", "UserDefinedFields", "Network", "Process", "Malware",
                "ThreatIntelIndicators", "Action", "Vulnerabilities", "FindingProviderFields"):
        set_field(doc, sh + "flattened." + snake(src), compact_json(rec.get(src)))

    doc["event"] = {**doc.get("event", {}), "dataset": "aws.securityhub", "kind": "alert"}
    set_field(doc, "event.action", text(as_list(rec.get("Types"))[0]) if as_list(rec.get("Types")) else None)
    if (text(comp.get("Status")) or "").upper() in ("PASSED", "FAILED"):
        doc["event"]["outcome"] = "success" if comp["Status"].upper() == "PASSED" else "failure"
    for key, value in rec.items():
        if key not in KNOWN and value not in (None, "", {}, []):
            set_field(doc, sh + "unmapped." + snake(key), text(value))
    if malformed:
        set_field(doc, sh + "malformed", malformed)
    return doc


def is_record(obj):
    return isinstance(obj, dict) and "Id" in obj and ("ProductArn" in obj or "SchemaVersion" in obj
                                                      or "GeneratorId" in obj)


def records(obj):
    if isinstance(obj, list):
        for item in obj:
            yield from records(item)
    elif isinstance(obj, dict):
        findings = obj.get("Findings") or obj.get("findings") or dig(obj, "detail", "findings")
        if isinstance(findings, list):
            yield from records(findings)
        elif is_record(obj):
            yield obj
        else:
            yield None
    else:
        yield None


def record_key(rec):
    return json.dumps([rec.get("ProductArn"), rec.get("Id"), rec.get("UpdatedAt")])


class _Text:
    def __init__(self, value):
        self.value = value

    def read(self, _size=-1):
        value, self.value = self.value, ""
        return value


def is_csv_header(line):
    return looks_like_csv_header(line, [("id", "message", "raw", "event", "json", "finding"),
                                        ("productarn", "title", "message", "raw", "event", "json", "finding")])


def parse(fh, ctx):
    head = fh.read(1 << 16)
    if is_csv_header(first_line(head)):
        for kind, value in csv_records(fh, CSV_NAMES, keep_case=KEEP_CASE, head=head.lstrip("﻿")):
            objs = list(iter_json(_Text(value))) if kind == "json" else [value]
            for obj in objs:
                for rec in records(obj):
                    yield (record_key(rec), build(rec)) if rec else (None, "CSV row that is not a finding")
        return
    for obj in iter_json(fh, head):
        for rec in records(obj):
            yield (record_key(rec), build(rec)) if rec else (None, "JSON value is not a Security Hub finding")


def from_ocsf(r):
    rec = ocsf.to_securityhub(r)
    if not rec.get("Id"):
        return None, "Security Lake finding without finding_info.uid"
    return record_key(rec), build(rec)


def detect(path, head):
    h = head[:65536].replace('\\"', '"')  # also inside CloudWatch "message" strings
    if ('"Findings"' in h or '"findings"' in h or '"SchemaVersion"' in h) and '"ProductArn"' in h \
            and '"GeneratorId"' in h:
        return True
    first = first_line(h)
    return looks_like_csv_header(first, ["productarn", "generatorid", ("title", "severity", "label")]) or \
        (looks_like_csv_header(first, [("message", "finding", "raw")]) and '"ProductArn' in h.replace('""', '"'))


LOG = AwsLog(
    prefix="aws-securityhub", namespace="aws.securityhub", title="AWS Security Hub finding",
    dataset="aws.securityhub", detect=detect, parse=parse, use_occurrence=False,
    ocsf=("securityhub", from_ocsf),
    describe=[
        "`aws securityhub get-findings` output, EventBridge finding events, JSON arrays or JSON Lines (.gz fine)",
        "Amazon Security Lake exports (OCSF Security/Detection/Vulnerability/Compliance Finding): JSON or Athena CSV",
        "CSV: a whole-finding JSON column, or flattened columns (Severity.Label, Resources.0.Id, ...)",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load AWS Security Hub findings into SOF-ELK (index aws-securityhub-<source>)"))
