#!/usr/bin/env python3
"""Load AWS CloudTrail logs into SOF-ELK as aws-cloudtrail-<source>.

Field names follow SOF-ELK's own CloudTrail parser (configfiles/6901-aws.conf): eventName ->
aws.cloudtrail.event_name, sourceIPAddress -> source.address (+ source.ip when it is an IP),
userIdentity.userName -> user.name, awsRegion -> cloud.region, requestParameters /
responseElements / additionalEventData -> aws.cloudtrail.flattened.* as JSON text, and so on.
On top of that it keeps fields SOF-ELK drops that hunting needs: the session issuer of an
assumed role, MFA flags, recipient account, read-only/management flags, TLS details, a
curated set of request/response parameters, every resource ARN, and event.outcome.

Inputs (plain or .gz, any file name):
  * CloudTrail S3 delivery files: {"Records": [...]}
  * Event history "Download events" JSON ({"Records": [...]})
  * JSON Lines, one event per line (SOF-ELK's aws-cloudtrail2sof-elk.py output, CloudTrail Lake
    or Athena exports), optionally prefixed with a timestamp (CloudWatch Logs export to S3)
  * a JSON array of events, or `aws logs filter-log-events` output ({"events": [{"message": ...}]})
  * CSV (comma, tab, semicolon or pipe separated), when the logs were already converted:
      - Event history CSV download; with the "CloudTrail event" column every field is kept,
        without it the summary columns are used (Event name, Event time, User name, AWS access
        key, Source IP address, AWS region, Error code, Event source, Read-only, Event ID)
      - Athena / CloudTrail Lake query results (eventtime, useridentity as a struct
        "{type=IAMUser, arn=...}" or JSON, requestparameters as JSON text, ...)
      - flattened exports with dotted columns (userIdentity.arn, userIdentity.sessionContext.
        sessionIssuer.userName, ...), or a column holding the whole event as JSON
        (CloudWatch Logs Insights "@message", "_raw", ...)
CloudTrail digest files are recognised and skipped.

Example:
  python3 AWS/cloudtrail2sofelk.py /cases/IR-42/cloudtrail --source 123456789012 --dry-run
  python3 AWS/cloudtrail2sofelk.py /cases/IR-42/cloudtrail --source 123456789012 --es http://sof-elk:9200
"""
import json
import re
import sys

from sof_elk_aws_common import (AwsLog, canon, compact_json, csv_records, dig, iso,
                                looks_like_csv_header, run, set_field, snake, to_bool, to_int,
                                valid_ip)

# requestParameters keys copied to aws.cloudtrail.request_parameters.<snake_case> (keyword).
# Everything else stays searchable in aws.cloudtrail.flattened.request_parameters.
REQUEST_KEYS = {
    "bucketName", "key", "instanceType", "instanceId", "imageId", "keyName", "userName",
    "roleName", "roleArn", "roleSessionName", "groupName", "groupId", "policyArn", "policyName",
    "name", "trailName", "secretId", "keyId", "functionName", "snapshotId", "attribute",
    "operationType", "dBInstanceIdentifier", "dBSnapshotIdentifier", "detectorId",
    "logGroupName", "accessKeyId", "status", "principalArn", "instanceProfileName",
    "serialNumber", "durationSeconds", "sourceIdentity", "externalId", "cidrIp", "fromPort",
    "toPort", "ipProtocol", "vpcId", "subnetId", "regionName", "documentName", "target",
    "stackName", "cluster", "taskDefinition", "projectName", "withDecryption", "attributeType",
}
# camelCase keys whose snake_case form needs a fix-up
REQUEST_FIELD = {"dBInstanceIdentifier": "db_instance_identifier",
                 "dBSnapshotIdentifier": "db_snapshot_identifier"}
# Native spelling of every record key, so CSV columns in any case ("useridentity",
# "userIdentity.sessionContext.sessionIssuer.userName", "EventName") map back to it.
NATIVE_KEYS = [
    "eventVersion", "eventTime", "eventSource", "eventName", "awsRegion", "sourceIPAddress",
    "userAgent", "requestParameters", "responseElements", "additionalEventData", "requestID",
    "eventID", "eventType", "readOnly", "managementEvent", "recipientAccountId", "eventCategory",
    "errorCode", "errorMessage", "vpcEndpointId", "serviceEventDetails", "resources", "tlsDetails",
    "sharedEventID", "apiVersion", "sessionCredentialFromConsole",
    "userIdentity", "type", "arn", "accessKeyId", "accountId", "principalId", "invokedBy",
    "userName", "sessionContext", "sessionIssuer", "attributes", "mfaAuthenticated",
    "creationDate", "sourceIdentity", "webIdFederationData", "identityProvider",
    "tlsVersion", "cipherSuite", "clientProvidedHostHeader",
]
CSV_NAMES = {canon(k): k for k in NATIVE_KEYS}
CSV_KEEP_CASE = ("requestParameters", "responseElements", "additionalEventData", "serviceEventDetails")
# Event history CSV summary columns (the console download without "CloudTrail event")
CSV_ALIASES = {
    "eventtime": ("eventTime",), "eventname": ("eventName",), "eventsource": ("eventSource",),
    "eventid": ("eventID",), "username": ("userIdentity", "userName"),
    "awsaccesskey": ("userIdentity", "accessKeyId"), "sourceipaddress": ("sourceIPAddress",),
    "awsregion": ("awsRegion",), "errorcode": ("errorCode",), "readonly": ("readOnly",),
    "useridentityarn": ("userIdentity", "arn"),
}

TS_PREFIX_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s+(?=[{\[])")


def scalar_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def request_parameters(doc, params):
    if not isinstance(params, dict):
        return
    for key in REQUEST_KEYS:
        text = scalar_text(params.get(key))
        if text is not None:
            set_field(doc, "aws.cloudtrail.request_parameters." + REQUEST_FIELD.get(key, snake(key)), text)
    # SSM SendCommand and similar: instanceIds is a list
    ids = params.get("instanceIds")
    if isinstance(ids, list) and not dig(doc, "aws", "cloudtrail", "request_parameters", "instance_id"):
        ids = [i for i in ids if isinstance(i, str)]
        set_field(doc, "aws.cloudtrail.request_parameters.instance_id", ids if len(ids) > 1 else (ids[0] if ids else None))
    # SOF-ELK: requestParameters.Host (S3 data events) -> host.hostname
    set_field(doc, "host.hostname", scalar_text(params.get("Host")))
    # SOF-ELK takes the first instancesSet item; keep them all (RunInstances can start many)
    items = dig(params, "instancesSet", "items") or []
    if isinstance(items, list):
        for src, dst in (("instanceId", "instance_id"), ("imageId", "image_id"), ("keyName", "key_name")):
            values = [i[src] for i in items if isinstance(i, dict) and isinstance(i.get(src), str)]
            if values and not dig(doc, "aws", "cloudtrail", "request_parameters", dst):
                set_field(doc, f"aws.cloudtrail.request_parameters.{dst}", values if len(values) > 1 else values[0])
    # CreateSecurityGroupIngress style: the CIDRs opened
    cidrs = []
    for perm in dig(params, "ipPermissions", "items") or []:
        for rng in dig(perm, "ipRanges", "items") or []:
            if isinstance(rng, dict) and rng.get("cidrIp"):
                cidrs.append(rng["cidrIp"])
        for rng in dig(perm, "ipv6Ranges", "items") or []:
            if isinstance(rng, dict) and rng.get("cidrIpv6"):
                cidrs.append(rng["cidrIpv6"])
    if cidrs and not dig(doc, "aws", "cloudtrail", "request_parameters", "cidr_ip"):
        set_field(doc, "aws.cloudtrail.request_parameters.cidr_ip", sorted(set(cidrs)))
    groups = dig(params, "groupSet", "items") or dig(params, "securityGroupIdSet", "items") or []
    if isinstance(groups, list):
        ids = [g.get("groupId") for g in groups if isinstance(g, dict) and g.get("groupId")]
        set_field(doc, "aws.cloudtrail.request_parameters.security_group_ids", ids)
    set_field(doc, "aws.cloudtrail.request_parameters.target_user_name",
              scalar_text(params.get("newUserName")))


def response_elements(doc, resp):
    if not isinstance(resp, dict):
        return
    set_field(doc, "aws.cloudtrail.console_login", scalar_text(resp.get("ConsoleLogin")))
    set_field(doc, "aws.cloudtrail.response_elements.access_key_id",
              dig(resp, "accessKey", "accessKeyId") or dig(resp, "credentials", "accessKeyId"))
    set_field(doc, "aws.cloudtrail.response_elements.assumed_role_arn", dig(resp, "assumedRoleUser", "arn"))
    set_field(doc, "aws.cloudtrail.response_elements.user_arn", dig(resp, "user", "arn"))
    items = dig(resp, "instancesSet", "items") or []
    if isinstance(items, list):
        ids = [i.get("instanceId") for i in items if isinstance(i, dict) and i.get("instanceId")]
        set_field(doc, "aws.cloudtrail.response_elements.instance_id", ids if len(ids) > 1 else (ids[0] if ids else None))


def build(rec):
    """One CloudTrail record -> document (SOF-ELK 6901-aws.conf names first)."""
    doc, malformed = {}, []
    ts = iso(rec.get("eventTime"))
    if ts:
        doc["@timestamp"] = ts
    elif rec.get("eventTime"):
        malformed.append(f"eventTime={rec.get('eventTime')}")
    uid = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    ct = "aws.cloudtrail."
    for src, dst in (("eventName", ct + "event_name"), ("eventSource", ct + "event_source"),
                     ("requestID", ct + "request_id"), ("eventID", ct + "shared_event_id"),
                     ("eventType", ct + "event_type"), ("eventVersion", ct + "event_version"),
                     ("eventCategory", ct + "event_category"), ("errorCode", ct + "error_code"),
                     ("errorMessage", ct + "error_message"), ("vpcEndpointId", ct + "vpc_endpoint_id"),
                     ("recipientAccountId", ct + "recipient_account_id"),
                     ("awsRegion", "cloud.region"), ("userAgent", "user_agent.original")):
        set_field(doc, dst, scalar_text(rec.get(src)))
    set_field(doc, "cloud.account.id", scalar_text(rec.get("recipientAccountId")))
    for src, dst in (("readOnly", "read_only"), ("managementEvent", "management_event")):
        set_field(doc, ct + dst, to_bool(rec.get(src)))

    source = scalar_text(rec.get("sourceIPAddress"))
    set_field(doc, "source.address", source)
    set_field(doc, "source.ip", valid_ip(source))

    # userIdentity
    for src, dst in (("type", "type"), ("arn", "arn"), ("accessKeyId", "access_key_id"),
                     ("accountId", "account_id"), ("principalId", "principal_id"),
                     ("invokedBy", "invoked_by"), ("userName", "user_name")):
        set_field(doc, ct + "user_identity." + dst, scalar_text(uid.get(src)))
    set_field(doc, "user.name", scalar_text(uid.get("userName")))
    sc = uid.get("sessionContext") if isinstance(uid.get("sessionContext"), dict) else {}
    set_field(doc, ct + "user_identity.session_context", compact_json(sc))
    issuer = sc.get("sessionIssuer") if isinstance(sc.get("sessionIssuer"), dict) else {}
    for src, dst in (("type", "type"), ("arn", "arn"), ("userName", "user_name"),
                     ("accountId", "account_id"), ("principalId", "principal_id")):
        set_field(doc, ct + "user_identity.session_issuer." + dst, scalar_text(issuer.get(src)))
    set_field(doc, ct + "user_identity.mfa_authenticated", to_bool(dig(sc, "attributes", "mfaAuthenticated")))
    created = dig(sc, "attributes", "creationDate")
    set_field(doc, ct + "user_identity.session_created", iso(created) if isinstance(created, str) else None)
    set_field(doc, ct + "user_identity.source_identity", scalar_text(sc.get("sourceIdentity")))

    # parameters: curated fields + the whole object as JSON text (SOF-ELK's flattened.*)
    params, resp, extra = rec.get("requestParameters"), rec.get("responseElements"), rec.get("additionalEventData")
    request_parameters(doc, params)
    response_elements(doc, resp)
    if isinstance(extra, dict):
        set_field(doc, "source.bytes", to_int(extra.get("bytesTransferredIn")))
        set_field(doc, "destination.bytes", to_int(extra.get("bytesTransferredOut")))
        for src, dst in (("MFAUsed", "mfa_used"), ("LoginTo", "login_to"), ("CredentialType", "credential_type")):
            set_field(doc, ct + "additional_eventdata." + dst, scalar_text(extra.get(src)))
    set_field(doc, ct + "flattened.request_parameters", compact_json(params))
    set_field(doc, ct + "flattened.response_elements", compact_json(resp))
    set_field(doc, ct + "flattened.additional_eventdata", compact_json(extra))
    set_field(doc, ct + "flattened.service_event_details", compact_json(rec.get("serviceEventDetails")))

    resources = rec.get("resources") if isinstance(rec.get("resources"), list) else []
    for src, dst in (("ARN", "arn"), ("type", "type"), ("accountId", "account_id")):
        values = [r.get(src) or r.get(src.lower()) for r in resources if isinstance(r, dict)]
        values = [v for v in values if isinstance(v, str)]
        set_field(doc, ct + "resources." + dst, values if len(values) > 1 else (values[0] if values else None))

    tls = rec.get("tlsDetails") if isinstance(rec.get("tlsDetails"), dict) else {}
    for src, dst in (("tlsVersion", "tls_version"), ("cipherSuite", "cipher_suite"),
                     ("clientProvidedHostHeader", "client_provided_host_header")):
        set_field(doc, ct + "tls_details." + dst, scalar_text(tls.get(src)))

    failed = bool(rec.get("errorCode")) or dig(doc, "aws", "cloudtrail", "console_login") == "Failure"
    doc["event"] = {"dataset": "aws.cloudtrail", "kind": "event",
                    "outcome": "failure" if failed else "success"}
    set_field(doc, "event.action", scalar_text(rec.get("eventName")))

    known = {"eventTime", "eventName", "eventSource", "requestID", "eventID", "eventType",
             "eventVersion", "eventCategory", "errorCode", "errorMessage", "vpcEndpointId",
             "recipientAccountId", "awsRegion", "userAgent", "readOnly", "managementEvent",
             "sourceIPAddress", "userIdentity", "requestParameters", "responseElements",
             "additionalEventData", "serviceEventDetails", "resources", "tlsDetails"}
    for key, value in rec.items():
        if key not in known and value not in (None, "", {}, []):
            text = scalar_text(value) if not isinstance(value, (dict, list)) else compact_json(value)
            set_field(doc, f"{ct}unmapped.{snake(key)}", text)
    if malformed:
        set_field(doc, ct + "malformed", malformed)
    return doc


def is_record(obj):
    return isinstance(obj, dict) and ("eventName" in obj or "eventID" in obj) and "eventTime" in obj


def records_from(obj, ctx):
    """CloudTrail records inside one decoded JSON value."""
    if isinstance(obj, list):
        for item in obj:
            yield from records_from(item, ctx)
    elif isinstance(obj, dict):
        if isinstance(obj.get("Records"), list):
            yield from records_from(obj["Records"], ctx)
        elif isinstance(obj.get("events"), list):  # aws logs filter-log-events output
            for ev in obj["events"]:
                msg = ev.get("message") if isinstance(ev, dict) else None
                try:
                    yield from records_from(json.loads(msg), ctx) if isinstance(msg, str) else ()
                except ValueError:
                    yield None
        elif "digestStartTime" in obj or "digestPublicKeyFingerprint" in obj:
            return  # digest file
        elif is_record(obj):
            yield obj
        else:
            yield None
    else:
        yield None


def parse(fh, ctx):
    head = fh.read(1 << 16)
    if looks_like_csv_header(head.split("\n", 1)[0], [("eventname", "eventid", "cloudtrailevent", "message")]):
        yield from parse_csv(head, fh)
        return
    first_line = head.split("\n", 1)[0]
    stripped = TS_PREFIX_RE.sub("", first_line).strip()
    line_mode = False
    if stripped:
        try:
            json.loads(stripped)
            line_mode = "\n" in head.strip()  # one JSON value per line (JSON Lines)
        except ValueError:
            line_mode = False
    if line_mode:
        buffer = head
        while True:
            *lines, buffer = buffer.split("\n")
            for line in lines:
                yield from parse_line(line)
            more = fh.read(1 << 20)
            if not more:
                break
            buffer += more
        yield from parse_line(buffer)
        return
    text = head + fh.read()
    try:
        obj = json.loads(text)
    except ValueError as exc:
        if exc.msg == "Extra data":  # JSON Lines whose first line is very long
            for line in text.split("\n"):
                yield from parse_line(line)
        else:
            yield None, f"not valid JSON ({exc.msg})"
        return
    if isinstance(obj, dict) and ("digestStartTime" in obj or "digestPublicKeyFingerprint" in obj):
        yield None, "CloudTrail digest file (not events)"
        return
    for rec in records_from(obj, ctx):
        yield (rec.get("eventID") or compact_json(rec), build(rec)) if rec else (None, "JSON value is not a CloudTrail record")


def parse_line(line):
    line = TS_PREFIX_RE.sub("", line).strip()
    if not line:
        return
    try:
        obj = json.loads(line)
    except ValueError:
        yield None, "line is not valid JSON"
        return
    for rec in records_from(obj, None):
        yield (rec.get("eventID") or compact_json(rec), build(rec)) if rec else (None, "JSON value is not a CloudTrail record")


def parse_csv(head, fh):
    """CloudTrail already converted to CSV (Event history download, Athena, flattened exports)."""
    for kind, value in csv_records(fh, CSV_NAMES, CSV_ALIASES, CSV_KEEP_CASE, head=head):
        if kind == "json":
            yield from parse_line(value)
            continue
        for key in CSV_KEEP_CASE:  # Athena returns these as JSON text, which decode_cell parsed
            if isinstance(value.get(key), str):
                try:
                    value[key] = json.loads(value[key])
                except ValueError:
                    pass
        if is_record(value):
            yield value.get("eventID") or compact_json(value), build(value)
        else:
            yield None, "CSV row without an event name/ID and event time"


def detect(path, head):
    name = path.name
    if "CloudTrail-Digest" in name:
        return False
    if "_CloudTrail_" in name or "CloudTrail-Insight" in name:
        return True
    h = head[:65536]
    if '"eventVersion"' in h and '"eventSource"' in h and '"eventName"' in h:
        return True
    first = h.split("\n", 1)[0]
    return looks_like_csv_header(first, [("eventname", "cloudtrailevent"), ("eventtime", "cloudtrailevent")]) or \
        (looks_like_csv_header(first, ["message"]) and "eventSource" in h)


LOG = AwsLog(
    prefix="aws-cloudtrail", namespace="aws.cloudtrail", title="AWS CloudTrail",
    dataset="aws.cloudtrail", detect=detect, parse=parse, use_occurrence=False,
    describe=[
        "CloudTrail S3 delivery files ({\"Records\": [...]}, .json or .json.gz)",
        "Event history download: JSON, or CSV (with or without the 'CloudTrail event' column)",
        "CSV conversions: Athena/CloudTrail Lake results, flattened (userIdentity.arn) or raw-JSON column",
        "JSON Lines (one event per line), optionally timestamp-prefixed (CloudWatch Logs export)",
        "JSON array of events; `aws logs filter-log-events` output",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load AWS CloudTrail logs into SOF-ELK (index aws-cloudtrail-<source>)"))
