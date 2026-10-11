#!/usr/bin/env python3
"""Stream EvtxECmd JSON records into a per-host SOF-ELK-compatible evtxlogs index."""
import argparse
import ipaddress
import json
import re
import sys
from sof_elk_json_bulk_common import add_common_arguments, add_tag, base_event, copy_renames, parse_timestamp, run_import, set_nested

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")


INDEX_PREFIX = "evtxlogs"
LABEL_TYPE = "kape_evtxlogs"
PATTERNS = ("*_EvtxECmd_Output.json", "*_EvtxECmd_Output.json.gz")
EXCLUDES = ()
RENAMES = {
    "Level": "kape.log_level", "MapDescription": "kape.map_description", "ExecutableInfo": "kape.executable_info",
    "Computer": "winlog.computer_name", "RemoteHost": "winlog.remote_host", "UserId": "winlog.user.identifer",
    "UserName": "winlog.user.name", "Channel": "winlog.channel", "Provider": "winlog.provider_name",
    "EventId": "winlog.event_id", "ProcessId": "winlog.process.pid", "ThreadId": "winlog.process.thread.id",
    "SourceFile": "file.source_file", "TimeCreated": "winlog.time_created", "RecordNumber": "winlog.record_id",
    "Keywords": "winlog.keywords",
}
PAYLOAD_ROOT_RENAMES = {
    "ActionName": "winlog.event_data.ActionName", "EnginePID": "winlog.event_data.EnginePid",
    "InstanceId": "winlog.event_data.InstanceId", "Path": "winlog.event_data.Path", "Priority": "winlog.event_data.Priority",
    "ProcessId": "winlog.event_data.ProcessId", "QueuedTaskInstanceId": "winlog.event_data.QueuedTaskInstanceId",
    "ResultCode": "winlog.event_data.ResultCode", "RunningTaskInstanceId": "winlog.event_data.RunningTaskInstanceId",
    "TaskInstanceId": "winlog.event_data.TaskInstanceId", "TaskName": "winlog.event_data.TaskName",
    "UserContext": "winlog.event_data.UserContext", "UserName": "winlog.event_data.UserName",
}
MAPPINGS = {
    "@timestamp": {"type": "date"}, "labels.type": {"type": "keyword"}, "tags": {"type": "keyword"},
    "log.file.path": {"type": "keyword"}, "sof-elk.path": {"type": "keyword"},
    "winlog.time_created": {"type": "date"}, "remote.port": {"type": "keyword"},
}


def get_nested(doc, dotted):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def nonempty(value):
    return value is not None and value != ""


def payload_data_fields(data):
    """Mirror split_kv_to_fields.rb for EventData.Data."""
    out = {}
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and "#text" in item and item.get("#text") != "" and item.get("@Name") is not None:
            out[str(item["@Name"])] = item["#text"]
    return out


def parse_remote_host(doc):
    value = get_nested(doc, "winlog.remote_host")
    if not isinstance(value, str) or not value:
        return
    ip_text, port_text = value, None
    # IPv4:port and [IPv6]:port. Bare IPv6 is retained in remote_host only.
    if value.startswith("[") and "]" in value:
        close = value.find("]")
        ip_text = value[1:close]
        suffix = value[close + 1:]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port_text = suffix[1:]
    elif value.count(":") == 1:
        maybe_ip, maybe_port = value.rsplit(":", 1)
        if maybe_port.isdigit():
            ip_text, port_text = maybe_ip, maybe_port
    try:
        ipaddress.ip_address(ip_text)
        set_nested(doc, "remote.ip", ip_text)
        if port_text is not None:
            set_nested(doc, "remote.port", port_text)
    except ValueError:
        return


def transform(raw, source_path, hostname, label_type, ingest_time):
    if not isinstance(raw, dict):
        raise ValueError("EvtxECmd JSON records must be objects")
    doc = base_event(raw, source_path, hostname, label_type, ingest_time)
    copy_renames(raw, doc, RENAMES)

    payload = raw.get("Payload")
    parsed_payload = None
    if nonempty(payload):
        if isinstance(payload, dict):
            parsed_payload = payload
        elif isinstance(payload, str):
            try:
                parsed_payload = json.loads(payload)
            except ValueError:
                add_tag(doc, "_jsonparsefailure")

    if isinstance(parsed_payload, dict):
        event_data = parsed_payload.get("EventData")
        if isinstance(event_data, dict):
            data = event_data.get("Data")
            if nonempty(data):
                # Logstash converts named Data items into individual event_data fields.
                if isinstance(data, (dict, list)) and (
                    (isinstance(data, dict) and "@Name" in data) or
                    (isinstance(data, list) and data and isinstance(data[0], dict) and "@Name" in data[0])
                ):
                    for name, value in payload_data_fields(data).items():
                        event_data_out = doc.setdefault("winlog", {}).setdefault("payload", {}).setdefault("event_data", {})
                        event_data_out[name] = value
                elif isinstance(data, str):
                    parts = data.split(", ")
                    set_nested(doc, "winlog.payload.event_data.string", parts)
                else:
                    # This mirrors the string fallback for inconsistent payload shapes.
                    set_nested(doc, "winlog.payload.event_data.string", data)
            binary = event_data.get("Binary")
            if nonempty(binary):
                set_nested(doc, "winlog.payload.event_data.binary", binary)
        user_data = parsed_payload.get("UserData")
        if nonempty(user_data):
            # EventData is heterogeneous across Windows providers. Normalize it to
            # a single string representation so one index cannot oscillate between
            # an Elasticsearch text field and an object field. Preserve the full
            # structured value as JSON text when it is an object/list.
            if isinstance(user_data, dict):
                user_data = dict(user_data)
                event_data_value = user_data.get("EventData")
                if isinstance(event_data_value, (dict, list)):
                    user_data["EventData"] = json.dumps(
                        event_data_value, ensure_ascii=False, separators=(",", ":")
                    )
            set_nested(doc, "winlog.payload.user_data", user_data)
        copy_renames(parsed_payload, doc, PAYLOAD_ROOT_RENAMES)

    # The six PayloadData fields are independently grok-parsed in the original pipeline.
    for n in range(1, 7):
        key = f"PayloadData{n}"
        value = raw.get(key)
        if not nonempty(value):
            continue
        match = re.match(r"^(\w+): (.*)$", str(value), flags=re.DOTALL)
        if match:
            set_nested(doc, f"winlog.payload_data.{match.group(1)}", match.group(2))
        else:
            add_tag(doc, f"_grokparsefail_6504-{n:02d}")

    # This exact misspelling is in the repository's Logstash rename; postprocessing copies it to user.id.
    user_identifier = get_nested(doc, "winlog.user.identifer")
    if user_identifier is not None:
        set_nested(doc, "user.id", user_identifier)

    time_value = get_nested(doc, "winlog.time_created")
    normalized = parse_timestamp(time_value)
    if normalized:
        set_nested(doc, "winlog.time_created", normalized)
        doc["@timestamp"] = normalized
    else:
        doc["@timestamp"] = ingest_time

    remote_host = get_nested(doc, "winlog.remote_host")
    if remote_host:
        parse_remote_host(doc)

    keywords = get_nested(doc, "winlog.keywords")
    if isinstance(keywords, str):
        set_nested(doc, "winlog.keywords", keywords.split(", "))

    map_description = get_nested(doc, "kape.map_description")
    doc["message"] = f"KAPE map used: {map_description}" if map_description else "No event summary available"
    return doc


def main():
    parser = argparse.ArgumentParser()
    add_common_arguments(parser, "Load EvtxECmd JSON records directly into evtxlogs-<hostname>.")
    args = parser.parse_args()
    run_import(args, LABEL_TYPE, INDEX_PREFIX, PATTERNS, EXCLUDES, MAPPINGS, transform)

if __name__ == "__main__":
    main()
