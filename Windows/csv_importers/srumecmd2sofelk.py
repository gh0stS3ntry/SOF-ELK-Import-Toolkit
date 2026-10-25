#!/usr/bin/env python3
"""Load SrumECmd (SRUM database) CSVs into srum-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-srum.json (plus the shared component-toolkit-common.json).
SrumECmd writes one CSV per SRUM table; all of them start with the same identity columns
(Id, Timestamp, ExeInfo, SidType, Sid, UserName, UserId, AppId), which go to srum.*, user.id
and user.name. Table-specific counters are srum.<snake_case>. When ExeInfo is a file path, it is
also written as ECS process.executable / process.name. event.dataset names the table, e.g.
srum.network_connections.

@timestamp is the SRUM record Timestamp: when Windows wrote the usage record (records are
flushed roughly hourly), not when the activity started.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/srum.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). Conversions are listed in
# sof_elk_template_importer.CONV_TYPE.
COLUMNS = {
    # Identity columns, present in every SrumECmd table
    "id": [("srum.id", "long")],
    "timestamp": [("srum.timestamp", "date")],
    "exeinfo": [("srum.exe_info", "keyword")],
    "exeinfodescription": [("srum.exe_info_description", "keyword")],
    "exetimestamp": [("srum.exe_timestamp", "date")],
    "sidtype": [("srum.sid_type", "keyword")],
    "sid": [("user.id", "keyword")],
    "username": [("user.name", "keyword")],
    "userid": [("srum.user_id", "long")],  # SruDbIdMapTable index, not a Windows account ID
    "appid": [("srum.app_id", "long")],    # SruDbIdMapTable index

    # AppResourceUseInfo
    "backgroundbytesread": [("srum.background_bytes_read", "long")],
    "backgroundbyteswritten": [("srum.background_bytes_written", "long")],
    "backgroundcontextswitches": [("srum.background_context_switches", "long")],
    "backgroundcycletime": [("srum.background_cycle_time", "long")],
    "backgroundnumberofflushes": [("srum.background_number_of_flushes", "long")],
    "backgroundnumreadoperations": [("srum.background_num_read_operations", "long")],
    "backgroundnumwriteoperations": [("srum.background_num_write_operations", "long")],
    "facetime": [("srum.face_time", "long")],
    "foregroundbytesread": [("srum.foreground_bytes_read", "long")],
    "foregroundbyteswritten": [("srum.foreground_bytes_written", "long")],
    "foregroundcontextswitches": [("srum.foreground_context_switches", "long")],
    "foregroundcycletime": [("srum.foreground_cycle_time", "long")],
    "foregroundnumberofflushes": [("srum.foreground_number_of_flushes", "long")],
    "foregroundnumreadoperations": [("srum.foreground_num_read_operations", "long")],
    "foregroundnumwriteoperations": [("srum.foreground_num_write_operations", "long")],

    # NetworkUsages / NetworkConnections
    "bytesreceived": [("srum.bytes_received", "long")],
    "bytessent": [("srum.bytes_sent", "long")],
    "connectedtime": [("srum.connected_time", "long")],  # seconds
    "connectstarttime": [("srum.connect_start_time", "date")],
    "interfaceluid": [("srum.interface_luid", "long")],
    "interfacetype": [("srum.interface_type", "keyword")],
    "l2profileflags": [("srum.l2_profile_flags", "long")],
    "l2profileid": [("srum.l2_profile_id", "long")],
    "profilename": [("srum.profile_name", "keyword")],

    # PushNotifications
    "networktype": [("srum.network_type", "keyword")],
    "notificationtype": [("srum.notification_type", "keyword")],
    "payloadsize": [("srum.payload_size", "long")],

    # AppTimelineProvider / vfuprov
    "starttime": [("srum.start_time", "date")],
    "endtime": [("srum.end_time", "date")],
    "durationms": [("srum.duration_ms", "long")],
    "duration": [("srum.duration", "long")],
    "flags": [("srum.flags", "long")],

    # EnergyUsage
    "islt": [("srum.is_lt", "boolean")],
    "configurationhash": [("srum.configuration_hash", "keyword")],
    "eventtimestamp": [("srum.event_timestamp", "date")],
    "statetransition": [("srum.state_transition", "long")],
    "chargelevel": [("srum.charge_level", "long")],
    "cyclecount": [("srum.cycle_count", "long")],
    "designedcapacity": [("srum.designed_capacity", "long")],
    "fullchargedcapacity": [("srum.full_charged_capacity", "long")],
    "activeactime": [("srum.active_ac_time", "long")],
    "activedctime": [("srum.active_dc_time", "long")],
    "activedischargetime": [("srum.active_discharge_time", "long")],
    "activeenergy": [("srum.active_energy", "long")],
    "csactime": [("srum.cs_ac_time", "long")],
    "csdctime": [("srum.cs_dc_time", "long")],
    "csdischargetime": [("srum.cs_discharge_time", "long")],
    "csenergy": [("srum.cs_energy", "long")],
}

# event.dataset per SrumECmd table (file name part between SrumECmd_ and _Output)
DATASETS = {
    "appresourceuseinfo": "srum.app_resource_use_info",
    "apptimelineprovider": "srum.app_timeline_provider",
    "energyusage": "srum.energy_usage",
    "networkconnections": "srum.network_connections",
    "networkusages": "srum.network_usages",
    "pushnotifications": "srum.push_notifications",
    "vfuprov": "srum.vfuprov",
}

TIME_MEANING = {
    "timestamp": "SRUM record time - when Windows wrote the usage record (about hourly), not when"
                 " the activity started",
}

NAME_RE = re.compile(r"srumecmd_(.+?)_output", re.I)
# Table guess from the columns, for CSVs renamed without the SrumECmd_<Table>_Output part
SIGNATURES = [
    ("AppResourceUseInfo", {"foregroundcycletime"}),
    ("NetworkUsages", {"bytesreceived", "bytessent"}),
    ("NetworkConnections", {"connectedtime", "connectstarttime"}),
    ("PushNotifications", {"notificationtype", "payloadsize"}),
    ("EnergyUsage", {"chargelevel", "eventtimestamp"}),
    ("AppTimelineProvider", {"durationms"}),
    ("vfuprov", {"flags", "starttime"}),
]


def detect_section(path, header):
    """SrumECmd table name (e.g. 'NetworkUsages') from the file name or columns, otherwise None."""
    h = {c.strip().lower() for c in header}
    m = NAME_RE.search(path.stem)
    if m:
        return m.group(1)
    if not {"id", "timestamp", "appid"} <= h:
        return None
    for section, cols in SIGNATURES:
        if cols <= h:
            return section
    return "Unknown" if "exeinfo" in h else None


def dataset_for(section):
    return DATASETS.get(section.lower(), f"srum.{engine.snake(section)}")


def enrich(doc, meta):
    """process.executable / process.name when ExeInfo is a path (not a service or package name)."""
    exe = engine.get_field(doc, "srum.exe_info")
    if exe and "\\" in exe:
        path = exe.lower()
        doc["process"] = {"executable": path, "name": path.rsplit("\\", 1)[-1]}


ARTIFACT = engine.Artifact(
    name="srum",
    tool="SrumECmd",
    columns=COLUMNS,
    detect_section=detect_section,
    dataset_for=dataset_for,
    time_default=["srum.timestamp"],
    time_meaning=TIME_MEANING,
    enrich=enrich,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load SrumECmd CSVs into a host-specific SOF-ELK index with a fixed schema.")
