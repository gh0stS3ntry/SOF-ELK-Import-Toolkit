#!/usr/bin/env python3
"""Load AmcacheParser CSV sections into amcache-<hostname>.

Every AmcacheParser column is mapped to a fixed field with a fixed type, defined by the explicit
index template in Windows/index_templates/index-amcache.json (plus the shared
component-toolkit-common.json). ECS names are used where they fit (file.*, package.*), and
everything else lives under amcache.* in snake_case. Nothing is inferred per run, so every host's
amcache-<hostname> index has the same schema and ES|QL queries work across amcache-*.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/amcache.md.
"""
import re

import sof_elk_template_importer as engine

# --------------------------------------------------------------------------- column map
#
# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions are listed in sof_elk_template_importer.CONV_TYPE.

COLUMNS = {
    # Present in several sections
    "keyname": [("amcache.key_name", "keyword")],
    "keylastwritetimestamp": [("amcache.key_last_write", "date")],
    "programid": [("amcache.program_id", "keyword")],
    "programinstanceid": [("amcache.program_instance_id", "keyword")],
    "language": [("amcache.language", "long")],
    "manufacturer": [("amcache.manufacturer", "keyword")],
    "description": [("amcache.description", "keyword")],
    "name": [("amcache.name", "keyword")],
    "version": [("amcache.version", "keyword")],
    "productversion": [("amcache.product_version", "keyword")],
    "class": [("amcache.class", "keyword")],
    "inf": [("amcache.inf", "keyword")],
    "provider": [("amcache.provider", "keyword")],
    "service": [("amcache.service", "keyword")],
    "driverid": [("amcache.driver_id", "keyword")],
    "drivername": [("amcache.driver_name", "keyword")],
    "driverpackagestrongname": [("amcache.driver_package_strong_name", "keyword")],
    "driverinbox": [("amcache.driver_in_box", "boolean")],

    # AssociatedFileEntries / UnassociatedFileEntries (InventoryApplicationFile)
    "applicationname": [("amcache.application_name", "keyword")],
    "filekeylastwritetimestamp": [("amcache.file_key_last_write", "date")],
    "sha1": [("file.hash.sha1", "sha1")],
    "isoscomponent": [("amcache.is_os_component", "boolean")],
    "fullpath": [("file.path", "path")],
    "fileextension": [("file.extension", "ext")],
    "linkdate": [("amcache.link_date", "date")],
    "productname": [("file.pe.product", "keyword")],
    "size": [("file.size", "long")],
    "longpathhash": [("amcache.long_path_hash", "keyword")],
    "binarytype": [("amcache.binary_type", "keyword")],
    "ispefile": [("amcache.is_pe_file", "boolean")],
    "binfileversion": [("amcache.bin_file_version", "keyword")],
    "binproductversion": [("amcache.bin_product_version", "keyword")],
    "usn": [("amcache.usn", "long")],

    # ProgramEntries (InventoryApplication)
    "publisher": [("amcache.publisher", "keyword")],
    "installdate": [("package.installed", "date")],
    "installdatearplastmodified": [("amcache.install_date_arp_last_modified", "date")],
    "installdatemsi": [("amcache.install_date_msi", "date")],
    "installdatefromlinkfile": [("amcache.install_date_from_link_file", "date")],
    "osversionatinstalltime": [("amcache.os_version_at_install_time", "keyword")],
    "bundlemanifestpath": [("amcache.bundle_manifest_path", "keyword")],
    "hiddenarp": [("amcache.hidden_arp", "boolean")],
    "inboxmodernapp": [("amcache.inbox_modern_app", "boolean")],
    "manifestpath": [("amcache.manifest_path", "keyword")],
    "msipackagecode": [("amcache.msi_package_code", "keyword")],
    "msiproductcode": [("amcache.msi_product_code", "keyword")],
    "packagefullname": [("amcache.package_full_name", "keyword")],
    "registrykeypath": [("amcache.registry_key_path", "keyword")],
    "rootdirpath": [("package.path", "keyword")],
    "type": [("amcache.type", "keyword")],
    "source": [("amcache.source", "keyword")],
    "storeapptype": [("amcache.store_app_type", "keyword")],
    "uninstallstring": [("amcache.uninstall_string", "keyword")],

    # DeviceContainers
    "categories": [("amcache.categories", "keyword")],
    "discoverymethod": [("amcache.discovery_method", "keyword")],
    "friendlyname": [("amcache.friendly_name", "keyword")],
    "icon": [("amcache.icon", "keyword")],
    "isactive": [("amcache.is_active", "boolean")],
    "isconnected": [("amcache.is_connected", "boolean")],
    "ismachinecontainer": [("amcache.is_machine_container", "boolean")],
    "isnetworked": [("amcache.is_networked", "boolean")],
    "ispaired": [("amcache.is_paired", "boolean")],
    "modelid": [("amcache.model_id", "keyword")],
    "modelname": [("amcache.model_name", "keyword")],
    "modelnumber": [("amcache.model_number", "keyword")],
    "primarycategory": [("amcache.primary_category", "keyword")],
    "state": [("amcache.state", "long")],

    # DevicePnps
    "busreporteddescription": [("amcache.bus_reported_description", "keyword")],
    "classguid": [("amcache.class_guid", "keyword")],
    "compid": [("amcache.compid", "keyword")],
    "containerid": [("amcache.container_id", "keyword")],
    "driververdate": [("amcache.driver_ver_date", "mdy")],
    "driververversion": [("amcache.driver_ver_version", "keyword")],
    "enumerator": [("amcache.enumerator", "keyword")],
    "hwid": [("amcache.hwid", "keyword")],
    "installstate": [("amcache.install_state", "long")],
    "matchingid": [("amcache.matching_id", "keyword")],
    "model": [("amcache.model", "keyword")],
    "parentid": [("amcache.parent_id", "keyword")],
    "problemcode": [("amcache.problem_code", "long")],
    "stackid": [("amcache.stack_id", "keyword")],

    # DriveBinaries (InventoryDriverBinary)
    "drivertimestamp": [("amcache.link_date", "date")],  # PE header TimeDateStamp, same as LinkDate
    "driverlastwritetime": [("file.mtime", "date")],
    "driveriskernelmode": [("amcache.driver_is_kernel_mode", "boolean")],
    "driversigned": [("amcache.driver_signed", "boolean")],
    "driverchecksum": [("amcache.driver_checksum", "long")],
    "drivercompany": [("file.pe.company", "keyword")],
    "drivertype": [("amcache.driver_type", "long")],
    "driverversion": [("file.pe.file_version", "keyword")],
    "imagesize": [("amcache.image_size", "long")],
    "product": [("file.pe.product", "keyword")],
    "wdfversion": [("amcache.wdf_version", "keyword")],

    # DriverPackages
    "date": [("amcache.driver_date", "date")],
    "directory": [("amcache.directory", "keyword")],
    "hwids": [("amcache.hwid", "keyword")],
    "submissionid": [("amcache.submission_id", "keyword")],
    "sysfile": [("amcache.sys_file", "keyword")],

    # ShortCuts
    "lnkname": [("file.path", "path")],
}

# Section-specific meanings of columns whose name is reused across sections
SECTION_COLUMNS = {
    "file": {
        "name": [("file.name", "name")],
        "version": [("file.pe.file_version", "keyword")],
        "description": [("file.pe.description", "keyword")],
        # Older (Windows 8 / early 10) Amcache "File" key layout
        "programname": [("amcache.application_name", "keyword")],
        "fileidlastwritetimestamp": [("amcache.file_key_last_write", "date")],
        "volumeid": [("amcache.volume_id", "keyword")],
        "volumeidlastwritetimestamp": [("amcache.volume_id_last_write", "date")],
        "fileid": [("amcache.file_id", "keyword")],
        "mftentrynumber": [("amcache.mft_entry_number", "long")],
        "mftsequencenumber": [("amcache.mft_sequence_number", "long")],
        "filesize": [("file.size", "long")],
        "fileversionstring": [("file.pe.file_version", "keyword")],
        "fileversionnumber": [("amcache.file_version_number", "keyword")],
        "filedescription": [("file.pe.description", "keyword")],
        "sizeofimage": [("amcache.image_size", "long")],
        "peheaderhash": [("amcache.pe_header_hash", "keyword")],
        "peheaderchecksum": [("amcache.pe_header_checksum", "long")],
        "companyname": [("file.pe.company", "keyword")],
        "created": [("file.created", "date")],
        "lastmodified": [("file.mtime", "date")],
        "lastmodified2": [("amcache.last_modified2", "date")],
        "compiletime": [("amcache.compile_time", "date")],
        "languageid": [("amcache.language", "long")],
    },
    "program": {
        "name": [("package.name", "keyword")],
        "version": [("package.version", "keyword")],
    },
    "drivebinaries": {
        # KeyName is the driver's path (c:/windows/system32/drivers/x.sys)
        "keyname": [("amcache.key_name", "keyword"), ("file.path", "path")],
        "drivername": [("amcache.driver_name", "keyword"), ("file.name", "name")],
    },
}

# event.dataset per AmcacheParser section (unknown sections: amcache.<snake_case>)
DATASETS = {
    "associatedfileentries": "amcache.associated_file_entries",
    "unassociatedfileentries": "amcache.unassociated_file_entries",
    "fileentries": "amcache.file_entries",
    "programentries": "amcache.program_entries",
    "devicecontainers": "amcache.device_containers",
    "devicepnps": "amcache.device_pnps",
    "drivebinaries": "amcache.drive_binaries",
    "driverpackages": "amcache.driver_packages",
    "shortcuts": "amcache.shortcuts",
}

# @timestamp candidates per section kind, as template fields (first one with a value wins)
TIME_PREFS = {
    "file": ["amcache.file_key_last_write", "amcache.key_last_write"],
    "program": ["package.installed", "amcache.key_last_write"],
}
TIME_DEFAULT = ["amcache.key_last_write", "amcache.file_key_last_write"]

# What each @timestamp source column means (stored in kape.timestamp_meaning)
TIME_MEANING = {
    "filekeylastwritetimestamp": "Amcache file key last write - often close to first execution, not proof of it",
    "fileidlastwritetimestamp": "Amcache file key last write - often close to first execution, not proof of it",
    "keylastwritetimestamp": "Amcache registry key last write time",
    "installdate": "Program install date recorded in Amcache",
}


# --------------------------------------------------------------------------- sections

def detect_section(path, header):
    """AmcacheParser section name (e.g. 'ProgramEntries') from the file name or columns, or None."""
    h = {c.strip().lower() for c in header}
    stem = re.sub(r"^\d{8,}_", "", path.stem)
    if re.search(r"appcompatcache|shimcache", stem, re.I) or {"cacheentryposition", "lastmodifiedtimeutc"} <= h:
        return None  # ShimCache, handled by shimcache2sofelk.py
    m = re.search(r"amcache[_ -]+(.+)$", stem, re.I)
    if m:
        section = re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).strip("_")[:50]
        return section or "Unknown"
    if "filekeylastwritetimestamp" in h or ("sha1" in h and "programid" in h):
        return "FileEntries"
    return None


def section_kind(section):
    s = section.lower().replace("_", "")
    if s.endswith("fileentries"):
        return "file"
    if s == "programentries":
        return "program"
    return s


def dataset_for(section):
    s = section.lower().replace("_", "")
    return DATASETS.get(s, f"amcache.{engine.snake(section)}")


ARTIFACT = engine.Artifact(
    name="amcache",
    tool="AmcacheParser",
    columns=COLUMNS,
    section_columns=SECTION_COLUMNS,
    detect_section=detect_section,
    section_kind=section_kind,
    dataset_for=dataset_for,
    time_prefs=TIME_PREFS,
    time_default=TIME_DEFAULT,
    time_meaning=TIME_MEANING,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load AmcacheParser CSVs into a host-specific SOF-ELK index with a fixed schema.")
