#!/usr/bin/env python3
"""Discover forensic exports recursively and run the matching SOF-ELK importer.

Expected layout:
  SOF-ELK_ImportWrapper.py
  Windows/csv_importers/<thirteen CSV importers and sof_elk_csv_bulk_common.py>
  Windows/json_importers/<four JSON importers and sof_elk_json_bulk_common.py>
  Linux/linux2sofelk.py (UAC collections: a folder holding uac.log, or a UAC .zip)
  AWS/<cloudtrail|vpcflow|alb|waf|route53resolver|securityhub|eksaudit>2sofelk.py
      (AWS logs, plain or .gz, native, CSV or Amazon Security Lake OCSF exports)

A UAC collection is handed to Linux/linux2sofelk.py as a whole and its folder is not
searched for Windows exports (its [root]/ copy of the host's files could hold CSVs that
would otherwise be mistaken for KAPE output).

AWS logs are recognised with the AWS importers' own detect() functions, run on every file
that no Windows importer claimed, so the wrapper and the importer always agree on a file. The
evidence host name becomes the importers' --source (aws-cloudtrail-<hostname>, ...). A native
or CSV file goes to the first importer that claims it; an Amazon Security Lake export goes to
every importer whose source occurs in it, and each importer loads only its own records.

The wrapper only selects files and orchestrates the existing importers. It does not
parse or index evidence itself.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable

HYBRID_IMPORTERS = {
    "MFTECmd": ("mftecmd2sofelk.py", ("*_mftecmd*_output.json", "*_mftecmd*_output.json.gz", "*_mftecmd*_output.csv"), ()),
    "EvtxECmd": ("evtxecmd2sofelk.py", ("*_evtxecmd_output.json", "*_evtxecmd_output.json.gz", "*_evtxecmd_output.csv"), ()),
    "LECmd": ("lecmd2sofelk.py", ("*_lecmd_output.json", "*_lecmd_output.json.gz", "*_lecmd_output.csv"), ()),
    "PECmd": ("pecmd2sofelk.py", ("*_pecmd_output.json", "*_pecmd_output.json.gz", "*_pecmd_output.csv"), ("*_pecmd_output_timeline.json", "*_pecmd_output_timeline.json.gz", "*_pecmd_output_timeline.csv")),
}

CSV_IMPORTERS = {
    "NirSoft BrowsingHistoryView": ("nirsoft_bhv2sofelk.py", "browsinghistory"),
    "ConvertUsageLogsTo-CSV": ("clrusagelogs2sofelk.py", "clrusagelogs"),
    "JLECmd": ("jlecmd2sofelk.py", "jumplist"),
    "SBECmd": ("sbecmd2sofelk.py", "shellbag"),
    "AmcacheParser": ("amcache2sofelk.py", "amcache"),
    "AppCompatCacheParser": ("shimcache2sofelk.py", "shimcache"),
    "RECmd": ("recmd2sofelk.py", "registry"),
    "RBCmd": ("rbcmd2sofelk.py", "recyclebin"),
    "RecentFileCacheParser": ("recentfilecache2sofelk.py", "recentfilecache"),
    "SQLECmd": ("sqlecmd2sofelk.py", "sqlitedb"),
    "SrumECmd": ("srumecmd2sofelk.py", "srum"),
    "SumECmd": ("sumecmd2sofelk.py", "sum"),
    "WxTCmd": ("wxtcmd2sofelk.py", "activitiescache"),
}

# Linux collections (UAC) go to one front end that runs every Linux importer.
LINUX_LABEL = "Linux (UAC)"
LINUX_IMPORTER = ("Linux", "linux2sofelk.py")
UAC_MARKERS = {"[root]", "journal", "live_response", "bodyfile"}

# AWS importers, in detection priority order: a native log file goes to the first one whose
# detect() claims it (VPC Flow is last because its CSV signature is the broadest). An Amazon
# Security Lake (OCSF) export can hold several sources, so it goes to every importer whose
# source it holds, and each loads only its own records. Label -> (script, index prefix).
AWS_IMPORTERS = {
    "AWS CloudTrail": ("cloudtrail2sofelk.py", "aws-cloudtrail"),
    "AWS WAF": ("waf2sofelk.py", "aws-waf"),
    "AWS Security Hub": ("securityhub2sofelk.py", "aws-securityhub"),
    "AWS EKS audit": ("eksaudit2sofelk.py", "kubernetes"),
    "AWS Route 53 Resolver": ("route53resolver2sofelk.py", "aws-route53"),
    "AWS ALB/ELB": ("alb2sofelk.py", "httpdlog"),
    "AWS VPC Flow": ("vpcflow2sofelk.py", "aws-vpcflow"),
}
AWS_SUBDIR = "AWS"
# AWS importers accept only these --date-order values.
AWS_DATE_ORDERS = {"dmy", "mdy"}

# CSV importers that do not accept --local-tz.
NO_LOCAL_TZ = {"NirSoft BrowsingHistoryView", "ConvertUsageLogsTo-CSV"}

# Columns only BrowsingHistoryView emits; used with "url" to recognise its exports.
BHV_SIGNATURE = {"visit time", "visit count", "visited from", "visit type", "visit duration",
                 "web browser", "user profile", "browser profile", "typed count", "history file"}
BHV_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)


def norm_header(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lstrip("\ufeff")).lower()


def read_csv_header(path: Path) -> list[str]:
    """Read a small header only, supporting common encodings and delimiters."""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as stream:
                first = stream.readline()
            if not first:
                return []
            delimiter = max((",", "\t", ";"), key=first.count)
            return next(csv.reader([first], delimiter=delimiter), [])
        except (UnicodeError, OSError, csv.Error):
            continue
    return []


def has_json_pattern(path: Path, patterns: Iterable[str], excludes: Iterable[str] = ()) -> bool:
    name = path.name.lower()
    return any(fnmatch.fnmatchcase(name, p) for p in patterns) and not any(
        fnmatch.fnmatchcase(name, p) for p in excludes
    )


def classify_csv(path: Path, headers: list[str]) -> set[str]:
    """Return importer keys matching this CSV's filename and/or header signature."""
    name = path.name.lower()
    stem = path.stem.lower()
    fields = {norm_header(h) for h in headers}
    # BrowsingHistoryView: URL plus at least two of its tool-specific columns. A lone
    # Url/Title column is not enough (RECmd TypedURLs and SCSI plugin CSVs have those).
    # A headerless export is accepted only with the familiar name and a URL in column 1.
    found: set[str] = set()
    if path.suffix.lower() in {".csv", ".txt", ".tsv"}:
        bhv_header = "url" in fields and len(fields & BHV_SIGNATURE) >= 2
        bhv_headerless = ("browsinghistory" in name and bool(headers)
                          and bool(BHV_URL_RE.match(headers[0].strip().lstrip("\ufeff"))))
        if bhv_header or bhv_headerless:
            found.add("NirSoft BrowsingHistoryView")

    # JLECmd: Automatic/Custom Destinations exports. Avoid classifying arbitrary AppId CSVs.
    if path.suffix.lower() == ".csv" and (
        "automaticdestinations" in name or "customdestinations" in name
    ):
        found.add("JLECmd")

    # SBECmd ShellBags, identified by its characteristic fields or explicit name.
    if path.suffix.lower() == ".csv" and (
        "sbecmd" in name or "bagpath" in fields or ("absolutepath" in fields and "shelltype" in fields)
    ):
        found.add("SBECmd")

    # AmcacheParser sections. These signatures intentionally do not match ShimCache.
    if path.suffix.lower() == ".csv" and (
        "amcache" in name or "filekeylastwritetimestamp" in fields or ("sha1" in fields and "programid" in fields)
    ):
        found.add("AmcacheParser")

    # AppCompatCache/ShimCache.
    if path.suffix.lower() == ".csv" and (
        "appcompatcache" in name or "shimcache" in name
        or {"cacheentryposition", "lastmodifiedtimeutc"}.issubset(fields)
    ):
        found.add("AppCompatCacheParser")

    # RECmd batch and plugin outputs. KAPE plugin filenames commonly have a timestamp
    # prefix and a double underscore before the hive path (e.g. UserAssist__C_Users_...).
    is_recmd_batch = "recmd_batch" in name or ("recmd" in name and "batch" in name)
    is_plugin_export = bool(re.match(r"^\d{8,}_", path.name)) and "__" in path.stem
    if path.suffix.lower() == ".csv" and (is_recmd_batch or is_plugin_export):
        found.add("RECmd")

    # RBCmd: modern Recycle Bin $I output.
    if path.suffix.lower() == ".csv" and (
        "rbcmd" in name or "recyclebin" in name
        or {"sourcefile", "version"}.issubset(fields) and any("deleted" in f or "deletion" in f for f in fields)
    ):
        found.add("RBCmd")

    # RecentFileCacheParser.
    if path.suffix.lower() == ".csv" and (
        "recentfilecache" in name or "recentfilecacheparser" in name
        or {"sourcefile", "sourcemodified", "file_names"}.issubset(fields)
        or {"sourcefile", "sourcemodified"}.issubset(fields) and any("filename" in f or "filenames" in f for f in fields)
    ):
        found.add("RecentFileCacheParser")

    # SQLECmd. Output varies with the SQLite map, so use both the tool name and
    # characteristic SQLite/report columns. A filename hint is preferred.
    if path.suffix.lower() == ".csv" and (
        "sqlecmd" in name or {"sourcefile", "query"}.issubset(fields)
        or {"database", "table"}.issubset(fields)
        or "sqlitemap" in name
    ):
        found.add("SQLECmd")

    # SrumECmd emits several well-known report CSVs, all with Timestamp/Id plus
    # tool-specific columns.
    if path.suffix.lower() == ".csv" and (
        "srumecmd" in name or {"id", "timestamp", "exeinfo"}.issubset(fields)
        or {"id", "timestamp", "user_id"}.issubset(fields) and any(x in fields for x in {"app_id", "bytesreceived", "bytessent", "networktype"})
    ):
        found.add("SrumECmd")

    # SumECmd / UAL output. Filename is the strongest signal because SUM CSV
    # schemas vary by report mode.
    if path.suffix.lower() == ".csv" and (
        "sumecmd" in name or "_sum_" in name or name.startswith("sum_")
    ):
        found.add("SumECmd")

    # WxTCmd Windows Timeline output. It can generate Activity, ActivityOperations
    # and ActivityPackage CSVs.
    if path.suffix.lower() == ".csv" and (
        "wxtcmd" in name or "activityoperations" in name or "activitypackage" in name
        or {"id", "activitytypeorg", "activitytype", "executable", "starttime"}.issubset(fields)
    ):
        found.add("WxTCmd")
    
    # ConvertUsageLogsTo-CSV.ps1: exact five-column schema. Filename is a strong cue,
    # but the header check prevents arbitrary CSVs from being classified as CLR usage logs.
    clr_headers = {"user", "assemblyname", "firstexecutiontimestamp", "lastexecutiontimestamp", "file"}
    if "convertusagelogs" in name or "usage logs" in name or clr_headers.issubset({re.sub(r"\s+", "", f) for f in fields}):
        found.add("ConvertUsageLogsTo-CSV")

    return found


def is_uac_zip(path: Path) -> bool:
    """A UAC output archive: a zip with uac.log at its top (or one folder down)."""
    if path.suffix.lower() != ".zip":
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            return any(n.replace("\\", "/").rstrip("/").endswith("uac.log") and n.count("/") <= 1
                       for n in zf.namelist())
    except (zipfile.BadZipFile, OSError):
        return False


class AwsDetector:
    """The AWS importers' own detect() functions, imported from AWS/.

    Importing (rather than copying the signatures) keeps the wrapper in step with the
    importers. If AWS/ is missing or fails to import, AWS discovery is disabled with a warning.
    """

    def __init__(self, wrapper_dir: Path):
        self.detectors: list[tuple[str, object]] = []
        self.head_text = None
        self.error = ""
        aws_dir = wrapper_dir / AWS_SUBDIR
        if not (aws_dir / "sof_elk_aws_common.py").is_file():
            self.error = f"{aws_dir} not found"
            return
        import importlib
        sys.path.insert(0, str(aws_dir))
        try:
            common = importlib.import_module("sof_elk_aws_common")
            for label, (script, _prefix) in AWS_IMPORTERS.items():
                module = importlib.import_module(Path(script).stem)
                self.detectors.append((label, module.LOG.detect))
            self.head_text = common.head_text
            self.is_ocsf = common.ocsf.head_is_ocsf
        except Exception as exc:  # noqa: BLE001 - any import failure only disables AWS discovery
            self.detectors = []
            self.error = f"could not load the AWS importers: {exc}"

    def classify(self, path: Path) -> list[str]:
        """Labels of the AWS importers that should load this file: the first that claims a
        native log, or every one whose source a Security Lake (OCSF) export holds. Staging keeps
        the folder layout under the input root, so path-based signatures (AWSLogs/<account>/
        vpcflowlogs/...) still hold when the importer checks the file again."""
        if not self.detectors:
            return []
        head = self.head_text(path)
        if not head:
            return []
        try:
            many = bool(self.is_ocsf(head))
        except Exception:  # noqa: BLE001
            many = False
        labels = []
        for label, detect in self.detectors:
            try:
                if detect(path, head):
                    labels.append(label)
                    if not many:
                        break
            except Exception:  # noqa: BLE001 - a detector crash on odd content means "not mine"
                continue
        return labels


def discover(root: Path, aws: AwsDetector | None = None
             ) -> tuple[dict[str, list[Path]], dict[str, list[Path]], list[Path], dict[str, list[Path]]]:
    """Walk the tree once; return selected files for the four JSON and thirteen CSV importers,
    the UAC collections (folders and zips) for the Linux importers, and AWS log files."""
    json_files = {name: [] for name in HYBRID_IMPORTERS}
    csv_files = {name: [] for name in CSV_IMPORTERS}
    aws_files: dict[str, list[Path]] = {name: [] for name in AWS_IMPORTERS}
    linux: list[Path] = []
    # os.walk avoids materializing a list of every descendant path at once.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "__pycache__"} and not d.startswith("sof-elk-import-"))
        directory = Path(dirpath)
        if "uac.log" in filenames and UAC_MARKERS & set(dirnames):
            linux.append(directory.resolve())
            dirnames[:] = []
            continue
        for filename in filenames:
            path = directory / filename
            lower = filename.lower()
            if lower.endswith(".zip") and is_uac_zip(path):
                linux.append(path.resolve())
                continue
            claimed = False
            for importer, (_script, patterns, excludes) in HYBRID_IMPORTERS.items():
                if has_json_pattern(path, patterns, excludes):
                    json_files[importer].append(path)
                    claimed = True
            suffix = path.suffix.lower()
            if suffix in {".csv", ".txt", ".tsv"}:
                header = read_csv_header(path)
                for importer in classify_csv(path, header):
                    csv_files[importer].append(path)
                    claimed = True
            # AWS logs have no fixed extension (Firehose WAF files have none), so every file a
            # Windows importer did not claim is offered to the AWS detectors.
            if not claimed and aws is not None and not filename.startswith("."):
                for label in aws.classify(path):
                    aws_files[label].append(path)
    for collection in (json_files, csv_files, aws_files):
        for key in collection:
            collection[key] = sorted(set(p.resolve() for p in collection[key]), key=lambda p: str(p).lower())
    return json_files, csv_files, sorted(set(linux), key=lambda p: str(p).lower()), aws_files


def locate_script(wrapper_dir: Path, subdir: str, script: str) -> Path | None:
    candidate = wrapper_dir / subdir / script
    if candidate.is_file():
        return candidate
    # Also support a flat deployment where the scripts are beside the wrapper.
    candidate = wrapper_dir / script
    if candidate.is_file():
        return candidate
    # Last-resort search within the wrapper's directory, excluding temp/cache folders.
    for path in wrapper_dir.rglob(script):
        if path.is_file() and "__pycache__" not in path.parts:
            return path
    return None


class StagingArea:
    """Build per-importer directories containing hardlinks to selected files.

    This keeps source filenames intact for tool detection, avoids excessive argv length,
    and normally adds no evidence-data copy. A copy is a fallback for filesystems that
    do not support hardlinks.
    """
    def __init__(self, root: Path):
        self.root = root
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.base: Path | None = None

    def __enter__(self) -> "StagingArea":
        try:
            self.temp = tempfile.TemporaryDirectory(prefix="sof-elk-import-", dir=str(self.root))
        except OSError:
            self.temp = tempfile.TemporaryDirectory(prefix="sof-elk-import-")
        self.base = Path(self.temp.name)
        return self

    def add(self, importer_key: str, files: list[Path], keep_tree_from: Path | None = None) -> Path:
        """Stage files for one importer. With keep_tree_from, each file keeps its path relative
        to that folder (AWS importers read the account, service and region from the
        AWSLogs/<account>/<service>/<region>/ layout); otherwise each gets a numbered subdir."""
        assert self.base is not None
        dest = self.base / re.sub(r"[^A-Za-z0-9_-]+", "_", importer_key)
        dest.mkdir(parents=True, exist_ok=True)
        for i, source in enumerate(files):
            if keep_tree_from is not None:
                target = dest / source.relative_to(keep_tree_from)
                target.parent.mkdir(parents=True, exist_ok=True)
            else:
                # Preserve the original basename and avoid clashes by placing files in unique subdirs.
                item_dir = dest / f"{i:08d}"
                item_dir.mkdir(exist_ok=True)
                target = item_dir / source.name
            try:
                os.link(source, target)
            except OSError:
                try:
                    target.symlink_to(source)
                except OSError:
                    shutil.copy2(source, target)
        return dest

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.temp is not None:
            self.temp.cleanup()


def add_common_cli_args(command: list[str], args: argparse.Namespace, *, is_json: bool, label: str) -> None:
    command.extend(["--hostname", args.hostname, "--es", args.es])
    if args.user:
        command.extend(["--user", args.user])
    if args.password is not None:
        command.extend(["--password", args.password])
    if args.insecure:
        command.append("--insecure")
    command.extend(["--batch-size", str(args.batch_size)])
    command.extend(["--max-retries", str(args.max_retries), "--retry-backoff", str(args.retry_backoff),
                    "--timeout", str(args.timeout)])
    if args.log_file:
        command.extend(["--log-file", args.log_file])
    if args.case:
        command.extend(["--case", args.case])
    if not is_json:
        if args.local_tz and label not in NO_LOCAL_TZ:
            command.extend(["--local-tz", args.local_tz])
    if args.dry_run:
        command.append("--dry-run")


def run_one(label: str, script_path: Path, input_dir: Path, args: argparse.Namespace,
            staging: StagingArea, extra: list[str] | None = None, is_json: bool = False) -> int:
    print("\n" + "=" * 76, flush=True)
    print(f"[{label}] Starting import", flush=True)
    print(f"[{label}] Script: {script_path}", flush=True)
    staged_count = sum(1 for p in input_dir.rglob("*") if p.is_file())
    print(f"[{label}] Selected input files: {staged_count}", flush=True)
    command = [sys.executable, str(script_path), str(input_dir)]
    add_common_cli_args(command, args, is_json=is_json, label=label)
    if is_json:
        command.extend(["--workers", str(args.workers), "--sample-docs", str(args.sample_docs)])
    if extra:
        command.extend(extra)
    print(f"[{label}] Command: {command[0]} {Path(command[1]).name} <staged-input> --hostname {args.hostname}", flush=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="" if line.endswith("\n") else "\n", flush=True)
        result = proc.wait()
    except OSError as exc:
        print(f"[{label}] ERROR: could not start importer: {exc}", flush=True)
        return 127
    if result == 0:
        print(f"[{label}] Completed successfully", flush=True)
    else:
        print(f"[{label}] ERROR: importer exited with status {result}", flush=True)
    return result


def run_linux(script_path: Path, evidence: Path, args: argparse.Namespace) -> int:
    """Run Linux/linux2sofelk.py on one UAC collection (folder or zip), streaming its output."""
    print("\n" + "=" * 76, flush=True)
    print(f"[{LINUX_LABEL}] Starting import of {evidence}", flush=True)
    command = [sys.executable, str(script_path), str(evidence)]
    # Linux importers read the time zone from the evidence itself, so --local-tz is not passed.
    add_common_cli_args(command, args, is_json=True, label=LINUX_LABEL)
    command.extend(["--sample-docs", str(args.sample_docs)])
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="" if line.endswith("\n") else "\n", flush=True)
        result = proc.wait()
    except OSError as exc:
        print(f"[{LINUX_LABEL}] ERROR: could not start importer: {exc}", flush=True)
        return 127
    if result == 0:
        print(f"[{LINUX_LABEL}] Completed successfully", flush=True)
    elif result == 3:
        print(f"[{LINUX_LABEL}] ERROR: the journal was not loaded (no journalctl JSON export); see the"
              " ACTION NEEDED message above", flush=True)
    else:
        print(f"[{LINUX_LABEL}] ERROR: importer exited with status {result}", flush=True)
    return result


def run_aws(label: str, script_path: Path, input_dir: Path, file_count: int, args: argparse.Namespace) -> int:
    """Run one AWS importer on its staged folder; the evidence host name is its --source."""
    print("\n" + "=" * 76, flush=True)
    print(f"[{label}] Starting import", flush=True)
    print(f"[{label}] Script: {script_path}", flush=True)
    print(f"[{label}] Selected input files: {file_count}", flush=True)
    command = [sys.executable, str(script_path), str(input_dir), "--source", args.hostname, "--es", args.es]
    if args.user:
        command.extend(["--user", args.user])
    if args.password is not None:
        command.extend(["--password", args.password])
    if args.insecure:
        command.append("--insecure")
    command.extend(["--batch-size", str(args.batch_size), "--max-retries", str(args.max_retries),
                    "--retry-backoff", str(args.retry_backoff), "--timeout", str(args.timeout),
                    "--sample-docs", str(args.sample_docs)])
    if args.log_file:
        command.extend(["--log-file", args.log_file])
    if args.case:
        command.extend(["--case", args.case])
    if args.date_order in AWS_DATE_ORDERS:
        command.extend(["--date-order", args.date_order])
    if args.vpc_fields and script_path.name == AWS_IMPORTERS["AWS VPC Flow"][0]:
        command.extend(["--fields", args.vpc_fields])
    if args.dry_run:
        command.append("--dry-run")
    print(f"[{label}] Command: {command[0]} {Path(command[1]).name} <staged-input> --source {args.hostname}", flush=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="" if line.endswith("\n") else "\n", flush=True)
        result = proc.wait()
    except OSError as exc:
        print(f"[{label}] ERROR: could not start importer: {exc}", flush=True)
        return 127
    if result == 0:
        print(f"[{label}] Completed successfully", flush=True)
    else:
        print(f"[{label}] ERROR: importer exited with status {result}", flush=True)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recursively discover SOF-ELK forensic exports and invoke the matching CSV/JSON importers"
                    " (and the Linux importers for UAC collections, and the AWS importers for CloudTrail,"
                    " VPC Flow, ALB/ELB and WAF logs).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("directory", help="Root directory to search recursively")
    parser.add_argument("hostname", help="Evidence host name for per-host Elasticsearch indexes")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    parser.add_argument("--workers", type=int, default=2, help="Concurrent bulk workers for JSON importers")
    parser.add_argument("--case", help="Optional case/incident ID added to every document by every importer")
    parser.add_argument("--local-tz", help="UTC offset for *LOCAL timestamp fields in KAPE CSVs, e.g. +08:00")
    parser.add_argument("--bhv-tz", help="Timezone offset for NirSoft BrowsingHistoryView, e.g. +08:00 or UTC")
    parser.add_argument("--date-order", choices=("dmy", "mdy", "ymd"),
                        help="Regional date order: forced for BrowsingHistoryView, and passed to the AWS importers"
                             " (dmy/mdy only) for spreadsheet-style dates in CSVs re-saved by Excel")
    parser.add_argument("--vpc-fields", metavar="'version account-id ...'",
                        help="AWS VPC Flow custom log format for files without a header line (passed as --fields)")
    parser.add_argument("--dry-run", action="store_true", help="Pass dry-run mode to every importer")
    parser.add_argument("--sample-docs", type=int, default=2, help="Sample documents per JSON importer in dry-run mode")
    parser.add_argument("--max-retries", type=int, default=5,
                        help="Retries for failed Elasticsearch requests and rejected bulk items (timeouts, 429/5xx)")
    parser.add_argument("--retry-backoff", type=float, default=2.0, help="Base delay in seconds for exponential retry backoff")
    parser.add_argument("--timeout", type=float, default=300, help="Seconds to wait for each Elasticsearch HTTP response")
    parser.add_argument("--log-file", help="Append every importer's retries, bulk results and item errors to this file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: directory does not exist or is not a directory: {root}")
        return 2
    if args.batch_size < 1 or args.workers < 1:
        print("ERROR: --batch-size and --workers must be positive integers.")
        return 2
    if args.max_retries < 0 or args.retry_backoff <= 0 or args.timeout <= 0:
        print("ERROR: --max-retries must be >= 0, and --retry-backoff and --timeout must be positive.")
        return 2
    if args.log_file:
        # Importers run from other directories, so hand them an absolute path.
        args.log_file = str(Path(args.log_file).expanduser().resolve())

    wrapper_dir = Path(__file__).resolve().parent
    print(f"SOF-ELK Import Wrapper\nInput directory: {root}\nHostname: {args.hostname}\nElasticsearch: {args.es}", flush=True)
    print("Scanning directory tree and checking file signatures...", flush=True)
    aws = AwsDetector(wrapper_dir)
    if aws.error:
        print(f"WARNING: AWS log discovery is off: {aws.error}", flush=True)
    json_files, csv_files, linux_collections, aws_files = discover(root, aws)

    todo: list[tuple[str, str, str, list[Path], list[str] | None, bool]] = []
    failed: list[tuple[str, int]] = []
    for label, (script, _patterns, _excludes) in HYBRID_IMPORTERS.items():
        files = json_files[label]
        if files:
            todo.append((label, "json_importers", script, files, None, True))
    for label, (script, _prefix) in CSV_IMPORTERS.items():
        files = csv_files[label]
        if files:
            extra: list[str] = []
            if label == "NirSoft BrowsingHistoryView":
                if not args.bhv_tz:
                    print(f"[{label}] ERROR: found {len(files)} candidate file(s), but --bhv-tz is required; skipping to avoid guessing the source machine's timezone.", flush=True)
                    failed.append((label, 2))
                    continue
                extra.extend(["--tz", args.bhv_tz])
                if args.date_order:
                    extra.extend(["--date-order", args.date_order])
            todo.append((label, "csv_importers", script, files, extra, False))

    print("\nDiscovery summary:", flush=True)
    total_files = 0
    for label, files in [(x, json_files[x]) for x in HYBRID_IMPORTERS] + [(x, csv_files[x]) for x in CSV_IMPORTERS]:
        print(f"  {label}: {len(files)} file(s)", flush=True)
        total_files += len(files)
    print(f"  {LINUX_LABEL}: {len(linux_collections)} collection(s)", flush=True)
    for path in linux_collections:
        print(f"    {path}", flush=True)
    total_files += len(linux_collections)
    for label in AWS_IMPORTERS:
        print(f"  {label}: {len(aws_files[label])} file(s)", flush=True)
        total_files += len(aws_files[label])
    aws_todo = [label for label in AWS_IMPORTERS if aws_files[label]]
    if aws_todo:
        print(f"  AWS logs load into <prefix>-{args.hostname} indexes (the host name is the AWS importers' --source)",
              flush=True)
    if not todo and not linux_collections and not aws_todo:
        print("No eligible input files found (or all candidates were skipped).", flush=True)
        if not total_files:
            return 1
        print(f"Importers failed/skipped: {len(failed)}", flush=True)
        for label, code in failed:
            print(f"  ERROR: {label} (exit status {code})", flush=True)
        return 1

    success = 0
    with StagingArea(root) as staging:
        for label, subdir, script, files, extra, is_json in todo:
            script_path = locate_script(wrapper_dir, subdir, script)
            if script_path is None:
                print(f"[{label}] ERROR: could not locate importer {script} under {wrapper_dir}", flush=True)
                failed.append((label, 127))
                continue
            staged_dir = staging.add(label, files)
            code = run_one(label, script_path, staged_dir, args, staging, extra=extra, is_json=is_json)
            if code == 0:
                success += 1
            else:
                failed.append((label, code))
        for label in aws_todo:
            script = AWS_IMPORTERS[label][0]
            script_path = locate_script(wrapper_dir, AWS_SUBDIR, script)
            if script_path is None:
                print(f"[{label}] ERROR: could not locate importer {script} under {wrapper_dir}", flush=True)
                failed.append((label, 127))
                continue
            staged_dir = staging.add(label, aws_files[label], keep_tree_from=root)
            code = run_aws(label, script_path, staged_dir, len(aws_files[label]), args)
            if code == 0:
                success += 1
            else:
                failed.append((label, code))
    if linux_collections:
        script_path = locate_script(wrapper_dir, *LINUX_IMPORTER)
        for evidence in linux_collections:
            label = f"{LINUX_LABEL} {evidence.name}"
            if script_path is None:
                print(f"[{LINUX_LABEL}] ERROR: could not locate {LINUX_IMPORTER[1]} under {wrapper_dir}", flush=True)
                failed.append((label, 127))
                continue
            code = run_linux(script_path, evidence, args)
            if code == 0:
                success += 1
            else:
                failed.append((label, code))

    print("\n" + "=" * 76, flush=True)
    print("Import wrapper summary", flush=True)
    print(f"Importers succeeded: {success}", flush=True)
    print(f"Importers failed/skipped: {len(failed)}", flush=True)
    for label, code in failed:
        print(f"  ERROR: {label} (exit status {code})", flush=True)
    if failed:
        print("One or more importers failed or were skipped. See messages above.", flush=True)
        return 1
    print("All scheduled importers completed successfully.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())