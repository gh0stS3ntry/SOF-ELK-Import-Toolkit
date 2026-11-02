#!/usr/bin/env python3
"""Run the hunting pack's role checklists for one case and save every result as CSV.

    python3 SOF-ELK_RunChecklists.py IR-2026-042 ./IR-2026-042-hunt --es http://192.168.233.128:9200

What it does:

1. Finds the case's indexes: every open, non-hidden index holding documents whose flat
   `case` field is the case name (upper/lower case ignored), as written by the importers'
   --case option.
2. Groups them into evidence hosts by the <prefix>-<hostname> index suffix (host.name
   gives the display name). AWS indexes (aws-cloudtrail-*, aws-vpcflow-*, aws-waf-*, and
   httpdlog-* loaded by AWS/alb2sofelk.py) are grouped into one "AWS" target that runs the
   three AWS checklists without a role prompt.
3. Asks the role of each other host (or takes it from --role), and picks the checklists:
   the Windows or Linux baseline plus the role's checklist from hunting/checklists/.
4. Runs every query those checklists name through Elasticsearch's ES|QL _query API, in
   checklist order, ONCE per case (not once per host). The query's FROM line is rewritten
   to the case's own indexes of every host (so cross-host rarity columns such as
   host_count still compare the hosts of the case), the case is applied as a Query DSL
   filter, and each result row is routed to the host(s) it belongs to, by its _index,
   source_indices or indexes column, or by host.name. Queries that return _index also get
   `| WHERE _index IN (...)` before their final LIMIT, so hosts that did not ask for the
   query do not use up its LIMIT. Pivot queries (EX-15, C2-09), which hold example values
   from another engagement, are skipped unless --include-pivots is given.
5. Writes <output>/<host>/<category>/<Query_ID>_<host>.csv, where <category> is the
   query's tactic folder in the pack (00-triage, TA0002-execution, ...).
6. Writes <output>/<case>_supertimeline.csv, a log2timeline (l2tcsv) style timeline built
   from every timestamp in the results, sorted by time, plus <case>_run_summary.csv
   (one line per host and query: status, rows, file, error) and <case>_run.log.

Resource use is kept low on purpose: queries run one at a time, each response is written
to its CSV and released before the next query, and the super timeline is sorted on disk
(fixed-size sorted runs merged with heapq), so memory stays bounded by one ES|QL response
(ES|QL returns at most 10,000 rows by default) plus --timeline-chunk rows.

Standard library only (urllib), through the same retrying client as the importers.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import heapq
import json
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "Windows" / "common"))
from sof_elk_es_client import (  # noqa: E402
    EsClient, EsUnavailable, add_client_arguments, apply_client_arguments, log)

PACK = HERE / "hunting"
CHECKLISTS = PACK / "checklists"
QUERIES = PACK / "queries"

WINDOWS_BASELINE = "00-baseline-all-windows-hosts.md"
LINUX_BASELINE = "linux-baseline-all-hosts.md"
AWS_CHECKLISTS = ("aws-account-control-plane.md", "aws-web-application.md", "aws-vpc-network.md")

# Role -> (platform, checklists run after the platform baseline). The pack's Linux SSH jump
# host and container host checklists are not offered: every query they name is already in
# the Linux baseline (row 3.7 checks every Linux host for container abuse), so those
# hosts take the baseline plus whichever of these roles fits.
ROLES = {
    "windows-end-user": ("windows", ("end-user-workstation.md",)),
    "windows-web-server": ("windows", ("web-server.md",)),
    "windows-exchange-server": ("windows", ("exchange-server.md",)),
    "windows-database-server": ("windows", ("database-server.md",)),
    "windows-file-server": ("windows", ("file-server.md",)),
    "windows-domain-controller": ("windows", ("domain-controller.md",)),
    "linux-web-server": ("linux", ("linux-web-server.md",)),
    "linux-database-server": ("linux", ("linux-database-server.md",)),
    "linux-file-server": ("linux", ("linux-file-server.md",)),
    "linux-backup-server": ("linux", ("linux-backup-server.md",)),
    "linux-mail-server": ("linux", ("linux-mail-server.md",)),
    "linux-vpn-gateway": ("linux", ("linux-vpn-gateway.md",)),
}
ROLE_NAMES = list(ROLES)
BASELINES = {"windows": WINDOWS_BASELINE, "linux": LINUX_BASELINE}

# Index families written by the importers (same list as SOF-ELK_DeleteIndexes.py).
WINDOWS_FAMILIES = frozenset({
    "filesystem", "evtxlogs", "lnkfiles", "prefetch", "amcache", "shimcache", "registry",
    "jumplist", "shellbag", "recyclebin", "srum", "activitiescache", "clrusagelogs",
    "recentfilecache", "sqlitedb", "sum"})
LINUX_FAMILIES = frozenset({"logstash", "auditd", "bodyfile", "wtmp", "packages", "linuxconfig"})
SHARED_FAMILIES = frozenset({"browsinghistory", "httpdlog", "genericcsv"})
AWS_FAMILIES = frozenset({"aws-cloudtrail", "aws-vpcflow", "aws-waf"})
KNOWN_FAMILIES = sorted(WINDOWS_FAMILIES | LINUX_FAMILIES | SHARED_FAMILIES | AWS_FAMILIES,
                        key=len, reverse=True)
# SOF-ELK's own Logstash indexes (logstash-2026.10, httpdlog-2026.10.31) are not per host.
DATED_SUFFIX_RE = re.compile(r"^\d{4}\.\d{2}(\.\d{2})?$")
AWS_KEY = "aws"
AWS_NAME = "AWS"

FROM_RE = re.compile(r"^FROM\s+(?P<sources>.+?)\s+METADATA\s+_index\s*$", re.M)
LIMIT_RE = re.compile(r"^\|\s*LIMIT\s+(?P<n>\d+)\s*$")
HEADER_RE = re.compile(r"^//\s*(?P<id>[A-Z0-9]{2,5}-\d{2})\s*\|\s*(?P<title>.+?)\s*$")
SINCE_RE = re.compile(r'^(\|\s*EVAL\s+since\s*=\s*TO_DATETIME\()"[^"]*"(\))', re.M)
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
UNQUOTED_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
UNSAFE_PATH_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')

L2T_HEADER = ["date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host",
              "short", "desc", "version", "filename", "inode", "notes", "format", "extra"]
# Index family -> (l2tcsv source, sourcetype)
FAMILY_SOURCE = {
    "evtxlogs": ("EVT", "WinEVTX"),
    "filesystem": ("FILE", "NTFS $MFT/$J (MFTECmd)"),
    "lnkfiles": ("LNK", "Windows Shortcut"),
    "prefetch": ("LOG", "WinPrefetch"),
    "amcache": ("AMCACHE", "Amcache Registry Entry"),
    "shimcache": ("REG", "AppCompatCache Registry Key"),
    "registry": ("REG", "Registry Key"),
    "jumplist": ("LNK", "Jump List"),
    "shellbag": ("REG", "ShellBags"),
    "recyclebin": ("RECBIN", "Recycle Bin"),
    "browsinghistory": ("WEBHIST", "Browser History"),
    "srum": ("LOG", "SRUM"),
    "activitiescache": ("LOG", "Windows Timeline (ActivitiesCache)"),
    "clrusagelogs": ("LOG", ".NET CLR Usage Log"),
    "recentfilecache": ("LOG", "RecentFileCache"),
    "sqlitedb": ("LOG", "SQLite Database"),
    "sum": ("LOG", "User Access Logging (SUM)"),
    "genericcsv": ("LOG", "Generic CSV"),
    "logstash": ("LOG", "Syslog/Journal"),
    "auditd": ("LOG", "Linux Audit"),
    "bodyfile": ("FILE", "Bodyfile"),
    "wtmp": ("LOG", "UTMP/WTMP"),
    "packages": ("LOG", "Package Manager"),
    "linuxconfig": ("FILE", "Linux Configuration"),
    "httpdlog": ("LOG", "Web Server Access Log"),
    "aws-cloudtrail": ("LOG", "AWS CloudTrail"),
    "aws-vpcflow": ("LOG", "AWS VPC Flow Log"),
    "aws-waf": ("LOG", "AWS WAF Log"),
}
# Columns that name the user, the evidence file and the inode, most specific first.
USER_COLUMNS = ("user.name", "winlog.user.name", "source.user.name", "aws.cloudtrail.user_identity.arn",
                "user", "users", "account", "accounts", "principal", "user.id", "winlog.user.identifier")
FILE_COLUMNS = ("kape.source_file", "log.file.path", "file.path", "process.executable", "url.original")
# Columns that say which index (and so which host) a result row came from.
INDEX_COLUMNS = ("_index", "source_indices", "indexes")
HOST_COLUMNS = ("host.name", "host_names", "hosts")
INODE_COLUMNS = ("file.inode", "kape.mft.entry_number", "filesystem.entry_number")
SUMMARY_HEADER = ["host", "roles", "checklists", "query_id", "title", "category", "status", "rows",
                  "truncated", "seconds", "file", "checklist_rows", "error"]


# --------------------------------------------------------------------------- checklists

@dataclass
class Query:
    qid: str
    title: str
    path: Path
    category: str
    text: str
    families: list[str]
    limit: int | None
    keeps_index: bool = False      # `_index` is an output column (KEEP _index / STATS ... BY _index)

    @property
    def pivot(self):
        """Pivot queries carry engagement-specific values (file names, accounts) to edit."""
        return "(pivot)" in self.title.lower()

    @property
    def coverage(self):
        """Data-coverage queries report earliest/latest dates, which are not events."""
        return "coverage" in self.title.lower()


_QUERY_CACHE: dict[Path, Query] = {}


def family_of_pattern(pattern):
    """'amcache-*' -> 'amcache'; 'aws-cloudtrail-*' -> 'aws-cloudtrail'."""
    return pattern.strip().strip('"').rstrip("*").rstrip("-")


def outputs_index(text):
    """True when the query's last KEEP or STATS ... BY returns `_index` as its own column."""
    last = None
    for command in re.split(r"\n\s*\|", re.sub(r"//[^\n]*", "", text)):
        command = command.strip()
        if re.match(r"(KEEP|STATS)\b", command):
            last = command
    if last is None:
        return True          # no KEEP/STATS: every column, _index included, is returned
    columns = last[4:] if last.startswith("KEEP") else (re.split(r"\bBY\b", last)[1:] or [""])[-1]
    return bool(re.search(r"(^|[\s,])_index\s*(,|$)", columns))


def load_query(folder: Path) -> Query:
    folder = folder.resolve()
    if folder in _QUERY_CACHE:
        return _QUERY_CACHE[folder]
    path = folder / "query.esql"
    text = path.read_text(encoding="utf-8")
    header = HEADER_RE.match(text.splitlines()[0]) if text else None
    if not header:
        raise SystemExit(f"ERROR: {path} has no '// ID | title' header line")
    match = FROM_RE.search(text)
    if not match:
        raise SystemExit(f"ERROR: {path} has no 'FROM ... METADATA _index' line")
    families = [family_of_pattern(p) for p in match.group("sources").split(",") if p.strip()]
    last = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("//")][-1]
    limit = LIMIT_RE.match(last.strip())
    query = Query(qid=header.group("id"), title=header.group("title"), path=path,
                  category=folder.parent.name, text=text, families=families,
                  limit=int(limit.group("n")) if limit else None, keeps_index=outputs_index(text))
    _QUERY_CACHE[folder] = query
    return query


def checklist_title(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].replace("Checklist:", "").strip()
    return path.stem


def parse_checklist(path: Path):
    """Yield (row number, check text, query folder) for every query link in the checklist tables.

    Uses the layout the pack's README describes (and build_checklist_xlsx.py reads):
    "## N. Section" headings, each with a table #, Check, Queries, IR ref, What to look for.
    """
    in_table_section = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            in_table_section = not line[3:].strip().lower().startswith("not covered")
            continue
        if not in_table_section or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] in ("#", "") or set(cells[0]) <= set("-:"):
            continue
        check = LINK_RE.sub(r"\1", cells[1]).replace("`", "")
        for _label, target in LINK_RE.findall(cells[2]):
            folder = (path.parent / target).resolve()
            if (folder / "query.esql").is_file():
                yield cells[0], check, folder
            else:
                log.warning("%s row %s links to %s, which has no query.esql", path.name, cells[0], target)


@dataclass
class PlanItem:
    query: Query
    refs: list[str] = field(default_factory=list)   # "Baseline: all Windows hosts 5.4"


def build_plan(checklist_files):
    """Ordered {query id: PlanItem}; each query runs once even if several rows name it."""
    plan: dict[str, PlanItem] = {}
    for name in checklist_files:
        path = CHECKLISTS / name
        if not path.is_file():
            raise SystemExit(f"ERROR: checklist {path} is missing; this role has no checklist to run")
        title = checklist_title(path)
        for row, _check, folder in parse_checklist(path):
            query = load_query(folder)
            item = plan.setdefault(query.qid, PlanItem(query))
            ref = f"{title} {row}"
            if ref not in item.refs:
                item.refs.append(ref)
    return plan


# --------------------------------------------------------------------------- discovery

@dataclass
class Target:
    key: str                       # index suffix (lower case), or "aws"
    name: str                      # display name used for the folder and file names
    indexes: dict[str, list[str]] = field(default_factory=dict)   # family -> [index]
    docs: int = 0
    os_hint: str = ""
    roles: list[str] = field(default_factory=list)

    @property
    def is_aws(self):
        return self.key == AWS_KEY

    def all_indexes(self):
        return sorted(i for idx in self.indexes.values() for i in idx)

    def platform_guess(self):
        if self.os_hint in ("windows", "linux"):
            return self.os_hint
        fams = set(self.indexes)
        win, lin = len(fams & WINDOWS_FAMILIES), len(fams & LINUX_FAMILIES)
        return "windows" if win > lin else "linux" if lin > win else ""


def case_query(case):
    return {"term": {"case": {"value": case, "case_insensitive": True}}}


def find_case_indexes(client, case):
    """{index: number of documents of this case}, over all open non-hidden indexes."""
    body = {"size": 0, "track_total_hits": False, "query": case_query(case),
            "aggs": {"indexes": {"terms": {"field": "_index", "size": 10000}}}}
    status, payload = client.request(
        "POST", "/*,-.*/_search?ignore_unavailable=true&allow_no_indices=true", body)
    if status >= 300 or not isinstance(payload, dict):
        raise SystemExit(f"ERROR: could not search for case '{case}': HTTP {status}: {payload}")
    buckets = payload.get("aggregations", {}).get("indexes", {}).get("buckets", [])
    return {str(b["key"]): int(b.get("doc_count", 0)) for b in buckets if b.get("key")}


PROFILE_FIELDS = ("host.name", "labels.evidence_source", "cloud.provider", "host.os.type")


def index_profile(client, index, case):
    """Most common value of each PROFILE_FIELDS field among the case's documents in index."""
    def search(fields):
        body = {"size": 0, "track_total_hits": False, "query": case_query(case),
                "aggs": {f: {"terms": {"field": f, "size": 1}} for f in fields}}
        return client.request("POST", f"/{quote(index, safe='')}/_search", body)

    status, payload = search(PROFILE_FIELDS)
    results = {}
    if status < 300 and isinstance(payload, dict):
        aggs = payload.get("aggregations", {})
        for f in PROFILE_FIELDS:
            buckets = aggs.get(f, {}).get("buckets", [])
            if buckets:
                results[f] = str(buckets[0].get("key"))
        return results
    # A field that is text (not aggregatable) in this index fails the whole request: ask one by one.
    for f in PROFILE_FIELDS:
        status, payload = search((f,))
        if status < 300 and isinstance(payload, dict):
            buckets = payload.get("aggregations", {}).get(f, {}).get("buckets", [])
            if buckets:
                results[f] = str(buckets[0].get("key"))
    return results


def split_index(index):
    """'amcache-rd01' -> ('amcache', 'rd01'); unknown families -> (None, None)."""
    for fam in KNOWN_FAMILIES:
        if index.startswith(fam + "-") and len(index) > len(fam) + 1:
            return fam, index[len(fam) + 1:]
    return None, None


def safe_name(text):
    return UNSAFE_PATH_RE.sub("_", text).strip(" .") or "unnamed"


def group_targets(client, case, counts):
    """Group the case's indexes into hosts (by index suffix) and one AWS target."""
    targets: dict[str, Target] = {}
    skipped = []
    profiles = {}
    for index in sorted(counts):
        fam, suffix = split_index(index)
        if fam is None:
            skipped.append((index, "not a toolkit index family"))
            continue
        if DATED_SUFFIX_RE.match(suffix):
            skipped.append((index, "SOF-ELK dated index, not a per-host index"))
            continue
        profiles[index] = index_profile(client, index, case)
    # Suffixes that also have a non-AWS host index (a Linux web server's httpdlog-<host>).
    host_suffixes = {split_index(i)[1] for i, p in profiles.items()
                     if split_index(i)[0] not in AWS_FAMILIES | {"httpdlog"}
                     and p.get("cloud.provider") != "aws"}
    for index, prof in profiles.items():
        fam, suffix = split_index(index)
        is_aws = (fam in AWS_FAMILIES or prof.get("cloud.provider") == "aws"
                  or (fam == "httpdlog" and "labels.evidence_source" in prof)
                  or (fam == "httpdlog" and "host.name" not in prof and suffix not in host_suffixes))
        if is_aws:
            target = targets.setdefault(AWS_KEY, Target(AWS_KEY, AWS_NAME))
        else:
            name = prof.get("host.name") or suffix.upper()
            if name.lower() != suffix and re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("._-") != suffix:
                name = suffix.upper()
            target = targets.setdefault(suffix, Target(suffix, safe_name(name)))
            if prof.get("host.os.type") and not target.os_hint:
                target.os_hint = prof["host.os.type"].lower()
        target.indexes.setdefault(fam, []).append(index)
        target.docs += counts[index]
    hosts = sorted((t for t in targets.values() if not t.is_aws), key=lambda t: t.name.lower())
    aws = targets.get(AWS_KEY)
    return hosts, aws, skipped


# --------------------------------------------------------------------------- roles

def parse_role_answer(answer):
    """'1', '1,6', 'windows-web-server', 'skip' -> list of role names (empty = skip).

    Raises ValueError on anything else.
    """
    answer = answer.strip().lower()
    if answer in ("s", "skip", "-"):
        return []
    roles = []
    for part in re.split(r"[,+\s]+", answer):
        if not part:
            continue
        if part.isdigit() and 1 <= int(part) <= len(ROLE_NAMES):
            role = ROLE_NAMES[int(part) - 1]
        elif part in ROLES:
            role = part
        else:
            raise ValueError(f"'{part}' is not a role number or name")
        if role not in roles:
            roles.append(role)
    if not roles:
        raise ValueError("no role given")
    platforms = {ROLES[r][0] for r in roles}
    if len(platforms) > 1:
        raise ValueError("pick Windows roles or Linux roles for a host, not both")
    return roles


def print_role_menu(out=None):
    out = out or sys.stdout
    print("\nHost roles (several roles for one host: separate them with commas, e.g. 6,5;"
          " 's' skips the host):", file=out)
    for n, role in enumerate(ROLE_NAMES, 1):
        print(f"  {n:>2}. {role}", file=out)


def ask_roles(target, input_fn=input):
    guess = target.platform_guess()
    families = ", ".join(f"{f} ({len(i)})" if len(i) > 1 else f for f, i in sorted(target.indexes.items()))
    print(f"\nHost {target.name}: {target.docs:,} document(s) in {families}"
          + (f"; looks like {guess.capitalize()}" if guess else ""))
    while True:
        try:
            answer = input_fn(f"Role of {target.name}: ")
        except EOFError:
            raise SystemExit("\nERROR: no answer for the host role (stdin closed); use --role HOST=ROLE") from None
        try:
            roles = parse_role_answer(answer)
        except ValueError as exc:
            print(f"  {exc}; answer with a number from 1 to {len(ROLE_NAMES)}, a role name, or 's'")
            continue
        if roles and guess and ROLES[roles[0]][0] != guess:
            print(f"  note: {target.name} looks like {guess.capitalize()}, but a "
                  f"{ROLES[roles[0]][0].capitalize()} role was picked; its queries will find no data "
                  "unless the indexes match")
        return roles


def checklists_for(target):
    if target.is_aws:
        return list(AWS_CHECKLISTS)
    if not target.roles:
        return []
    platform = ROLES[target.roles[0]][0]
    files = [BASELINES[platform]]
    for role in target.roles:
        for name in ROLES[role][1]:
            if name not in files:
                files.append(name)
    return files


# --------------------------------------------------------------------------- queries

def index_list(indexes):
    return ", ".join(i if UNQUOTED_INDEX_RE.match(i) else f'"{i}"' for i in indexes)


def build_query(query: Query, from_indexes, keep_indexes=None, since=None):
    """The query with its FROM line pointed at from_indexes.

    keep_indexes, when given, adds `| WHERE _index IN (...)` just before the final LIMIT
    (every query in the pack keeps _index in its output), so only this host's rows are
    returned while earlier STATS/INLINE STATS still see every host in from_indexes.
    """
    text = FROM_RE.sub(lambda m: f"FROM {index_list(from_indexes)} METADATA _index", query.text, count=1)
    if since:
        text = SINCE_RE.sub(lambda m: f'{m.group(1)}"{since}"{m.group(2)}', text)
    if keep_indexes:
        values = ", ".join(json.dumps(i) for i in keep_indexes)
        where = f"| WHERE _index IN ({values})"
        lines = text.rstrip().splitlines()
        for pos in range(len(lines) - 1, -1, -1):
            stripped = lines[pos].strip()
            if not stripped or stripped.startswith("//"):
                continue
            if LIMIT_RE.match(stripped):
                lines.insert(pos, where)
            else:
                lines.append(where)
            break
        text = "\n".join(lines) + "\n"
    return text


def run_esql(client, text, case):
    """POST /_query; returns (status, payload). The case filter is applied as Query DSL."""
    body = {"query": text, "filter": case_query(case)}
    return client.request("POST", "/_query", body)


def error_text(payload):
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            reason = err.get("reason") or err.get("type") or ""
            causes = err.get("root_cause") or []
            if not reason and causes and isinstance(causes[0], dict):
                reason = causes[0].get("reason", "")
            return f"{err.get('type', 'error')}: {reason}".strip()
        if err:
            return str(err)
    return str(payload)[:500]


def cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return " | ".join(cell(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


# --------------------------------------------------------------------------- super timeline

ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def sort_key(value):
    """ES date / date_nanos text -> 'YYYY-MM-DDTHH:MM:SS.nnnnnnnnn' in UTC, or None."""
    if not isinstance(value, str):
        return None
    m = ISO_RE.match(value.strip())
    if not m:
        return None
    day, clock, frac, zone = m.groups()
    frac = (frac or "")[:9].ljust(9, "0")
    if zone and zone != "Z" and zone.replace(":", "") not in ("+0000", "-0000"):
        try:
            dt = datetime.fromisoformat(f"{day}T{clock}{zone[:3]}:{zone[-2:]}").astimezone(timezone.utc)
        except ValueError:
            return None
        day, clock = dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")
    return f"{day}T{clock}.{frac}"


def macb(column_names):
    flags = {"M": False, "A": False, "C": False, "B": False}
    for name in column_names:
        n = name.lower()
        if any(t in n for t in ("creat", "birth", "btime", "install")):
            flags["B"] = True
        if any(t in n for t in ("modif", "mtime", "last_write", "write")):
            flags["M"] = True
        if any(t in n for t in ("access", "atime")):
            flags["A"] = True
        if any(t in n for t in ("ctime", "change", "metadata")):
            flags["C"] = True
    return "".join(k if v else "." for k, v in flags.items())


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def first_value(value):
    if isinstance(value, list):
        return next((v for v in value if v not in (None, "")), None)
    return value


def pick(row_map, names, default="-"):
    for name in names:
        value = first_value(row_map.get(name))
        if value not in (None, ""):
            return cell(value)
    return default


def one_line(text, limit):
    text = re.sub(r"[\r\n\t]+", " ", text)
    return text if len(text) <= limit else text[:limit - 3] + "..."


class Timeline:
    """Collects timeline rows into sorted runs on disk and merges them at the end."""

    def __init__(self, workdir: Path, chunk_rows=50000, desc_limit=4000):
        self.workdir = workdir
        self.chunk_rows = max(1000, chunk_rows)
        self.desc_limit = desc_limit
        self.buffer: list[list[str]] = []
        self.runs: list[Path] = []
        self.count = 0

    def add_row(self, target: Target, item: PlanItem, names, date_cols, values_row, rel_file):
        """Turn one result row into timeline rows (one per distinct timestamp in the row)."""
        query = item.query
        row_map = dict(zip(names, values_row))
        stamps: dict[str, list[str]] = {}
        for i in date_cols:
            raw = values_row[i] if i < len(values_row) else None
            if isinstance(raw, list):
                keys = sorted(k for k in (sort_key(v) for v in raw) if k)
                key = keys[0] if keys else None
                label = f"{names[i]} (earliest of {len(raw)})" if len(raw) > 1 else names[i]
            else:
                key, label = sort_key(raw), names[i]
            if key:
                stamps.setdefault(key, []).append(label)
        if not stamps:
            return 0
        # The row's index: this target's own one when the row lists several (stacked rows).
        listed = [str(v) for name in INDEX_COLUMNS for v in as_list(row_map.get(name)) if v]
        own = set(target.all_indexes())
        index = next((i for i in listed if i in own), listed[0] if listed else "")
        fam, suffix = split_index(index) if index else (None, None)
        source, sourcetype = FAMILY_SOURCE.get(fam, ("LOG", fam or "ES|QL"))
        details = []
        for i, name in enumerate(names):
            if i in date_cols or name in INDEX_COLUMNS:
                continue
            value = cell(values_row[i] if i < len(values_row) else None)
            if value != "":
                details.append(f"{name}: {value}")
        desc = one_line(f"[{query.qid}] {query.title} | " + "; ".join(details), self.desc_limit)
        meaning = pick(row_map, ("kape.timestamp_meaning", "ts_meaning"), "")
        host = target.name if not target.is_aws else (suffix or AWS_NAME)
        user = pick(row_map, USER_COLUMNS)
        filename = pick(row_map, FILE_COLUMNS, f"ES:{index}" if index else "-")
        inode = pick(row_map, INODE_COLUMNS)
        notes = "; ".join(item.refs) or "-"
        for key, labels in stamps.items():
            kind = "; ".join(labels)
            if meaning and labels in (["@timestamp"], ["ts"]):
                kind = meaning
            self._add([
                key,
                f"{key[5:7]}/{key[8:10]}/{key[0:4]}", key[11:19], "UTC", macb(labels),
                source, sourcetype, one_line(kind, 200), user, host,
                one_line(desc, 80), desc, "2", filename, inode, notes,
                f"esql/{query.qid}",
                f"query_id: {query.qid}; category: {query.category}; _index: {index or '-'}; "
                f"timestamp_column: {kind}; result_file: {rel_file}",
            ])
        return len(stamps)

    def _add(self, row):
        self.buffer.append(row)
        self.count += 1
        if len(self.buffer) >= self.chunk_rows:
            self._flush()

    def _flush(self):
        if not self.buffer:
            return
        self.buffer.sort()
        path = self.workdir / f"run-{len(self.runs):05d}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerows(self.buffer)
        self.runs.append(path)
        self.buffer = []

    def write(self, out_path: Path):
        """Merge the sorted runs into out_path, dropping exact duplicate rows. Returns rows written."""
        self._flush()
        # Merge at most 200 runs at a time so the number of open files stays small.
        runs = list(self.runs)
        level = 0
        while len(runs) > 200:
            merged = []
            for start in range(0, len(runs), 200):
                path = self.workdir / f"merge-{level}-{start:05d}.csv"
                self._merge(runs[start:start + 200], path, final=False)
                merged.append(path)
            runs, level = merged, level + 1
        return self._merge(runs, out_path, final=True)

    @staticmethod
    def _merge(paths, out_path, final):
        files = [p.open(newline="", encoding="utf-8") for p in paths]
        written = 0
        try:
            readers = [csv.reader(fh) for fh in files]
            with out_path.open("w", newline="", encoding="utf-8") as out:
                writer = csv.writer(out)
                if final:
                    writer.writerow(L2T_HEADER)
                previous = None
                for row in heapq.merge(*readers):
                    if row == previous:
                        continue
                    previous = row
                    writer.writerow(row[1:] if final else row)
                    written += 1
        finally:
            for fh in files:
                fh.close()
        for p in paths:
            if p != out_path:
                try:
                    p.unlink()
                except OSError:
                    pass
        return written


# --------------------------------------------------------------------------- runner

def ordered_queries(plans):
    """Union of the targets' plans, in checklist order (first target's order first)."""
    order: dict[str, Query] = {}
    for plan in plans.values():
        for qid, item in plan.items():
            order.setdefault(qid, item.query)
    return order


class RowRouter:
    """Decides which target(s) a result row belongs to.

    Rows name their index in _index, or (stacked queries) list it in source_indices or
    indexes; Linux queries that group by host give host.name. A stacked row seen on several
    hosts goes to each of them. A result with none of these columns is a case-wide stack
    (PR-01, LEX-03), and every requesting target gets the whole result.
    """

    def __init__(self, columns, targets):
        # Only text columns can name an index or host ("hosts" is a count in some queries).
        text_cols = [(i, c.get("name", "")) for i, c in enumerate(columns)
                     if c.get("type") in ("keyword", "text")]
        self.index_cols = [i for i, n in text_cols if n in INDEX_COLUMNS]
        self.host_cols = [i for i, n in text_cols if n in HOST_COLUMNS]
        self.by_index = {i: t for t in targets for i in t.all_indexes()}
        self.by_name = {}
        for t in targets:
            self.by_name[t.name.lower()] = t
            self.by_name[t.key] = t
        self.targets = targets
        self.case_wide = not self.index_cols and not self.host_cols

    def owners(self, row):
        if self.case_wide:
            return self.targets
        found = []
        for i in self.index_cols:
            for value in as_list(row[i] if i < len(row) else None):
                t = self.by_index.get(str(value))
                if t is not None and t not in found:
                    found.append(t)
        if not found:
            for i in self.host_cols:
                for value in as_list(row[i] if i < len(row) else None):
                    t = self.by_name.get(str(value).lower()) if isinstance(value, str) else None
                    if t is not None and t not in found:
                        found.append(t)
        return found


def run_group(client, case, targets, peers, out_dir, timeline, summary, args, totals):
    """Run every query the targets' checklists name, once each, and route rows to the targets.

    peers: every target in the same group (all hosts of the case, or the AWS group); the
    query reads all their indexes, so rarity across hosts still works, but only rows of
    the targets that asked for the query are written.
    """
    plans = {t.key: build_plan(checklists_for(t)) for t in targets}
    queries = ordered_queries(plans)
    total = len(queries)
    for t in targets:
        files = checklists_for(t)
        print(f"\n{t.name}: {', '.join(t.roles) or 'AWS'} -> {len(plans[t.key])} queries from {', '.join(files)}")
        log.info("target %s roles=%s checklists=%s indexes=%s", t.name, t.roles, files, t.all_indexes())
    print(f"\nRunning {total} distinct queries for {len(targets)} target(s)")

    def record(target, query, status, **extra):
        item = plans[target.key][query.qid]
        row = {"host": target.name, "roles": ",".join(target.roles) or "aws",
               "checklists": "; ".join(checklists_for(target)), "query_id": query.qid,
               "title": query.title, "category": query.category, "status": status, "rows": 0,
               "truncated": "", "seconds": "", "file": "", "checklist_rows": "; ".join(item.refs),
               "error": ""}
        row.update(extra)
        summary.writerow([row.get(k, "") for k in SUMMARY_HEADER])
        totals[status] = totals.get(status, 0) + 1

    for n, (qid, query) in enumerate(queries.items(), 1):
        prefix = f"  [{n:>3}/{total}] {qid:<8}"
        wanted = [t for t in targets if qid in plans[t.key]]
        if query.pivot and not args.include_pivots:
            for t in wanted:
                record(t, query, "skipped", error="pivot query: edit its values and run it by hand, "
                                                  "or use --include-pivots")
            print(f"{prefix} skipped (pivot query)")
            continue
        runnable = [t for t in wanted if any(t.indexes.get(f) for f in query.families)]
        for t in wanted:
            if t not in runnable:
                record(t, query, "no-data", error="no index for " + ", ".join(f"{f}-*" for f in query.families))
        if not runnable:
            print(f"{prefix} no data ({', '.join(query.families)})")
            continue
        from_idx = sorted(i for t in peers for f in query.families for i in t.indexes.get(f, []))
        keep = sorted(i for t in runnable for f in query.families for i in t.indexes.get(f, []))
        text = build_query(query, from_idx, keep if (query.keeps_index and keep != from_idx) else None,
                           args.since)
        log.debug("query %s for %s:\n%s", qid, ", ".join(t.name for t in runnable), text,
                  extra={"file_only": True})
        started = time.monotonic()
        status, payload = run_esql(client, text, case)
        seconds = f"{time.monotonic() - started:.1f}"
        if status >= 300 or not isinstance(payload, dict) or "columns" not in payload:
            message = error_text(payload)
            log.error("%s failed: HTTP %s: %s", qid, status, message)
            for t in runnable:
                record(t, query, "error", seconds=seconds, error=f"HTTP {status}: {message}")
            print(f"{prefix} ERROR HTTP {status}: {message[:160]}")
            continue

        columns = payload.get("columns") or []
        values = payload.get("values") or []
        partial = bool(payload.get("is_partial"))
        del payload
        names = [c.get("name", "") for c in columns]
        date_cols = [i for i, c in enumerate(columns) if c.get("type") in ("date", "date_nanos")]
        in_timeline = bool(date_cols) and not query.coverage and qid not in args.timeline_exclude
        router = RowRouter(columns, runnable)
        outputs = {}
        try:
            for t in runnable:
                rel = Path(t.name) / query.category / f"{qid}_{t.name}.csv"
                path = out_dir / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                fh = path.open("w", newline="", encoding="utf-8")
                writer = csv.writer(fh)
                writer.writerow(names)
                outputs[t.key] = [fh, writer, 0, 0, rel.as_posix()]
            for row in values:
                for t in router.owners(row):
                    out = outputs[t.key]
                    out[1].writerow([cell(v) for v in row])
                    out[2] += 1
                    if in_timeline:
                        out[3] += timeline.add_row(t, plans[t.key][qid], names, date_cols, row, out[4])
        finally:
            for out in outputs.values():
                out[0].close()
        truncated = partial or bool(query.limit and len(values) >= query.limit)
        parts = []
        for t in runnable:
            _fh, _w, rows, events, rel = outputs[t.key]
            record(t, query, "ok" if rows else "empty", rows=rows, file=rel, seconds=seconds,
                   truncated="yes" if truncated else "",
                   error="case-wide result (rows are not tied to one host)" if router.case_wide else "")
            parts.append(f"{t.name}: {rows}")
        note = "  (hit the query LIMIT; more rows exist)" if truncated else ""
        print(f"{prefix} {len(values):>6} row(s) in {seconds}s -> {', '.join(parts)}{note}")
        del values


def parse_role_args(values):
    """['RD01=1,6', 'web01=linux-web-server'] -> {'rd01': [...]}"""
    roles = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"ERROR: --role must be HOST=ROLE[,ROLE], got '{value}'")
        host, answer = value.split("=", 1)
        try:
            roles[host.strip().lower()] = parse_role_answer(answer)
        except ValueError as exc:
            raise SystemExit(f"ERROR: --role {value}: {exc}") from None
    return roles


def normalize_since(value):
    if not value:
        return None
    text = value.strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        text += "T00:00:00Z"
    if not ISO_RE.match(text):
        raise SystemExit("ERROR: --since must look like 2026-10-01 or 2026-10-01T08:00:00Z")
    if not re.search(r"(Z|[+-]\d{2}:?\d{2})$", text):
        text += "Z"
    return text


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the hunting pack's role checklists for a case and write the results as CSV, "
                    "plus a super timeline.")
    parser.add_argument("case", help="Case name, as given to the importers with --case (upper/lower case ignored)")
    parser.add_argument("output_dir", help="Directory for the results (created if missing)")
    parser.add_argument("--role", action="append", default=[], metavar="HOST=ROLE[,ROLE]",
                        help="Role of a host without asking, by number or name (repeatable), "
                             "e.g. --role RD01=windows-end-user --role DC01=6. ROLE 'skip' skips the host.")
    parser.add_argument("--since", help="Start of the incident window (2026-10-01 or 2026-10-01T08:00:00Z), "
                                        "set in the queries' `since` lines")
    parser.add_argument("--include-pivots", action="store_true",
                        help="Also run pivot queries (EX-15, C2-09), which still hold example values")
    parser.add_argument("--no-aws", action="store_true", help="Do not run the AWS checklists")
    parser.add_argument("--only", action="append", default=[], metavar="HOST",
                        help="Run only these hosts (repeatable; use AWS for the AWS group)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Find the hosts, ask the roles and list the queries; run nothing")
    parser.add_argument("--timeline-exclude", action="append", default=[], metavar="QUERY_ID",
                        help="Leave this query's results out of the super timeline (repeatable). "
                             "Data-coverage queries are always left out.")
    parser.add_argument("--timeline-chunk", type=int, default=50000,
                        help="Timeline rows held in memory before a sorted run is written to disk")
    parser.add_argument("--desc-limit", type=int, default=4000,
                        help="Maximum length of a timeline 'desc' cell")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username, if security is enabled")
    parser.add_argument("--password", help="Elasticsearch password (asked for when --user is given without it)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    add_client_arguments(parser)
    args = parser.parse_args(argv)
    args.timeline_exclude = {q.strip().upper() for q in args.timeline_exclude}
    args.since = normalize_since(args.since)
    return args


def main(argv=None, input_fn=input):
    args = parse_args(argv)
    out_dir = Path(args.output_dir).expanduser().resolve()
    case_file = safe_name(args.case)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        if not args.log_file:
            args.log_file = str(out_dir / f"{case_file}_run.log")
    apply_client_arguments(args)
    if args.user and args.password is None:
        args.password = getpass.getpass(f"Elasticsearch password for {args.user}: ")
    client = EsClient(args.es, args.user, args.password, args.insecure)
    preset = parse_role_args(args.role)
    only = {h.strip().lower() for h in args.only}

    try:
        print(f"Elasticsearch: {args.es}\nCase: {args.case}")
        counts = find_case_indexes(client, args.case)
        if not counts:
            print(f"\nNo index holds documents with case = '{args.case}'. Check the name given to the "
                  "importers' --case option.")
            return 1
        hosts, aws, skipped = group_targets(client, args.case, counts)
        print(f"Found {len(counts)} index(es): {len(hosts)} host(s)" + (", plus AWS" if aws else ""))
        for index, why in skipped:
            print(f"  ignoring {index}: {why}")
        if aws:
            print(f"  AWS: {', '.join(aws.all_indexes())} (runs the AWS checklists, no role needed)")
        all_hosts = list(hosts)
        if only:
            hosts = [h for h in hosts if h.name.lower() in only or h.key in only]
            if aws and "aws" not in only:
                aws = None
        if args.no_aws:
            aws = None

        asked = False
        for host in hosts:
            given = preset.get(host.name.lower(), preset.get(host.key))
            if given is not None:
                host.roles = given
                print(f"\nHost {host.name}: role {', '.join(given) or 'skip'} (from --role)")
                continue
            if not asked:
                if not sys.stdin.isatty() and input_fn is input:
                    raise SystemExit(f"ERROR: stdin is not a terminal, so the role of {host.name} cannot be "
                                     "asked; give every host with --role HOST=ROLE")
                print_role_menu()
                asked = True
            host.roles = ask_roles(host, input_fn)
        targets = [h for h in hosts if h.roles] + ([aws] if aws else [])
        if not targets:
            print("\nNothing to run.")
            return 0

        if args.dry_run:
            for target in targets:
                files = checklists_for(target)
                plan = build_plan(files)
                print(f"\n{target.name} ({', '.join(target.roles) or 'AWS'}): {len(plan)} queries "
                      f"from {', '.join(files)}")
                for qid, item in plan.items():
                    have = [f for f in item.query.families if target.indexes.get(f)]
                    state = ("pivot, skipped" if item.query.pivot and not args.include_pivots
                             else "runs" if have else "no data")
                    print(f"  {item.query.category}/{qid}_{target.name}.csv  [{state}]  {item.query.title}")
            print("\nDry run: no query was run.")
            return 0

        workdir = Path(tempfile.mkdtemp(prefix=".timeline-", dir=out_dir))
        timeline = Timeline(workdir, args.timeline_chunk, args.desc_limit)
        totals: dict[str, int] = {}
        summary_path = out_dir / f"{case_file}_run_summary.csv"
        aborted = None
        try:
            with summary_path.open("w", newline="", encoding="utf-8") as sfh:
                summary = csv.writer(sfh)
                summary.writerow(SUMMARY_HEADER)
                groups = [([h for h in targets if not h.is_aws], all_hosts)]
                if aws in targets:
                    groups.append(([aws], [aws]))
                for group, peers in groups:
                    if not group:
                        continue
                    try:
                        run_group(client, args.case, group, peers, out_dir, timeline, summary, args, totals)
                    except EsUnavailable as exc:
                        aborted = f"Elasticsearch became unreachable ({exc})"
                        break
                    except KeyboardInterrupt:
                        aborted = "interrupted"
                        break
                    finally:
                        sfh.flush()
            timeline_path = out_dir / f"{case_file}_supertimeline.csv"
            print(f"\nWriting the super timeline ({timeline.count:,} event(s) before de-duplication)...")
            written = timeline.write(timeline_path)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        print("\nDone: " + ", ".join(f"{v} {k}" for k, v in totals.items() if v))
        print(f"  results:        {out_dir}")
        print(f"  super timeline: {timeline_path} ({written:,} row(s))")
        print(f"  run summary:    {summary_path}")
        print(f"  log:            {args.log_file}")
        if aborted:
            print(f"\nERROR: {aborted}; the run stopped early. Everything up to that point was "
                  "written, including the super timeline.", file=sys.stderr)
            return 2
        return 1 if totals.get("error") else 0
    except EsUnavailable as exc:
        print(f"ERROR: Elasticsearch is unreachable at {args.es}: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
