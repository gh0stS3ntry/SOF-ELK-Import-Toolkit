#!/usr/bin/env python3
"""Delete the toolkit indexes of one evidence host, one case, or both.

Every importer in this toolkit writes one index per evidence host, named
<prefix>-<hostname> (amcache-rd01, filesystem-rd01, aws-cloudtrail-prod, ...), and
stores the optional --case ID in every document's `case` field. This script finds
the indexes for a hostname (--hostname) or a case ID (--case), lists them, asks for
confirmation and deletes them, for example to reload a host from scratch or to clear
a finished or test case.

By hostname, matching is deliberately strict so that a similar hostname is never caught:

* The hostname is normalized exactly as the importers do it (lower-case, other
  characters replaced by "-"), and only indexes whose name ends in "-<hostname>" are
  considered. "rd01" does not match "rd011" or "rd01-old".
* Each candidate's documents are then checked. When they carry host.name (Windows and
  Generic-CSV importers) or labels.evidence_source (AWS importers), the index is
  selected only if that value is the hostname. This keeps "amcache-ws-01" (host
  ws-01) safe when deleting host "01".
* An index whose documents do not say which host they came from (empty, closed, or
  loaded by an older importer) is selected only when the part before "-<hostname>"
  is one of the toolkit's own prefixes, or one given with --prefix.

By case, the case ID is not part of the index name, so every (non-hidden) index is
searched for documents whose `case` equals the ID (ignoring upper/lower case). An
index is deleted only when ALL of its documents belong to that case. An index that
also holds documents from another case, or without a case (the same host imported
twice under different --case values), is listed and left alone, so another case's
evidence is never removed. Closed indexes cannot be searched and are skipped.

With both --hostname and --case, only that host's indexes whose documents all belong
to the case are deleted.

Deletion is irreversible: the script lists the selected indexes first and requires
the hostname (or case ID) to be typed back, unless --yes is given. --dry-run only
lists them. Kibana Data Views use wildcards (amcache-*, ...), so they are not touched.

Standard library only.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "Windows" / "common"))
from sof_elk_es_client import EsClient, EsUnavailable, add_client_arguments, apply_client_arguments  # noqa: E402

# Index prefixes written by the importers in this repository.
TOOLKIT_PREFIXES = frozenset({
    # Windows/csv_importers
    "browsinghistory", "clrusagelogs", "jumplist", "shellbag", "amcache", "shimcache",
    "registry", "recyclebin", "recentfilecache", "sqlitedb", "srum", "sum", "activitiescache",
    # Windows/json_importers
    "filesystem", "evtxlogs", "lnkfiles", "prefetch",
    # AWS (httpdlog also holds Linux/httpd2sofelk.py web server logs)
    "aws-cloudtrail", "aws-vpcflow", "aws-waf", "httpdlog",
    # Generic-CSV
    "genericcsv",
    # Linux (journal, text syslog and vsftpd share SOF-ELK's logstash family; web logs go to
    # httpdlog and browser history to browsinghistory, both listed above)
    "logstash",
})

# Fields that record which evidence host (or AWS evidence source) a document came from.
OWNER_FIELDS = ("host.name", "labels.evidence_source")


def sanitize_hostname(hostname):
    """Same normalization as the importers: rd01 / RD01 / "RD 01" -> rd01 / rd01 / rd-01."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise SystemExit("ERROR: hostname must contain at least one letter or digit")
    return value


def list_indexes(client, pattern="*"):
    """Indexes matching pattern, as dicts from _cat/indices (open and closed, not hidden)."""
    path = (f"/_cat/indices/{quote(pattern, safe='*-._')}"
            "?format=json&h=index,status,health,docs.count,store.size&s=index&expand_wildcards=open,closed")
    status, payload = client.request("GET", path)
    if status == 404:
        return []
    if status >= 300 or not isinstance(payload, list):
        raise SystemExit(f"ERROR: could not list indexes: HTTP {status}: {payload}")
    return [row for row in payload
            if isinstance(row, dict) and row.get("index") and not str(row["index"]).startswith(".")]


def list_candidates(client, host):
    """Indexes named *-<host>."""
    suffix = f"-{host}"
    return [row for row in list_indexes(client, "*" + suffix)
            if row["index"].endswith(suffix) and len(row["index"]) > len(suffix)]


def index_owners(client, index):
    """Distinct host.name / labels.evidence_source values in an index.

    Returns a set (empty when no document has either field), or None when the index
    cannot be searched (for example it is closed, or the field is not aggregatable).
    """
    owners, failures = set(), 0
    for field in OWNER_FIELDS:
        body = {"size": 0, "track_total_hits": False,
                "aggs": {"owners": {"terms": {"field": field, "size": 20}}}}
        status, payload = client.request("POST", f"/{quote(index, safe='')}/_search", body)
        if status >= 300 or not isinstance(payload, dict):
            failures += 1
            continue
        buckets = payload.get("aggregations", {}).get("owners", {}).get("buckets", [])
        owners.update(str(b.get("key")) for b in buckets if b.get("key") is not None)
    return None if failures == len(OWNER_FIELDS) else owners


def classify(client, host, rows, prefixes):
    """Split candidates into (selected, skipped); each entry is (row, note)."""
    allowed = TOOLKIT_PREFIXES | prefixes
    selected, skipped = [], []
    for row in rows:
        index = row["index"]
        prefix = index[:-(len(host) + 1)]
        if prefixes and prefix not in prefixes:
            skipped.append((row, f"prefix '{prefix}' not in --prefix"))
            continue
        owners = index_owners(client, index) if row.get("status", "open") == "open" else None
        if owners:
            if host not in owners:
                skipped.append((row, "documents belong to " + ", ".join(sorted(owners))))
            else:
                others = sorted(owners - {host})
                selected.append((row, f"also holds: {', '.join(others)}" if others else "host.name matches"))
        elif prefix in allowed:
            what = ("closed" if row.get("status") == "close"
                    else "cannot be checked" if owners is None else "no host field")
            selected.append((row, f"{what}; known prefix '{prefix}'"))
        else:
            what = "cannot be checked" if owners is None else "has no host field"
            skipped.append((row, f"{what} and prefix '{prefix}' is not a toolkit prefix "
                                 f"(add --prefix {prefix} to include it)"))
    return selected, skipped


def case_query(case):
    return {"term": {"case": {"value": case, "case_insensitive": True}}}


def case_counts(client, case):
    """{index: number of documents whose case is this ID}, over all open non-hidden indexes."""
    body = {"size": 0, "track_total_hits": False, "query": case_query(case),
            "aggs": {"indexes": {"terms": {"field": "_index", "size": 10000}}}}
    status, payload = client.request(
        "POST", "/*,-.*/_search?ignore_unavailable=true&allow_no_indices=true", body)
    if status >= 300 or not isinstance(payload, dict):
        raise SystemExit(f"ERROR: could not search for case '{case}': HTTP {status}: {payload}")
    buckets = payload.get("aggregations", {}).get("indexes", {}).get("buckets", [])
    return {str(b["key"]): int(b.get("doc_count", 0)) for b in buckets if b.get("key")}


def other_docs(client, index, case):
    """Documents in index that do not belong to case (no case, or another one); None if unknown."""
    body = {"query": {"bool": {"must_not": [case_query(case)]}}}
    status, payload = client.request("POST", f"/{quote(index, safe='')}/_count", body)
    if status >= 300 or not isinstance(payload, dict) or "count" not in payload:
        return None
    return int(payload["count"])


def classify_case(client, case, rows, counts, report_missing):
    """Keep only indexes whose documents all belong to case; returns (selected, skipped)."""
    selected, skipped = [], []
    for row in rows:
        index = row["index"]
        hits = counts.get(index, 0)
        if not hits:
            if report_missing:
                what = "closed, cannot be searched" if row.get("status") == "close" else "no documents"
                skipped.append((row, f"{what} for case '{case}'"))
            continue
        other = other_docs(client, index, case)
        if other == 0:
            selected.append((row, f"all {hits} doc(s) are case '{case}'"))
        elif other is None:
            skipped.append((row, f"{hits} doc(s) are case '{case}', the rest could not be counted"))
        else:
            skipped.append((row, f"{hits} doc(s) are case '{case}' but {other} are not; "
                                 "the index holds other evidence, so it is kept"))
    return selected, skipped


def show(title, entries):
    print(f"\n{title} ({len(entries)}):")
    if not entries:
        print("  (none)")
        return
    width = max(len(row["index"]) for row, _ in entries)
    for row, note in entries:
        docs = row.get("docs.count") or "-"
        size = row.get("store.size") or "-"
        print(f"  {row['index']:<{width}}  {str(row.get('status', '')):<6} docs={docs:<10} size={size:<9} {note}")


def confirm(what, token, count):
    if not sys.stdin.isatty():
        raise SystemExit("ERROR: refusing to delete without confirmation; stdin is not a terminal. "
                         "Re-run with --yes to delete without prompting.")
    try:
        answer = input(f"\nThis permanently deletes {count} index(es). Type the {what} '{token}' to confirm: ")
    except EOFError:
        answer = ""
    return answer.strip().lower() == token.lower()


def delete_indexes(client, entries):
    """DELETE each index on its own (wildcard deletes may be disabled). Returns failures."""
    failed = 0
    for row, _ in entries:
        index = row["index"]
        status, payload = client.request("DELETE", f"/{quote(index, safe='')}")
        if status < 300:
            print(f"  deleted {index}")
        elif status == 404:
            print(f"  {index} was already gone")
        else:
            failed += 1
            print(f"  ERROR: could not delete {index}: HTTP {status}: {payload}", file=sys.stderr)
    return failed


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Delete the toolkit indexes of one evidence host (--hostname), one case (--case), or both.")
    parser.add_argument("--hostname", help="Evidence host name, as given to the importers (normalized the same way)")
    parser.add_argument("--case", help="Case ID, as given to the importers with --case (upper/lower case ignored)")
    parser.add_argument("--prefix", action="append", default=[], metavar="PREFIX",
                        help="Only consider indexes with this prefix (repeatable), e.g. --prefix amcache. "
                             "Also allows a custom --index prefix such as amcache-test")
    parser.add_argument("--dry-run", action="store_true", help="List the matching indexes; delete nothing")
    parser.add_argument("--yes", "-y", action="store_true", help="Delete without asking for confirmation")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username, if security is enabled")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    add_client_arguments(parser)
    args = parser.parse_args(argv)
    args.case = (args.case or "").strip() or None
    if not args.hostname and not args.case:
        parser.error("give --hostname, --case, or both")
    return args


def has_prefix(index, prefixes):
    return any(index.startswith(p + "-") for p in prefixes)


def main(argv=None):
    args = parse_args(argv)
    apply_client_arguments(args)
    host = sanitize_hostname(args.hostname) if args.hostname else None
    if host and host != args.hostname:
        print(f"note: hostname normalized to '{host}', as the importers do")
    case = args.case
    prefixes = {p.strip().lower().rstrip("-") for p in args.prefix if p.strip()}
    client = EsClient(args.es, args.user, args.password, args.insecure)

    try:
        print(f"Elasticsearch: {args.es}")
        if host:
            print(f"Hostname: {host}  (indexes named <prefix>-{host})")
        if case:
            print(f"Case: {case}  (indexes whose documents all have case = '{case}')")
        selected, skipped = [], []
        if host:
            selected, skipped = classify(client, host, list_candidates(client, host), prefixes)
        if case:
            counts = case_counts(client, case)
            if host:
                rows = [row for row, _ in selected]
            else:
                rows = [row for row in list_indexes(client) if row["index"] in counts]
                if prefixes:
                    skipped += [(row, "prefix not in --prefix") for row in rows if not has_prefix(row["index"], prefixes)]
                    rows = [row for row in rows if has_prefix(row["index"], prefixes)]
            selected, case_skipped = classify_case(client, case, rows, counts, report_missing=bool(host))
            skipped += case_skipped
        show("Indexes to delete", selected)
        if skipped:
            show("Matching indexes that are NOT selected", skipped)
        if case and not host:
            closed = [row["index"] for row in list_indexes(client) if row.get("status") == "close"]
            if closed:
                print(f"\nnote: {len(closed)} closed index(es) cannot be searched for the case and were "
                      f"skipped: {', '.join(closed)}")
        if not selected:
            print("\nNothing to delete.")
            return 0
        if args.dry_run:
            print("\nDry run: nothing was deleted.")
            return 0
        what, token = ("hostname", host) if host else ("case ID", case)
        if not args.yes and not confirm(what, token, len(selected)):
            print("Aborted: nothing was deleted.")
            return 1
        print()
        failed = delete_indexes(client, selected)
    except EsUnavailable as exc:
        print(f"ERROR: Elasticsearch is unreachable at {args.es}: {exc}", file=sys.stderr)
        return 2
    print(f"\nDeleted {len(selected) - failed} of {len(selected)} index(es)" + (f"; {failed} failed" if failed else "."))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
