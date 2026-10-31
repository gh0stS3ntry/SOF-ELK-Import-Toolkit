#!/usr/bin/env python3
"""Static checks for the ES|QL hunting query pack (standard library only).

It cannot run a query, but it catches the mistakes that cost the most time on a SOF-ELK VM:

  * a field name that does not exist in the toolkit's index templates or the native field
    reference (renamed columns, typos, raw parser column names from the old importers);
  * the pack's conventions: FROM ... METADATA _index, _index kept in the output, no wildcards
    in KEEP, winlog.event_id cast with TO_STRING before IN (...);
  * Linux queries (queries/linux/) are checked against the Linux importers' mappings only. A
    query reading several index families must not depend on a field that only an optional
    family (auditd-*, httpdlog-*, browsinghistory-*) has, unless its "Needs:" header names that
    family, so it still runs on a host without auditd, a web server or a browser; and every
    Linux query filters host.os.type == "linux";
  * RLIKE patterns that Lucene regex rejects or reads differently than intended
    (\\d / \\s / \\w, unescaped & @ ~ # < >, ^ / $ anchors, bounded repetition after .*);
  * LIKE patterns with a lone backslash (ES|QL LIKE uses backslash as its escape character);
  * every query folder has a README.md, every query is in the catalog in hunting/README.md,
    every query ID a checklist names exists, and relative links in the pack's Markdown resolve.

Usage:
    python3 hunting/tools/check_queries.py            # check the whole pack
    python3 hunting/tools/check_queries.py -v         # also list each query checked

Exit status is 0 when there are no errors (warnings do not fail the run).
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent
REPO = PACK.parent
QUERIES = PACK / "queries"
CHECKLISTS = PACK / "checklists"
TEMPLATES = REPO / "Windows" / "index_templates"
AWS_TEMPLATES = REPO / "AWS" / "index_templates"
LINUX_TEMPLATES = REPO / "Linux" / "index_templates"
LINUX_QUERIES = QUERIES / "linux"
# Linux families that many hosts do not have: no auditd installed (Debian, Ubuntu and Kali by
# default), no web server, no browser. A query reading several families must still run
# without them, so it may not reference a field that only these families define.
LINUX_OPTIONAL_FAMILIES = ("auditd", "httpdlog", "browsinghistory")
NATIVE_CSV = REPO / "docs" / "sofelk-native-fields.csv"

NATIVE_FAMILIES = ("filesystem", "evtxlogs", "lnkfiles", "prefetch")
# Inferred-type importers: field names follow the raw CSV header, so they are not checked.
INFERRED_FAMILIES = ("recentfilecache", "sqlitedb", "sum")
# clrusagelogs2sofelk.py creates its own explicit mapping (no template file to read).
CLR_FIELDS = {
    "@timestamp", "host.name", "case", "user.name", "file.name", "file.path", "process.name",
    "message", "clr_usage.first_execution_timestamp", "clr_usage.last_execution_timestamp",
    "clr_usage.runtime", "clr_usage.assembly_name", "clr_usage.source_user",
    "kape.source_file", "kape.timestamp_source",
}
ALWAYS = {"_index", "@timestamp"}

ID_RE = re.compile(r"^[A-Z0-9]{2,4}-\d{2}$")
HEADER_RE = re.compile(r"^//\s*(?P<id>[A-Z0-9]{2,4}-\d{2})\s*\|\s*(?P<title>.+?)\s*$")


class Fields:
    """Known field names per index family: exact names plus allowed open-ended prefixes."""

    def __init__(self):
        self.exact: dict[str, set[str]] = {}
        self.prefixes: dict[str, set[str]] = {}
        self.linux: dict[str, tuple[set[str], set[str]]] = {}
        self.linux_types: dict[str, dict[str, str]] = {}

    def add(self, family, name):
        self.exact.setdefault(family, set()).add(name)

    def add_prefix(self, family, prefix):
        self.prefixes.setdefault(family, set()).add(prefix)

    def known(self, family, name):
        if name in self.exact.get(family, ()):
            return True
        if any(name.startswith(p) for p in self.prefixes.get(family, ())):
            return True
        # object sub-fields of a keyword/date leaf are never valid, but a parent object is
        return any(f.startswith(name + ".") for f in self.exact.get(family, ()))

    def known_linux(self, family, name):
        """Like known(), but only against the Linux importers' mapping of the family."""
        exact, prefixes = self.linux.get(family, ((), ()))
        return (name in exact or any(name.startswith(p) for p in prefixes)
                or any(f.startswith(name + ".") for f in exact))


def leaf_types(props, prefix=""):
    """{dotted field: mapping type} for the leaves of a mapping."""
    out = {}
    for key, spec in (props or {}).items():
        name = f"{prefix}{key}"
        if "properties" in spec:
            out.update(leaf_types(spec["properties"], name + "."))
        else:
            out[name] = spec.get("type", "object")
    return out


def walk_mapping(props, prefix, out_exact, out_prefix):
    for key, spec in (props or {}).items():
        name = f"{prefix}{key}"
        if "properties" in spec or spec.get("type") == "object":
            if spec.get("dynamic") in (True, "true") or spec.get("type") == "object":
                out_prefix.add(name + ".")
            walk_mapping(spec.get("properties"), name + ".", out_exact, out_prefix)
        else:
            out_exact.add(name)
            for sub in (spec.get("fields") or {}):
                out_exact.add(f"{name}.{sub}")


def load_fields() -> Fields:
    fields = Fields()
    common_exact, common_prefix = set(), set()
    common = json.loads((TEMPLATES / "component-toolkit-common.json").read_text(encoding="utf-8"))
    walk_mapping(common["template"]["mappings"]["properties"], "", common_exact, common_prefix)
    for path in sorted(TEMPLATES.glob("index-*.json")):
        family = path.stem[len("index-"):]
        spec = json.loads(path.read_text(encoding="utf-8"))
        exact, prefix = set(common_exact), set(common_prefix)
        walk_mapping(spec["template"]["mappings"].get("properties"), "", exact, prefix)
        for name in exact:
            fields.add(family, name)
        for p in prefix:
            fields.add_prefix(family, p)
    for name in CLR_FIELDS:
        fields.add("clrusagelogs", name)

    # AWS indexes: aws-<log type>-<source>, composed of their own common component
    aws_exact, aws_prefix = set(), set()
    aws_common = json.loads((AWS_TEMPLATES / "component-toolkit-aws-common.json").read_text(encoding="utf-8"))
    walk_mapping(aws_common["template"]["mappings"]["properties"], "", aws_exact, aws_prefix)
    for path in sorted(AWS_TEMPLATES.glob("index-*.json")):
        family = path.stem[len("index-"):]
        spec = json.loads(path.read_text(encoding="utf-8"))
        exact, prefix = set(aws_exact), set(aws_prefix)
        walk_mapping(spec["template"]["mappings"].get("properties"), "", exact, prefix)
        for name in exact:
            fields.add(family, name)
        for p in prefix:
            fields.add_prefix(family, p)

    # Linux indexes: <family>-<hostname>, composed of the Linux common component. httpdlog
    # also has the AWS (ALB/ELB) mapping above; both use SOF-ELK's web field names.
    linux_exact, linux_prefix = set(), set()
    linux_common = json.loads((LINUX_TEMPLATES / "component-toolkit-linux-common.json").read_text(encoding="utf-8"))
    walk_mapping(linux_common["template"]["mappings"]["properties"], "", linux_exact, linux_prefix)
    for path in sorted(LINUX_TEMPLATES.glob("index-*.json")):
        family = path.stem[len("index-"):]
        spec = json.loads(path.read_text(encoding="utf-8"))
        exact, prefix = set(linux_exact), set(linux_prefix)
        walk_mapping(spec["template"]["mappings"].get("properties"), "", exact, prefix)
        fields.linux[family] = (exact, prefix)
        fields.linux_types[family] = {**leaf_types(linux_common["template"]["mappings"]["properties"]),
                                      **leaf_types(spec["template"]["mappings"].get("properties"))}
        for name in exact:
            fields.add(family, name)
        for p in prefix:
            fields.add_prefix(family, p)

    with NATIVE_CSV.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            index, raw = row["index"].strip(), row["field"].strip()
            families = NATIVE_FAMILIES if index == "all four" else (index,)
            for part in re.split(r"\s*,\s*|\s+/\s+", raw):
                part = part.strip()
                if not part:
                    continue
                if "<" in part or part.endswith("*"):
                    prefix = re.split(r"[<*]", part, maxsplit=1)[0]
                    for fam in families:
                        fields.add_prefix(fam, prefix)
                elif "/" in part:
                    # winlog.payload.event_data.SystemTime/LoaderTime/... (covered by the prefix)
                    continue
                else:
                    for fam in families:
                        fields.add(fam, part)
    # file.directory / file.name style rows on lnkfiles/prefetch also carry file.name
    for fam in ("lnkfiles", "prefetch"):
        fields.add(fam, "file.name")
        fields.add(fam, "file.directory")
    # Linux/browser2sofelk.py writes the Windows browsinghistory schema for Linux hosts
    fields.linux["browsinghistory"] = (set(fields.exact.get("browsinghistory", ())),
                                       set(fields.prefixes.get("browsinghistory", ())))
    fields.linux_types["browsinghistory"] = {
        **leaf_types(common["template"]["mappings"]["properties"]),
        **leaf_types(json.loads((TEMPLATES / "index-browsinghistory.json").read_text(encoding="utf-8"))
                     ["template"]["mappings"].get("properties"))}
    return fields


# ---------------------------------------------------------------------------------------------
# Query parsing


STRING_RE = re.compile(r'"""(?:.|\n)*?"""|"(?:[^"\\\n]|\\.)*"')
BACKTICK_RE = re.compile(r"`([^`]+)`")
DOTTED_RE = re.compile(r"(?<![\w.@`])(@?[A-Za-z_][\w@-]*(?:\.[\w@-]+)+)(?![\w(])")
FROM_RE = re.compile(r"^\s*FROM\s+(?P<targets>.+?)(?:\s+METADATA\s+(?P<meta>[\w, ]+))?\s*$",
                     re.I | re.M)


def strip_comments(text):
    out = []
    for line in text.splitlines():
        # a // inside a string literal is rare in this pack; only strip comments at line start
        # or after whitespace outside quotes
        in_str = False
        cut = len(line)
        i = 0
        while i < len(line) - 1:
            ch = line[i]
            if ch == '"':
                in_str = not in_str
            elif ch == "\\" and in_str:
                i += 1
            elif not in_str and line[i:i + 2] == "//":
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return "\n".join(out)


AWS_FAMILIES = sorted(p.stem[len("index-"):] for p in AWS_TEMPLATES.glob("index-*.json"))


def families_of(targets):
    fams = []
    for t in targets.split(","):
        t = t.strip()
        if t in ("aws-*", "aws*"):
            fams.extend(AWS_FAMILIES)
            continue
        aws = next((f for f in AWS_FAMILIES if t.startswith(f + "-")), None)
        if aws:
            fams.append(aws)
            continue
        m = re.match(r"^([a-z]+)-", t)
        if m:
            fams.append(m.group(1))
    return fams


def unescape_esql(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), s)


def check_rlike(pattern, where, problems):
    """Lucene RegExp pitfalls in an RLIKE pattern (already unescaped from the ES|QL literal)."""
    if re.search(r"\.\*[^|)]*\.\{\d*,\d+\}", pattern):
        problems.append(("error", f"{where}: bounded repetition after .* in RLIKE (too complex to determinize)"))
    in_class = False
    escaped = False
    for i, ch in enumerate(pattern):
        if escaped:
            escaped = False
            if ch in "dswDSW":
                problems.append(("error", f"{where}: RLIKE uses \\{ch}, which Lucene regex does not support"))
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_class:
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True
            continue
        if ch in "&@~#<>":
            problems.append(("error", f"{where}: unescaped '{ch}' in RLIKE is a Lucene operator; use [{ch}]"))
        if ch in "^$":
            problems.append(("warning", f"{where}: '{ch}' is a literal in Lucene RLIKE (patterns are always anchored)"))


def check_query(path: Path, fields: Fields, problems):
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    header = HEADER_RE.match(lines[0]) if lines else None
    if not header:
        problems.append(("error", f"{path}: first line must be '// <ID> | <title>'"))
        qid = None
    else:
        qid = header.group("id")
    meta = {}
    for line in lines[1:6]:
        for part in line.lstrip("/ ").split("|"):
            if ":" in part:
                k, v = part.split(":", 1)
                meta[k.strip().lower()] = v.strip()
    for key in ("tactic", "att&ck", "indexes"):
        if key not in meta:
            problems.append(("error", f"{path}: header is missing '{key.title()}:'"))

    # RLIKE checks need the literal text
    for m in re.finditer(r'RLIKE\s+("""(?:.|\n)*?"""|"(?:[^"\\]|\\.)*")', raw):
        lit = m.group(1)
        pat = lit[3:-3] if lit.startswith('"""') else unescape_esql(lit[1:-1])
        line_no = raw.count("\n", 0, m.start()) + 1
        check_rlike(pat, f"{path}:{line_no}", problems)

    # LIKE: backslash escapes only \\, * and ?; a literal backslash is "\\\\" in the query text
    for m in re.finditer(r'(?<![R\w])LIKE\s+"((?:[^"\\]|\\.)*)"', raw):
        pat = unescape_esql(m.group(1))
        line_no = raw.count("\n", 0, m.start()) + 1
        if re.search(r'\\(?![\\*?])', pat.replace("\\\\", "")):
            problems.append(("error", f"{path}:{line_no}: LIKE pattern has a lone backslash; "
                                      "write a literal backslash as \\\\\\\\ in the query"))

    body = strip_comments(raw)
    body_nostr = STRING_RE.sub('""', body)
    fm = FROM_RE.search(body_nostr)
    if not fm:
        problems.append(("error", f"{path}: no FROM line"))
        return qid, meta
    if "_index" not in (fm.group("meta") or ""):
        problems.append(("error", f"{path}: FROM must use METADATA _index"))
    fams = families_of(fm.group("targets"))
    after_from = body_nostr[fm.end():]
    if "_index" not in after_from:
        problems.append(("error", f"{path}: _index is not kept in the output (KEEP or STATS BY/VALUES)"))
    for km in re.finditer(r"\|\s*KEEP\b(?P<cols>(?:(?!\|).)*)", body_nostr, re.S):
        if "*" in BACKTICK_RE.sub("x", km.group("cols")) or "*" in km.group("cols"):
            problems.append(("error", f"{path}: KEEP must list explicit fields, not wildcards"))
    if re.search(r"winlog\.event_id`?\s*\)?\s+(NOT\s+)?IN\s*\(", body_nostr):
        problems.append(("error", f"{path}: winlog.event_id is a long; TO_STRING it before IN (...)"))

    is_linux = LINUX_QUERIES in path.parents
    if is_linux:
        for fam in fams:
            if fam not in fields.linux:
                problems.append(("error", f"{path}: {fam}-* is not a Linux index family"))
        # httpdlog-* and browsinghistory-* also hold Windows and AWS documents, and SOF-ELK's own
        # pipeline writes logstash-YYYY.MM; every Linux importer sets host.os.type "linux".
        if not re.search(r'host\.os\.type\s*==\s*""', body_nostr):
            problems.append(("error", f"{path}: Linux queries must filter WHERE host.os.type == \"linux\""))

    # field names
    checkable = [f for f in fams if f not in INFERRED_FAMILIES]
    if fams and len(checkable) == len(fams):
        names = set(BACKTICK_RE.findall(body_nostr))
        names |= set(DOTTED_RE.findall(BACKTICK_RE.sub(" ", body_nostr)))
        for name in sorted(names):
            if name in ALWAYS or "." not in name:
                continue
            if re.match(r"^\d", name):
                continue
            if is_linux:
                if not any(fields.known_linux(f, name) for f in checkable):
                    problems.append(("error", f"{path}: unknown field '{name}' for Linux {', '.join(fams)}"))
                elif len(set(fams)) > 1 and not any(fields.known_linux(f, name) for f in checkable
                                                    if f not in LINUX_OPTIONAL_FAMILIES
                                                    or f"{f}-*" in meta.get("needs", "")):
                    optional = ", ".join(f for f in fams if f in LINUX_OPTIONAL_FAMILIES)
                    problems.append(("error", f"{path}: '{name}' exists only in optional families "
                                              f"({optional}); the query fails on hosts without them"))
                types = {fields.linux_types.get(f, {}).get(name) for f in checkable} - {None}
                if len(types) > 1:
                    bare_uses = re.findall(r"(?<![\w.])(TO_[A-Z_]+\(\s*)?`?" + re.escape(name) + r"`?(?![\w.])",
                                           body_nostr)
                    if any(not conv for conv in bare_uses):
                        problems.append(("error", f"{path}: '{name}' is {' / '.join(sorted(types))} in "
                                                  f"{', '.join(fams)}; wrap every use in a TO_ conversion"))
            elif not any(fields.known(f, name) for f in checkable):
                problems.append(("error", f"{path}: unknown field '{name}' for {', '.join(fams)}"))
        # Raw parser column names (FullPath, KeyPath, Visit_Time, ...) are mixed-case and undotted.
        # ES|QL keywords and functions are upper case and EVAL names in this pack are lower case.
        bare = DOTTED_RE.sub(" ", BACKTICK_RE.sub(" ", body_nostr))
        for name in sorted(set(re.findall(r"(?<![\w.@])([A-Za-z_]\w*)", bare))):
            if re.search(r"[a-z]", name) and re.search(r"[A-Z]", name):
                problems.append(("error", f"{path}: '{name}' looks like a raw parser column; "
                                          "use the schema field name"))
    return qid, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    fields = load_fields()
    problems: list[tuple[str, str]] = []
    ids: dict[str, Path] = {}

    for qfile in sorted(QUERIES.rglob("*.esql")):
        qid, _meta = check_query(qfile, fields, problems)
        folder = qfile.parent
        readme = folder / "README.md"
        if not readme.exists():
            problems.append(("error", f"{folder}: missing README.md"))
        elif qid and not readme.read_text(encoding="utf-8").startswith(f"# {qid} "):
            problems.append(("error", f"{readme}: title must start with '# {qid} '"))
        if qid:
            if qid in ids:
                problems.append(("error", f"{qfile}: duplicate query ID {qid} (also {ids[qid]})"))
            ids[qid] = qfile
            if not folder.name.startswith(qid):
                problems.append(("error", f"{folder}: folder name must start with {qid}"))
        if args.verbose:
            print(f"checked {qid or '?':7} {qfile.relative_to(REPO)}")

    catalog = (PACK / "README.md").read_text(encoding="utf-8")
    for qid, qfile in ids.items():
        if f"[{qid}]" not in catalog:
            problems.append(("error", f"hunting/README.md: catalog does not list {qid}"))
        rel = qfile.parent.relative_to(PACK).as_posix()
        if f"({rel}" not in catalog:
            problems.append(("error", f"hunting/README.md: catalog link for {qid} should point to {rel}/"))
    for md in sorted(CHECKLISTS.glob("*.md")):
        text = md.read_text(encoding="utf-8")
        for ref in sorted(set(re.findall(r"\[([A-Z0-9]{2,4}-\d{2})\]", text))):
            if ref not in ids:
                problems.append(("error", f"{md}: references unknown query {ref}"))

    for md in sorted(PACK.rglob("*.md")):
        for target in re.findall(r"\]\(([^)#\s]+)[^)]*\)", md.read_text(encoding="utf-8")):
            if not re.match(r"^[a-z]+:", target) and not (md.parent / target).exists():
                problems.append(("error", f"{md}: broken link to {target}"))

    errors = [p for p in problems if p[0] == "error"]
    for level, msg in problems:
        print(f"{level.upper()}: {msg}")
    print(f"{len(ids)} queries checked, {len(errors)} error(s), {len(problems) - len(errors)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
