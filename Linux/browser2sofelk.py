#!/usr/bin/env python3
"""Load Firefox and Chromium-family browsing history from a Linux collection into browsinghistory-<hostname>.

Reads the browsers' own SQLite databases for every user (/home/*, /root), including snap and
flatpak installs:

  Firefox family   .mozilla/firefox/<profile>/places.sqlite (also LibreWolf, Waterfox,
                   snap/firefox/common/.mozilla, .var/app/org.mozilla.firefox/.mozilla)
  Chromium family  .config/<browser>/<profile>/History for Chrome, Chromium, Brave, Edge,
                   Vivaldi and Opera (also snap/chromium and flatpak .var/app/*/config)

One document per page visit (event.dataset "browsinghistory") and one per download
("browsinghistory.download", visit_type "Download"). Times are epoch-based (Firefox PRTime,
Chromium WebKit time), so no time zone is needed; @timestamp and browsinghistory.visit_time are UTC.

The schema is the one NirSoft BrowsingHistoryView output already uses
(Windows/index_templates/index-browsinghistory.json), so `FROM browsinghistory-*` and the hunting
queries (IA-02, C2-03, C2-08, EXF-05) cover Windows and Linux hosts alike: url.original,
url.domain, user.name, browsinghistory.visit_time, title, visit_count, typed_count, visit_type,
visited_from, web_browser, user_profile, browser_profile, history_file, record_id.

The databases are copied to a temporary folder (with their -wal file, so recent visits not yet
checkpointed are included) and read there; the evidence is never opened for writing. Only history
and download tables are read: cookies, saved logins, key4.db, form history and session files are
never touched.

Example:
  python3 Linux/browser2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
import datetime as dt
import json
import re
import sqlite3
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import LogSource, iso_utc, run_sources, set_field  # noqa: E402

DATASETS = ("browsinghistory", "browsinghistory.download")
SQLITE_MAGIC = b"SQLite format 3\x00"
WEBKIT_EPOCH_OFFSET_US = 11644473600 * 1000000

FIREFOX_BROWSERS = (("librewolf", "LibreWolf"), ("waterfox", "Waterfox"), ("org.mozilla.firefox", "Firefox"),
                    ("snap/firefox", "Firefox"), (".mozilla/firefox", "Firefox"))
CHROMIUM_BROWSERS = (("google-chrome", "Chrome"), ("com.google.chrome", "Chrome"), ("bravesoftware", "Brave"),
                     ("microsoft-edge", "Edge"), ("com.microsoft.edge", "Edge"), ("vivaldi", "Vivaldi"),
                     ("opera", "Opera"), ("chromium", "Chromium"))
FIREFOX_VISIT_TYPES = {1: "Link", 2: "Typed", 3: "Bookmark", 4: "Embed", 5: "Permanent Redirect",
                       6: "Temporary Redirect", 7: "Download", 8: "Framed Link", 9: "Reload"}
FIREFOX_VISIT_SOURCES = {0: "organic", 1: "sponsored", 2: "bookmarked", 3: "searched", 4: "tagged"}
FIREFOX_DOWNLOAD_STATES = {-1: "not started", 0: "downloading", 1: "complete", 2: "failed", 3: "cancelled",
                           4: "paused", 6: "blocked (parental control)", 7: "blocked (policy)", 8: "dirty"}
CHROMIUM_TRANSITIONS = {0: "Link", 1: "Typed", 2: "Auto Bookmark", 3: "Auto Subframe", 4: "Manual Subframe",
                        5: "Generated", 6: "Start Page", 7: "Form Submit", 8: "Reload", 9: "Keyword",
                        10: "Keyword Generated"}
CHROMIUM_QUALIFIERS = ((0x00800000, "BLOCKED"), (0x01000000, "FORWARD_BACK"), (0x02000000, "FROM_ADDRESS_BAR"),
                       (0x04000000, "HOME_PAGE"), (0x08000000, "FROM_API"), (0x10000000, "CHAIN_START"),
                       (0x20000000, "CHAIN_END"), (0x40000000, "CLIENT_REDIRECT"), (0x80000000, "SERVER_REDIRECT"))
CHROMIUM_DOWNLOAD_STATES = {0: "in progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
CHROMIUM_DANGER = {0: "not dangerous", 1: "dangerous file", 2: "dangerous url", 3: "dangerous content",
                   4: "maybe dangerous content", 5: "uncommon content", 6: "user validated", 7: "dangerous host",
                   8: "potentially unwanted", 9: "allowlisted by policy", 10: "async scanning",
                   11: "blocked password protected", 12: "blocked too large", 13: "sensitive content warning",
                   14: "sensitive content block", 15: "deep scanned safe", 16: "deep scanned opened dangerous",
                   17: "prompt for scanning", 18: "blocked unsupported filetype", 19: "dangerous account compromise"}
PROFILE_DIR_RE = re.compile(r"^(Default|Profile \d+|Guest Profile|System Profile)$")


# --------------------------------------------------------------------------- input discovery

def browser_of(rel, table):
    low = rel.lower()
    for key, name in table:
        if key in low:
            return name
    return None


def collect(ev, profile, args):
    items = []
    for top in ("home", "root"):
        folder = ev.root_path(top)
        if not ev.is_dir(folder):
            continue
        for path in ev.walk(folder, max_depth=9):
            p = PurePosixPath(path)
            if p.name == "places.sqlite" and "thunderbird" not in path.lower():
                kind = "firefox"
                name = browser_of(path, FIREFOX_BROWSERS) or "Firefox-based"
            elif p.name == "History" and (PROFILE_DIR_RE.match(p.parent.name) or browser_of(path, CHROMIUM_BROWSERS)):
                kind = "chromium"
                name = browser_of(path, CHROMIUM_BROWSERS) or "Chromium-based"
            else:
                continue
            head = ev.read_bytes(path, limit=16)
            if not head or not head.startswith(SQLITE_MAGIC):
                continue
            items.append((kind, name, path))
    return sorted(set(items), key=lambda x: x[2])


def item_label(item):
    return f"{item[1]}: {item[2]}"


# --------------------------------------------------------------------------- helpers

def prtime(value):
    """Firefox PRTime (µs since 1970) -> ISO UTC."""
    if not value:
        return None
    try:
        return iso_utc(dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=int(value)))
    except (OverflowError, ValueError, TypeError):
        return None


def webkit(value):
    """Chromium time (µs since 1601) -> ISO UTC; 0 means unset."""
    if not value:
        return None
    return prtime(int(value) - WEBKIT_EPOCH_OFFSET_US)


def duration_text(us):
    if not us:
        return None
    seconds, micro = divmod(int(us), 1000000)
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{micro // 1000:03d}"


def owner(ev, rel):
    """('/home/kali', 'kali') for a file under /home/kali; ('/root', 'root') under /root."""
    parts = PurePosixPath(ev.evidence_path(rel)).parts
    if len(parts) > 2 and parts[1] == "home":
        return f"/home/{parts[2]}", parts[2].lower()
    if len(parts) > 1 and parts[1] == "root":
        return "/root", "root"
    return None, None


def browser_profile(kind, rel):
    p = PurePosixPath(rel)
    return p.parent.name if kind == "firefox" or PROFILE_DIR_RE.match(p.parent.name) else "Default"


def url_fields(doc, url):
    set_field(doc, "url.original", url)
    if not url:
        return
    set_field(doc, "browsinghistory.url_length", len(url))
    try:
        u = urlsplit(url)
        set_field(doc, "url.scheme", u.scheme.lower() or None)
        set_field(doc, "url.domain", (u.hostname or "").lower() or None)
    except ValueError:
        pass


def columns(con, table):
    return {row[1] for row in con.execute(f"PRAGMA table_info({table})")}


def copy_database(ev, rel, tmp):
    """Copy the database and its -wal file (if collected) to tmp; return the local path."""
    local = Path(tmp) / "history.sqlite"
    ev.copy_out(rel, local)
    if ev.exists(rel + "-wal"):
        ev.copy_out(rel + "-wal", Path(tmp) / "history.sqlite-wal")
    return local


# --------------------------------------------------------------------------- Firefox

def firefox_rows(con, base):
    place_cols = columns(con, "moz_places")
    visit_cols = columns(con, "moz_historyvisits")
    typed = "p.typed" if "typed" in place_cols else "NULL"
    source = "v.source" if "source" in visit_cols else "NULL"
    query = (f"SELECT v.id, v.visit_date, v.visit_type, v.from_visit, {source}, p.url, p.title, p.visit_count,"
             f" {typed}, p.hidden, fp.url FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id"
             f" LEFT JOIN moz_historyvisits fv ON fv.id = v.from_visit LEFT JOIN moz_places fp ON fp.id = fv.place_id"
             f" ORDER BY v.id")
    for (vid, when, vtype, from_visit, src, url, title, count, typed_n, hidden, from_url) in con.execute(query):
        doc = base()
        stamp = prtime(when)
        url_fields(doc, url)
        set_field(doc, "browsinghistory.title", title)
        set_field(doc, "browsinghistory.visit_time", stamp)
        set_field(doc, "browsinghistory.visit_count", count)
        set_field(doc, "browsinghistory.typed_count", typed_n)
        set_field(doc, "browsinghistory.visit_type", FIREFOX_VISIT_TYPES.get(vtype, str(vtype) if vtype is not None else None))
        set_field(doc, "browsinghistory.transition", vtype)
        set_field(doc, "browsinghistory.visit_source", FIREFOX_VISIT_SOURCES.get(src) if src is not None else None)
        set_field(doc, "browsinghistory.from_visit", from_visit or None)
        set_field(doc, "browsinghistory.visited_from", from_url)
        set_field(doc, "browsinghistory.hidden", bool(hidden) if hidden is not None else None)
        set_field(doc, "browsinghistory.record_id", vid)
        yield ("visit", vid), stamp, "moz_historyvisits.visit_date", doc


def firefox_downloads(con, base):
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not {"moz_annos", "moz_anno_attributes"} <= tables:
        return
    rows = {}
    query = ("SELECT a.place_id, n.name, a.content, a.dateAdded FROM moz_annos a"
             " JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id"
             " WHERE n.name IN ('downloads/destinationFileURI', 'downloads/metaData')")
    for place_id, name, content, added in con.execute(query):
        entry = rows.setdefault(place_id, {})
        entry[name] = content
        if name == "downloads/destinationFileURI":
            entry["added"] = added
    for place_id, entry in sorted(rows.items()):
        url, title = con.execute("SELECT url, title FROM moz_places WHERE id = ?", (place_id,)).fetchone() or (None, None)
        doc = base()
        stamp = prtime(entry.get("added"))
        url_fields(doc, url)
        set_field(doc, "browsinghistory.title", title)
        set_field(doc, "browsinghistory.visit_time", stamp)
        set_field(doc, "browsinghistory.visit_type", "Download")
        set_field(doc, "browsinghistory.record_id", place_id)
        dest = entry.get("downloads/destinationFileURI")
        if dest:
            path = unquote(dest[7:]) if dest.startswith("file://") else dest
            set_file(doc, path)
        try:
            meta = json.loads(entry.get("downloads/metaData") or "{}")
        except ValueError:
            meta = {}
        if isinstance(meta, dict):
            state = meta.get("state")
            set_field(doc, "browsinghistory.download.state", FIREFOX_DOWNLOAD_STATES.get(state, None if state is None else str(state)))
            if meta.get("endTime"):
                set_field(doc, "browsinghistory.download.end_time", prtime(int(meta["endTime"]) * 1000))
            set_field(doc, "browsinghistory.download.total_bytes", meta.get("fileSize"))
            if "deleted" in meta:
                set_field(doc, "browsinghistory.download.deleted", bool(meta["deleted"]))
        yield ("download", place_id), stamp, "moz_annos.dateAdded (download start)", doc


# --------------------------------------------------------------------------- Chromium

def chromium_rows(con, base):
    visit_cols = columns(con, "visits")
    duration = "v.visit_duration" if "visit_duration" in visit_cols else "NULL"
    query = (f"SELECT v.id, v.visit_time, v.transition, v.from_visit, {duration}, u.url, u.title, u.visit_count,"
             f" u.typed_count, u.hidden, fu.url FROM visits v JOIN urls u ON u.id = v.url"
             f" LEFT JOIN visits fv ON fv.id = v.from_visit LEFT JOIN urls fu ON fu.id = fv.url ORDER BY v.id")
    for (vid, when, transition, from_visit, dur, url, title, count, typed_n, hidden, from_url) in con.execute(query):
        doc = base()
        stamp = webkit(when)
        url_fields(doc, url)
        set_field(doc, "browsinghistory.title", title)
        set_field(doc, "browsinghistory.visit_time", stamp)
        set_field(doc, "browsinghistory.visit_count", count)
        set_field(doc, "browsinghistory.typed_count", typed_n)
        if transition is not None:
            core = transition & 0xFF
            set_field(doc, "browsinghistory.visit_type", CHROMIUM_TRANSITIONS.get(core, str(core)))
            set_field(doc, "browsinghistory.transition", transition)
            set_field(doc, "browsinghistory.transition_qualifiers",
                      [name for bit, name in CHROMIUM_QUALIFIERS if transition & bit])
        set_field(doc, "browsinghistory.visit_duration", duration_text(dur))
        set_field(doc, "browsinghistory.from_visit", from_visit or None)
        set_field(doc, "browsinghistory.visited_from", from_url)
        set_field(doc, "browsinghistory.hidden", bool(hidden) if hidden is not None else None)
        set_field(doc, "browsinghistory.record_id", vid)
        yield ("visit", vid), stamp, "visits.visit_time", doc


def chromium_downloads(con, base):
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "downloads" not in tables:
        return
    cols = columns(con, "downloads")
    wanted = ["id", "guid", "current_path", "target_path", "start_time", "end_time", "received_bytes",
              "total_bytes", "state", "danger_type", "interrupt_reason", "opened", "referrer", "tab_url",
              "mime_type"]
    present = [c for c in wanted if c in cols]
    chains = {}
    if "downloads_url_chains" in tables:
        for did, _, url in con.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains[did] = url  # the last entry of the redirect chain is the URL actually fetched
    for row in con.execute(f"SELECT {', '.join(present)} FROM downloads ORDER BY id"):
        r = dict(zip(present, row))
        doc = base()
        stamp = webkit(r.get("start_time"))
        url_fields(doc, chains.get(r["id"]) or r.get("tab_url"))
        set_field(doc, "browsinghistory.visit_time", stamp)
        set_field(doc, "browsinghistory.visit_type", "Download")
        set_field(doc, "browsinghistory.record_id", r["id"])
        set_file(doc, r.get("target_path") or r.get("current_path"))
        set_field(doc, "file.size", r.get("total_bytes") or r.get("received_bytes") or None)
        set_field(doc, "browsinghistory.download.guid", r.get("guid"))
        set_field(doc, "browsinghistory.download.end_time", webkit(r.get("end_time")))
        set_field(doc, "browsinghistory.download.received_bytes", r.get("received_bytes"))
        set_field(doc, "browsinghistory.download.total_bytes", r.get("total_bytes"))
        if r.get("state") is not None:
            set_field(doc, "browsinghistory.download.state", CHROMIUM_DOWNLOAD_STATES.get(r["state"], str(r["state"])))
        if r.get("danger_type") is not None:
            set_field(doc, "browsinghistory.download.danger_type", CHROMIUM_DANGER.get(r["danger_type"], str(r["danger_type"])))
        if r.get("interrupt_reason"):
            set_field(doc, "browsinghistory.download.interrupt_reason", str(r["interrupt_reason"]))
        if r.get("opened") is not None:
            set_field(doc, "browsinghistory.download.opened", bool(r["opened"]))
        set_field(doc, "browsinghistory.download.mime_type", r.get("mime_type"))
        set_field(doc, "browsinghistory.download.referrer", r.get("referrer"))
        set_field(doc, "browsinghistory.download.tab_url", r.get("tab_url"))
        set_field(doc, "browsinghistory.visited_from", r.get("referrer") or r.get("tab_url"))
        yield ("download", r["id"]), stamp, "downloads.start_time", doc


def set_file(doc, path):
    if not path:
        return
    set_field(doc, "file.path", path)
    name = PurePosixPath(path).name
    set_field(doc, "file.name", name)
    if "." in name:
        set_field(doc, "file.extension", name.rsplit(".", 1)[1].lower())


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    kind, browser, rel = item
    history_file = ev.evidence_path(rel)
    user_profile, user = owner(ev, rel)
    prof = browser_profile(kind, rel)

    def base():
        doc = {}
        set_field(doc, "browsinghistory.web_browser", browser)
        set_field(doc, "browsinghistory.user_profile", user_profile)
        set_field(doc, "browsinghistory.browser_profile", prof)
        set_field(doc, "browsinghistory.history_file", history_file)
        set_field(doc, "user.name", user)
        set_field(doc, "kape.source_file", rel)
        return doc

    readers = (firefox_rows, firefox_downloads) if kind == "firefox" else (chromium_rows, chromium_downloads)
    with tempfile.TemporaryDirectory(prefix="browser2sofelk-") as tmp:
        try:
            local = copy_database(ev, rel, tmp)
            con = sqlite3.connect(str(local))
        except (OSError, sqlite3.Error) as exc:
            report.warn(f"{history_file}: cannot open ({exc})")
            return
        try:
            for reader in readers:
                try:
                    for (what, rid), stamp, source, doc in reader(con, base):
                        dataset = "browsinghistory.download" if what == "download" else "browsinghistory"
                        if stamp is None:
                            yield None, f"{what} without a usable time"
                            continue
                        doc["@timestamp"] = stamp
                        set_field(doc, "event.dataset", dataset)
                        set_field(doc, "kape.timestamp_source", source)
                        set_field(doc, "kape.timestamp_meaning",
                                  "Download start time (UTC)" if what == "download" else "Page visit time (UTC)")
                        yield [kind, history_file, what, rid], doc
                except sqlite3.DatabaseError as exc:
                    report.warn(f"{history_file}: {reader.__name__} failed ({exc}); the database may be"
                                " damaged or from an unsupported browser version")
        finally:
            con.close()


BROWSER = LogSource("browser", "browsinghistory", DATASETS, collect, parse, item_label, templates="windows")


def main(argv=None):
    return run_sources([BROWSER], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())
