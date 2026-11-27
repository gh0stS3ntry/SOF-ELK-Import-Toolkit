#!/usr/bin/env python3
"""Load Java application logs (Log4j, Log4j 2, Logback, JUL, Spring Boot, Tomcat, WildFly) into
SOF-ELK as javalog-<hostname>, one document per log event.

Java applications write their logs through a *pattern layout*: Log4j's ConversionPattern, Log4j 2's
PatternLayout or Logback's <pattern>, for example

    %d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n

One event is one header line (date, level, logger, ...) plus every line after it that does not
start a new event: exception stack traces ("\tat ...", "Caused by: ..."), SQL statements printed
over many lines by iBATIS/MyBatis/Hibernate, XML or JSON payloads. Those continuation lines are
merged into the event they belong to, so a stack trace or SQL statement is one document.

Layouts
  The importer knows the layouts Java frameworks use by default and the common hand-written ones
  (see BUILTIN_LAYOUTS), each with a lenient date so that yyyy-MM-dd, yy-MM-dd, dd-MMM-yyyy,
  ISO 8601 with or without an offset, and time-only (HH:mm:ss.SSS) dates all work. The first
  lines of each file decide which one fits best. A file that holds lines from more than one
  layout still loads: every built-in layout that occurs in the file is tried per line.

  The application's own pattern can be given instead, exactly as it is in its configuration:
    --pattern '%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n'
    --pattern-file log4j.properties   (also log4j2.xml/.properties/.yaml, logback.xml)
  Log4j, Log4j 2 and Logback conversion words are understood (%d %p %c %C %M %L %F %l %t %T %X
  %x %pid %r %sn %marker %m %n ..., format modifiers such as %-5p and %.30c, composite words
  such as %highlight(...) and %clr(...), and ${NAME:-default} properties).

Fields (Java/index_templates/index-javalog.json; ECS names where ECS has one)
  %d date            -> @timestamp (UTC), javalog.timestamp_original (as written)
  %p level           -> log.level (upper case)
  %c logger          -> log.logger
  %C class           -> javalog.class
  %M method          -> log.origin.function
  %F file, %L line   -> log.origin.file.name, log.origin.file.line
  %l location        -> javalog.location (and class/method/file/line taken from it)
  %t thread, %T id   -> process.thread.name, process.thread.id
  %pid / ${PID}      -> process.pid
  %X{key} MDC        -> javalog.mdc ("key=value"); traceId/spanId/user also -> trace.id,
                        span.id, user.name
  %x NDC, %marker    -> javalog.ndc, javalog.marker
  %r, %sn            -> javalog.relative_ms, javalog.sequence
  application name   -> service.name (Spring Boot 3 [app]; otherwise the log file's name
                        without extension and rotation suffix, or --service)
  %m message         -> message: the whole event, continuation lines included;
                        javalog.first_line is the header line's message only, and
                        javalog.line_count the number of lines in the event
  Exceptions         -> error.type (first exception class), error.message, error.stack_trace,
                        javalog.exception.classes (every class, "Caused by:" and "nested
                        exception is:" included), javalog.exception.root_cause (+ _message),
                        javalog.exception.top_frame, javalog.exception.frame_count;
                        tags "exception" / "stack_trace"
  SQL statements     -> javalog.sql.statement (whitespace collapsed), javalog.sql.verb,
                        javalog.sql.tables, javalog.sql.object_id (iBATIS {pstm-N}); tag "sql"
  Every document     -> host.name, event.kind "event", event.dataset "java.log", labels.type
                        "javalog", event.timezone, log.file.path (path under the folder given),
                        log.offset (line number of the header line), javalog.layout,
                        javalog.pattern, tag "multiline" when continuation lines were merged,
                        and case / host.os.type when given

Times
  Java dates rarely carry an offset, so local times are read in --local-tz (+08:00 or an IANA name
  such as Asia/Singapore; default UTC, with a warning). A date with its own offset, or a %d{...}{TZ}
  option in --pattern, wins. Two-digit dates such as 26-11-26 are read as yy-MM-dd unless the data
  rules that out or --date-order says otherwise. Time-only layouts (Logback's default HH:mm:ss.SSS)
  take the date from --log-date, else from the file name (app.2026-11-26.log), else from the
  file's modification time, and roll over at midnight.

Files that do not look like Java logs are skipped and listed; .gz, .bz2 and .xz files are read
without unpacking. The _id comes from the host, the log family (the file name without a rotation
suffix), the event text and its occurrence number, so a re-run overwrites instead of duplicating.

Standard library only (Python 3.9+); documents are sent with urllib to the _bulk API.

Examples:
  python3 Java/javalog2sofelk.py /cases/IR-42/app01/logs --hostname APP01 --local-tz +08:00 --dry-run
  python3 Java/javalog2sofelk.py /cases/IR-42/app01/logs --hostname APP01 --local-tz Asia/Singapore
  python3 Java/javalog2sofelk.py server.log --hostname APP01 --pattern-file WEB-INF/classes/log4j.properties
"""
import argparse
import datetime as dt
import hashlib
import html
import io
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from urllib import error

try:
    import zoneinfo
except ImportError:  # Python 3.8
    zoneinfo = None

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "Linux" / "common"))

from sof_elk_linux_common import (ES, LogSource, add_client_arguments, apply_client_arguments,  # noqa: E402
                                  iso_utc, open_compressed, parse_offset, rotation_family,
                                  rotation_sort_key, run_source, sanitize_hostname, set_field)

PREFIX = "javalog"
DATASET = "java.log"
HOST_OS = ("windows", "linux", "macos", "unix")
SNIFF_LINES = 400
SNIFF_BYTES = 256 * 1024
DETECT_BYTES = 64 * 1024
DEFAULT_MAX_CHARS = 100_000

MONTHS = {m: i + 1 for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}
MONTH_RE = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?"
LEVEL_RE = (r"(?i:TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|SEVERE|FATAL|CRIT(?:ICAL)?|ALERT|"
            r"EMERG(?:ENCY)?|CONFIG|FINEST|FINER|FINE|VERBOSE|OFF|ALL)\b")


# --------------------------------------------------------------------------- dates

# The lenient date used by the built-in layouts (and by %d with no format or a named one Log4j
# and Logback define as ISO-like): numeric dates in any order, month names, ISO 8601 with T and
# an offset, AM/PM, comma or dot before the fraction, or a time only.
_TIME = r"\d{1,2}:\d{2}:\d{2}(?:[.,:]\d{1,9})?(?: ?[AaPp][Mm])?"
_ZONE = r"(?: ?(?:Z|[+-]\d{2}:?\d{2}|UTC|GMT)(?![\w:]))?"
ANY_DATE_RE = (r"(?:(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"
               r"|\d{1,2}[- ]" + MONTH_RE + r"[- ,]+\d{4}|" + MONTH_RE + r" \d{1,2},? \d{4})"
               r"[ T]" + _TIME + _ZONE + r"|" + _TIME + r")")
_ANY_PARTS = re.compile(
    r"^(?:(?P<d1>\d{1,4})(?P<sep>[-/.])(?P<d2>\d{1,2})[-/.](?P<d3>\d{1,4})"
    r"|(?P<dd>\d{1,2})[- ](?P<mon>[A-Za-z]{3})[a-z]*\.?[- ,]+(?P<yyyy>\d{4})"
    r"|(?P<mon2>[A-Za-z]{3})[a-z]*\.? (?P<dd2>\d{1,2}),? (?P<yyyy2>\d{4}))?"
    r"[ T]?(?P<H>\d{1,2}):(?P<M>\d{2}):(?P<S>\d{2})(?:[.,:](?P<frac>\d{1,9}))?"
    r"(?: ?(?P<ampm>[AaPp][Mm]))?(?: ?(?P<zone>Z|[+-]\d{2}:?\d{2}|UTC|GMT))?$")
ORDERS = ("ymd", "dmy", "mdy")


def year4(text):
    y = int(text)
    if len(text) <= 2:
        y += 2000 if y < 70 else 1900
    return y


def _zone(text):
    if not text:
        return None
    return parse_offset(text)


def _hour(h, ampm):
    if ampm:
        h = h % 12 + (12 if ampm.lower() == "pm" else 0)
    return h


def _micro(frac):
    return int((frac or "0")[:6].ljust(6, "0"))


def numeric_orders(d1, d2, d3):
    """Orders (ymd/dmy/mdy) under which the three numeric date parts are a valid date."""
    out = []
    for order in ORDERS:
        if order == "ymd":
            y, m, d = d1, d2, d3
            if len(d3) > 2:
                continue
        else:
            if len(d1) > 2:
                continue
            y = d3
            m, d = (d2, d1) if order == "dmy" else (d1, d2)
        if 1 <= int(m) <= 12 and 1 <= int(d) <= 31 and (len(y) in (2, 4)):
            out.append(order)
    return out


class AnyDate:
    """The lenient date: regex text plus a parser that needs the file's numeric order."""
    kind = "any"
    has_date = None  # decided per value

    def __init__(self, tz=None):
        self.regex = ANY_DATE_RE
        self.tz = tz

    def parse(self, raw, ctx):
        """-> (datetime naive-or-aware, has_date) or None."""
        m = _ANY_PARTS.match(raw.strip())
        if not m:
            return None
        g = m.groupdict()
        try:
            H, M, S = _hour(int(g["H"]), g["ampm"]), int(g["M"]), int(g["S"])
            micro = _micro(g["frac"])
            tz = _zone(g["zone"]) or self.tz
            if g["d1"]:
                order = ctx.order_for(g["d1"], g["d2"], g["d3"], g["sep"])
                if order is None:
                    return None
                if order == "ymd":
                    y, mo, d = year4(g["d1"]), int(g["d2"]), int(g["d3"])
                elif order == "dmy":
                    y, mo, d = year4(g["d3"]), int(g["d2"]), int(g["d1"])
                else:
                    y, mo, d = year4(g["d3"]), int(g["d1"]), int(g["d2"])
            elif g["mon"] or g["mon2"]:
                mo = MONTHS.get((g["mon"] or g["mon2"]).lower())
                if mo is None:
                    return None
                y, d = int(g["yyyy"] or g["yyyy2"]), int(g["dd"] or g["dd2"])
            else:
                return dt.datetime(1900, 1, 1, H, M, S, micro, tzinfo=tz), False
            return dt.datetime(y, mo, d, H, M, S, micro, tzinfo=tz), True
        except ValueError:
            return None


# SimpleDateFormat / DateTimeFormatter letters -> (regex, group kind)
def _sdf_token(letter, n):
    if letter in "yu":
        return (r"\d{2}", "yy") if n == 2 else (r"\d{4}", "yyyy") if n >= 3 else (r"\d{1,4}", "yyyy")
    if letter in "ML":
        if n >= 4:
            return r"[A-Za-z]+", "mon"
        if n == 3:
            return r"[A-Za-z]{3}\.?", "mon"
        return (r"\d{2}", "MM") if n == 2 else (r"\d{1,2}", "MM")
    if letter == "d":
        return (r"\d{2}" if n >= 2 else r"\d{1,2}"), "dd"
    if letter in "Hk":
        return (r"\d{2}" if n >= 2 else r"\d{1,2}"), "HH"
    if letter in "hK":
        return (r"\d{2}" if n >= 2 else r"\d{1,2}"), "hh"
    if letter == "m":
        return (r"\d{2}" if n >= 2 else r"\d{1,2}"), "mm"
    if letter == "s":
        return (r"\d{2}" if n >= 2 else r"\d{1,2}"), "ss"
    if letter in "Sn":
        return rf"\d{{{n}}}" if letter == "S" else r"\d{1,9}", "frac"
    if letter == "a":
        return r"[AaPp][Mm]", "ampm"
    if letter == "E":
        return (r"[A-Za-z]+" if n >= 4 else r"[A-Za-z]{3}"), None
    if letter == "Z":
        return r"(?:[+-]\d{4}|Z)", "zone"
    if letter in "Xx":
        return (r"(?:Z|[+-]\d{2}(?::?\d{2})?)" if letter == "X" else r"[+-]\d{2}(?::?\d{2})?"), "zone"
    if letter in "zV":
        return r"[A-Za-z][A-Za-z0-9_/+-]*", "zname"
    if letter == "D":
        return r"\d{1,3}", None
    if letter == "G":
        return r"[A-Za-z]+", None
    return None


class SdfDate:
    """A Java SimpleDateFormat / DateTimeFormatter pattern (yyyy-MM-dd HH:mm:ss,SSS ...)."""
    kind = "sdf"

    def __init__(self, fmt, tz=None):
        self.fmt = fmt
        self.tz = tz
        parts, i, kinds = [], 0, []
        while i < len(fmt):
            ch = fmt[i]
            if ch == "'":
                j = fmt.find("'", i + 1)
                if j == i + 1:          # '' is a quote
                    parts.append("'")
                    i += 2
                    continue
                j = len(fmt) if j < 0 else j
                parts.append(re.escape(fmt[i + 1:j]))
                i = j + 1
                continue
            if ch.isalpha():
                j = i
                while j < len(fmt) and fmt[j] == ch:
                    j += 1
                tok = _sdf_token(ch, j - i)
                if tok is None:
                    raise ValueError(f"date format letter '{ch}' is not supported in '{fmt}'")
                rx, kind = tok
                if kind:
                    name = f"{kind}{len(kinds)}"
                    kinds.append((name, kind))
                    parts.append(f"(?P<{name}>{rx})")
                else:
                    parts.append(rx)
                i = j
                continue
            parts.append(r" +" if ch == " " else re.escape(ch))
            i += 1
        self._parse = re.compile("^" + "".join(parts) + "$")
        self.regex = re.sub(r"\(\?P<[^>]+>", "(?:", "".join(parts))
        names = {k for _, k in kinds}
        self.has_date = bool(names & {"dd", "MM", "mon"})
        self.has_year = bool(names & {"yy", "yyyy"})

    def parse(self, raw, ctx):
        m = self._parse.match(raw.strip())
        if not m:
            return None
        v = {}
        for name, value in m.groupdict().items():
            v[re.sub(r"\d+$", "", name)] = value
        try:
            if "mon" in v:
                mo = MONTHS.get(v["mon"][:3].lower())
                if mo is None:
                    return None
            else:
                mo = int(v.get("MM", 1))
            if "yyyy" in v:
                y = int(v["yyyy"])
            elif "yy" in v:
                y = year4(v["yy"])
            else:
                y = 1900
            H = int(v.get("HH", v.get("hh", 0)))
            if "hh" in v:
                H = _hour(H, v.get("ampm"))
            tz = self.tz
            if v.get("zone"):
                tz = _zone(v["zone"]) or tz
            elif v.get("zname"):
                tz = _named_zone(v["zname"]) or tz
            stamp = dt.datetime(y, mo, int(v.get("dd", 1)), H, int(v.get("mm", 0)), int(v.get("ss", 0)),
                                _micro(v.get("frac")), tzinfo=tz)
        except ValueError:
            return None
        if not self.has_date:
            return stamp, False
        if not self.has_year:
            stamp = stamp.replace(year=ctx.base_date().year)
        return stamp, True


class EpochDate:
    """%d{UNIX} (seconds) and %d{UNIX_MILLIS}."""
    kind = "epoch"
    has_date = True

    def __init__(self, millis):
        self.millis = millis
        self.regex = r"\d{13}" if millis else r"\d{10}(?:\.\d+)?"

    def parse(self, raw, _ctx):
        try:
            value = float(raw) / (1000 if self.millis else 1)
            return dt.datetime.fromtimestamp(value, dt.timezone.utc), True
        except (ValueError, OverflowError, OSError):
            return None


# Named %d formats of Log4j 1/2 and Logback. ISO-like names use the lenient date.
NAMED_DATES = {
    "ABSOLUTE": "HH:mm:ss,SSS", "ABSOLUTE_MICROS": "HH:mm:ss,nnnnnn", "ABSOLUTE_NANOS": "HH:mm:ss,nnnnnnnnn",
    "ABSOLUTE_PERIOD": "HH:mm:ss.SSS", "COMPACT": "yyyyMMddHHmmssSSS", "DATE": "dd MMM yyyy HH:mm:ss,SSS",
    "DATE_PERIOD": "dd MMM yyyy HH:mm:ss.SSS", "ISO8601_BASIC": "yyyyMMdd'T'HHmmss,SSS",
    "ISO8601_BASIC_PERIOD": "yyyyMMdd'T'HHmmss.SSS", "US_MONTH_DAY_YEAR2_TIME": "dd/MM/yy HH:mm:ss.SSS",
    "US_MONTH_DAY_YEAR4_TIME": "dd/MM/yyyy HH:mm:ss.SSS",
}
ANY_NAMES = {"", "ISO8601", "ISO8601_PERIOD", "DEFAULT", "DEFAULT_PERIOD", "DEFAULT_MICROS", "DEFAULT_NANOS",
             "ISO8601_OFFSET_DATE_TIME_HH", "ISO8601_OFFSET_DATE_TIME_HHMM", "ISO8601_OFFSET_DATE_TIME_HHCMM"}


def _named_zone(name):
    tz = parse_offset(name)
    if tz is None and zoneinfo is not None:
        try:
            tz = zoneinfo.ZoneInfo(name)
        except (zoneinfo.ZoneInfoNotFoundError, ValueError):
            tz = None
    return tz


def make_date(fmt=None, tz_name=None):
    tz = _named_zone(tz_name) if tz_name else None
    if tz_name and tz is None:
        raise ValueError(f"time zone '{tz_name}' in %d{{...}}{{{tz_name}}} is not known")
    name = (fmt or "").strip()
    if name.upper() in ANY_NAMES:
        return AnyDate(tz)
    if name.upper() in ("UNIX", "UNIX_MILLIS"):
        return EpochDate(name.upper() == "UNIX_MILLIS")
    return SdfDate(NAMED_DATES.get(name.upper(), name), tz)


# --------------------------------------------------------------------------- pattern layouts

# Conversion word -> field kind. Words not listed compile to a lazy wildcard and are not stored.
WORDS = {
    "d": "date", "date": "date",
    "p": "level", "le": "level", "level": "level",
    "c": "logger", "lo": "logger", "logger": "logger",
    "C": "class", "class": "class",
    "M": "method", "method": "method",
    "L": "line", "line": "line",
    "F": "file", "file": "file",
    "l": "location", "location": "location",
    "t": "thread", "thread": "thread", "tn": "thread", "threadName": "thread",
    "T": "tid", "tid": "tid", "threadId": "tid",
    "m": "message", "msg": "message", "message": "message",
    "pid": "pid", "processId": "pid",
    "X": "mdc", "mdc": "mdc", "MDC": "mdc",
    "x": "ndc", "NDC": "ndc",
    "marker": "marker", "markerSimpleName": "marker",
    "r": "relative", "relative": "relative",
    "sn": "sequence", "sequenceNumber": "sequence",
    "cn": "context", "contextName": "context", "applicationName": "appname",
    "n": "newline",
}
# Words that print nothing on the header line (exceptions are written on the lines after it).
EMPTY_WORDS = {"ex", "exception", "throwable", "xEx", "xException", "xThrowable", "rEx", "rException",
               "rThrowable", "wEx", "wex", "xwEx", "nopex", "nopexception", "caller", "throwableProxy",
               "exceptionClass", "noConsoleNoAnsi"}
# Log4j 2 composite words that take their inner pattern as the first {option}:
# %highlight{%-5level}, %style{%d}{bright}, %enc{%m}, %replace{%msg}{regex}{text}, %maxLen{%m}{100}.
BRACE_COMPOSITES = {"highlight", "style", "enc", "encode", "equals", "equalsIgnoreCase", "notEmpty",
                    "variablesNotEmpty", "varsNotEmpty", "maxLen", "maxLength", "replace"}
FIELD_RE = {
    "level": LEVEL_RE,
    "logger": r"\S+",
    "class": r"\S+",
    "method": r"[^\s.:()\[\]]+",
    "line": r"(?:\d+|\?)",
    "file": r"[^\s:()\[\]]+",
    "location": r"\S+",
    "thread": r".*?",
    "tid": r"\d+",
    "pid": r"\d+",
    "mdc": r".*?",
    "ndc": r".*?",
    "marker": r".*?",
    "relative": r"\d+",
    "sequence": r"\d+",
    "context": r"[^\]\s]*",
    "appname": r"[^\]]*?",
    "other": r".*?",
}
_TOKEN = re.compile(r"%(?P<mod>-?\d*(?:\.-?\d+)?)(?:(?P<paren>\()|(?P<word>[A-Za-z]+))")
_PROP = re.compile(r"\$\{(?P<name>[A-Za-z0-9_.]+)(?::-?(?P<default>(?:[^{}]|\{[^{}]*\})*))?\}")


def _options(text, i):
    """Read {..}{..} options at text[i:]; returns (list, new index)."""
    opts = []
    while i < len(text) and text[i] == "{":
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        opts.append(text[i + 1:j])
        i = j + 1
    return opts, i


def _close_paren(text, i):
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "(" and (j == 0 or text[j - 1] != "\\"):
            depth += 1
        elif text[j] == ")" and text[j - 1] != "\\":
            depth -= 1
            if depth == 0:
                return j
    raise ValueError("unbalanced '(' in pattern")


def resolve_properties(pattern):
    """${PID:- } -> %pid, ${NAME:-default} -> default, ${NAME} -> a wildcard (Logback/Spring)."""
    for _ in range(5):
        def repl(m):
            name = m.group("name")
            if name.upper() in ("PID", "PROCESS_ID"):
                return "%pid"
            if m.group("default") is not None:
                return m.group("default")
            return "%property"
        new = _PROP.sub(repl, pattern)
        if new == pattern:
            break
        pattern = new
    return pattern


class Layout:
    """A compiled pattern layout: header regex plus what each group holds."""

    def __init__(self, name, pattern):
        self.name = name
        self.pattern = pattern
        self.groups = {}        # group name -> (kind, option)
        self.date = None
        self._n = 0
        self._has_message = False
        body = self._compile(resolve_properties(pattern).replace("\\t", "\t"), top=True)
        if self.date is None:
            raise ValueError(f"pattern '{pattern}' has no %d date")
        if not self._has_message:
            body += r".*"
        self.regex = re.compile("^" + body + r"[ \t]*$")
        self.kinds = {k for k, _ in self.groups.values()}
        # More fields = more specific: wins a tie when two layouts match the same lines.
        self.specificity = len(self.groups)

    def _group(self, kind, option, rx):
        name = f"g{self._n}"
        self._n += 1
        self.groups[name] = (kind, option)
        return f"(?P<{name}>{rx})"

    def _compile(self, text, top=False):
        out, i = [], 0
        while i < len(text):
            ch = text[i]
            if ch == "%":
                if text.startswith("%%", i):
                    out.append("%")
                    i += 2
                    continue
                m = _TOKEN.match(text, i)
                if not m:
                    out.append("%")
                    i += 1
                    continue
                mod = m.group("mod")
                if m.group("paren"):            # %-30(...) grouping
                    end = _close_paren(text, m.start("paren"))
                    inner = self._compile(text[m.start("paren") + 1:end])
                    _, i = _options(text, end + 1)
                    out.append(self._pad(f"(?:{inner})", mod))
                    continue
                word = m.group("word")
                i = m.end()
                if i < len(text) and text[i] == "(":   # %highlight(...), %clr(...), %replace(...)
                    end = _close_paren(text, i)
                    inner = self._compile(text[i + 1:end])
                    _, i = _options(text, end + 1)
                    out.append(self._pad(f"(?:{inner})", mod))
                    continue
                opts, i = _options(text, i)
                if word in BRACE_COMPOSITES and opts and "%" in opts[0]:
                    out.append(self._pad(f"(?:{self._compile(opts[0])})", mod))
                    continue
                kind = WORDS.get(word)
                if kind is None and word in EMPTY_WORDS:
                    continue
                if kind == "newline":
                    if top:
                        break               # anything after %n (%ex, %throwable) is not on this line
                    continue
                if kind == "date":
                    if self.date is not None:
                        out.append(self._pad(r".*?", mod))
                        continue
                    self.date = make_date(opts[0] if opts else None, opts[1] if len(opts) > 1 else None)
                    out.append(self._pad(self._group("date", None, self.date.regex), mod))
                    continue
                if kind == "message":
                    self._has_message = True
                    rest = text[i:]
                    last = top and not re.sub(r"%n.*", "", rest, flags=re.S).strip()
                    out.append(self._group("message", None, r".*" if last else r".*?"))
                    continue
                if kind is None:
                    kind = "other"
                option = opts[0] if opts else None
                if kind == "mdc" and option:
                    option = option.split(":-")[0]
                out.append(self._pad(self._group(kind, option, FIELD_RE[kind]), mod))
                continue
            if ch in " \t":
                j = i
                while j < len(text) and text[j] in " \t":
                    j += 1
                out.append(r"[ \t]+")
                i = j
                continue
            if ch == "\\" and i + 1 < len(text):
                out.append(re.escape(text[i + 1]))
                i += 2
                continue
            out.append(re.escape(ch))
            i += 1
        return "".join(out)

    @staticmethod
    def _pad(rx, mod):
        """A minimum width pads with spaces: after the value for %-5p, before it for %5p."""
        m = re.match(r"(-?)(\d*)", mod or "")
        if not m.group(2):
            return rx
        return rx + "[ ]*" if m.group(1) else "[ ]*" + rx

    def match(self, line):
        return self.regex.match(line)


# Built-in layouts, in preference order for ties. %d is the lenient date in all of them.
BUILTIN_LAYOUTS = [
    # Log4j/Logback with method and line in brackets, e.g. '%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n'
    ("log4j-logger-method-line", "%d %-5p %c [%M :%L] %m"),
    ("log4j-logger-method-line-compact", "%d %-5p %c [%M:%L] %m"),
    # Spring Boot 3.x (application name) and 1.x/2.x defaults
    ("spring-boot-3", "%d %5p %pid --- [%applicationName] [%t] %-40.40c : %m"),
    ("spring-boot", "%d %5p %pid --- [%t] %-40.40c : %m"),
    # Logback / Log4j 2 defaults ('%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n')
    ("logback-default", "%d [%t] %-5p %c - %m"),
    ("log4j-thread-logger-line", "%d [%t] %-5p %c:%L - %m"),
    # Log4j 1 conversion patterns most often seen in log4j.properties
    ("log4j-level-thread-logger-line", "%d %-5p [%t] %c:%L - %m"),
    ("log4j-level-thread-logger", "%d %-5p [%t] %c - %m"),
    ("log4j-level-logger-line", "%d %-5p %c:%L - %m"),
    ("log4j-level-logger", "%d %-5p %c - %m"),
    ("log4j-level-bracket-logger-line", "%d %-5p [%c:%L] %m"),
    # JBoss / WildFly ('%d %-5p [%c] (%t) %m') and its no-thread variant
    ("wildfly", "%d %-5p [%c] (%t) %m"),
    ("log4j-level-bracket-logger", "%d %-5p [%c] %m"),
    # Tomcat / java.util.logging OneLineFormatter ('26-Nov-2026 00:01:16.063 INFO [main] class.method msg')
    ("jul-oneline", "%d %p [%t] %c %m"),
    ("bracket-date-thread-level-logger", "[%d] [%t] %-5p %c - %m"),
    ("bracket-date-level-logger", "[%d] %-5p %c - %m"),
    ("level-first-thread-logger", "%-5p %d [%t] %c: %m"),
    ("level-first-logger-line", "%-5p %d %c:%L - %m"),
]
# Fallbacks: date and level only; they still split events, but keep the rest in message.
GENERIC_LAYOUTS = [
    ("generic-date-level", "%d %-5p %m"),
    ("generic-date-bracket-level", "%d [%-5p] %m"),
    ("generic-date-thread-level", "%d [%t] %-5p %m"),
    ("generic-date-level-thread", "%d %-5p [%t] %m"),
    ("generic-bracket-date-level", "[%d] %-5p %m"),
    ("generic-bracket-date-bracket-level", "[%d] [%-5p] %m"),
    ("generic-level-date", "%-5p %d %m"),
    ("generic-bracket-level-date", "[%-5p] %d %m"),
]
_COMPILED = None


def builtin_layouts():
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = ([Layout(n, p) for n, p in BUILTIN_LAYOUTS], [Layout(n, p) for n, p in GENERIC_LAYOUTS])
    return _COMPILED


def patterns_from_config(path):
    """Pattern layouts in a log4j.properties, log4j2.xml/.properties/.yaml/.json or logback.xml."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    found = []
    regexes = [
        r"(?im)^\s*log4j\.appender\.[^=\s]+\.layout\.ConversionPattern\s*[=:]\s*(.+?)\s*$",   # log4j 1
        r"(?im)^\s*appender\.[^=\s]+\.layout\.pattern\s*[=:]\s*(.+?)\s*$",                    # log4j2 .properties
        r"(?is)<pattern>\s*(.+?)\s*</pattern>",                                              # logback / log4j2 xml
        r"(?is)<param\s+name=\"ConversionPattern\"\s+value=\"([^\"]+)\"",                     # log4j 1 xml
        r"(?is)<PatternLayout[^>]*\spattern=\"([^\"]+)\"",                                    # log4j2 xml
        r"(?im)^\s*\"?pattern\"?\s*:\s*\"(.+?)\"\s*,?\s*$",                                    # log4j2 yaml/json
    ]
    for rx in regexes:
        for m in re.finditer(rx, text):
            value = html.unescape(m.group(1)).strip()
            if value.startswith("<![CDATA[") and value.endswith("]]>"):
                value = value[9:-3].strip()
            if "%" in value and value not in found:
                found.append(value)
    return found


# --------------------------------------------------------------------------- per-file context

DATE_IN_NAME = re.compile(r"(?<!\d)(20\d{2})-?(0[1-9]|1[0-2])-?(0[1-9]|[12]\d|3[01])(?!\d)")


class FileContext:
    """What one file's dates need: numeric order, base date for time-only layouts, time zone."""

    def __init__(self, path, rel, tz, order=None, log_date=None):
        self.path, self.rel, self.tz = path, rel, tz
        self.forced_order = order
        self.order = order
        self.log_date = log_date
        self._base = None
        self.base_source = None
        self.rollover_days = 0
        self.notes = []

    def learn_orders(self, raws):
        """Decide the numeric date order from sample date texts."""
        if self.forced_order:
            return
        feasible, sep = set(ORDERS), None
        seen = False
        for raw in raws:
            m = _ANY_PARTS.match(raw.strip())
            if m and m.group("d1"):
                seen = True
                sep = sep or m.group("sep")
                feasible &= set(numeric_orders(m.group("d1"), m.group("d2"), m.group("d3")))
        if not seen:
            return
        prefer = {"/": ("mdy", "dmy", "ymd"), ".": ("dmy", "ymd", "mdy")}.get(sep, ("ymd", "dmy", "mdy"))
        choice = next((o for o in prefer if o in feasible), None)
        if choice is None:
            choice = prefer[0]
        self.order = choice
        sample = next((r for r in raws if _ANY_PARTS.match(r.strip()) and _ANY_PARTS.match(r.strip()).group("d1")), "")
        first = _ANY_PARTS.match(sample.strip()) if sample else None
        if first and len(first.group("d1")) <= 2 and len(feasible) > 1:
            self.notes.append(f"dates like '{sample.split()[0]}' read as {choice} (no line rules out"
                              f" {'/'.join(sorted(feasible - {choice}))}; use --date-order to change)")

    def order_for(self, d1, d2, d3, sep):
        if len(d1) == 4:
            return "ymd"
        valid = numeric_orders(d1, d2, d3)
        if self.order in valid:
            return self.order
        return valid[0] if valid else None

    def base_date(self):
        if self._base is None:
            if self.log_date:
                self._base, self.base_source = self.log_date, "--log-date"
            else:
                m = DATE_IN_NAME.search(PurePosixPath(self.rel).name)
                try:
                    if m:
                        self._base = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
                        self.base_source = "file name"
                except ValueError:
                    self._base = None
                if self._base is None:
                    stamp = dt.datetime.fromtimestamp(os.stat(self.path).st_mtime, dt.timezone.utc)
                    stamp = stamp.astimezone(self.tz) if self.tz else stamp
                    self._base = stamp.date() - dt.timedelta(days=self.rollover_days)
                    self.base_source = "file modification time"
        return self._base


# --------------------------------------------------------------------------- reading

def read_head(path, limit):
    try:
        with open_compressed(path) as raw:
            head = raw.read(limit)
    except Exception:  # noqa: BLE001 - unreadable or corrupt compressed data means "not mine"
        return None
    if not head or b"\x00" in head[:4096]:
        return None
    lines = head.decode("utf-8", "replace").splitlines()
    if len(head) == limit and len(lines) > 1:
        lines = lines[:-1]      # the last line may be cut off by the read limit
    return [x.lstrip("﻿") for x in lines[:SNIFF_LINES]]


JAVA_SIGNAL = re.compile(r"(?:\b(?:[a-z_$][\w$]*\.){2,}[A-Z][\w$]*\b|^\s+at [\w$.<>]+\(|"
                         r"\b\w+(?:Exception|Error)\b)", re.M)


def score_layouts(lines, layouts):
    """{layout: header lines it matches} for the sample lines."""
    hits = {}
    for layout in layouts:
        n = sum(1 for x in lines if layout.match(x))
        if n:
            hits[layout] = n
    return hits


def pick(hits, order):
    """Best layout: most matching lines, then the most fields, then list order."""
    return max(hits, key=lambda lay: (hits[lay], lay.specificity, -order.index(lay)))


TIMED_LINE = re.compile(r"\d{1,2}:\d{2}:\d{2}")


def detect(path, layouts=None):
    """True when the file (plain, .gz, .bz2 or .xz) looks like a Java application log.

    Used by this importer and by SOF-ELK_ImportWrapper.py, so both agree on a file. A layout must
    match at least half of the first lines that carry a time near their start (continuation lines
    such as stack frames and SQL do not count), and unless the layout has a logger or class, the
    sample must show something Java (a package.Class name, a stack frame or an ...Exception), so
    other 'date level message' logs (Python, Windows CBS) are left alone."""
    lines = read_head(path, DETECT_BYTES)
    if not lines:
        return False
    lines = [x for x in lines if x.strip()]
    if not lines:
        return False
    if not any(x[:1].isdigit() or x[:1] in "[" or x[:1].isalpha() for x in lines[:50]):
        return False
    specific, generic = builtin_layouts()
    candidates = layouts or (specific + generic)
    hits = score_layouts(lines, candidates)
    if not hits:
        return False
    best = pick(hits, candidates)
    # Lines that carry a time near their start but are no header of any layout found point to a
    # different log format that happens to match now and then: at least half must be headers.
    timed = [x for x in lines if x[:1] not in " \t" and TIMED_LINE.search(x[:48])]
    headers = sum(1 for x in timed if any(lay.match(x) for lay in hits))
    if headers * 2 < len(timed):
        return False
    if layouts:
        return True
    return ("logger" in best.kinds or "class" in best.kinds) or bool(JAVA_SIGNAL.search("\n".join(lines)))


# --------------------------------------------------------------------------- event analysis

THROWABLE_LINE = re.compile(
    r"^\s*(?:Caused by:\s*|Suppressed:\s*|Wrapped by:\s*|nested exception is:?\s*|"
    r"Exception in thread \"[^\"]*\"\s+)?"
    r"(?P<cls>(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*(?:Exception|Error|Throwable|Fault|Failure))"
    r"\b(?::\s?(?P<msg>.*))?$")
THROWABLE_ANY = re.compile(r"(?<![\w$.])(?P<cls>(?:[a-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error))\b"
                           r"(?::\s?(?P<msg>.*))?")
FRAME_LINE = re.compile(r"^\s+at\s+(?P<frame>\S.*?)\s*$")
MORE_LINE = re.compile(r"^\s+\.\.\. \d+ (?:more|common frames omitted)")

SQL_MARKER = re.compile(
    r"(?i)(?:(?:Executing|Preparing) (?:prepared )?(?:Statement|Call|Query|Update|Batch|SQL(?: query| statement| update)?)|"
    r"Preparing|Hibernate|SQL(?: statement| query)?|Query|statement|sql)\s*[:=]\s*\[?")
SQL_START = re.compile(r"(?is)^[\s(]*(SELECT|INSERT|UPDATE|DELETE|MERGE|WITH|CALL|EXEC(?:UTE)?|CREATE|DROP|"
                       r"ALTER|TRUNCATE|GRANT|REVOKE|REPLACE|UPSERT|BEGIN|DECLARE)\b")
SQL_SHAPE = {
    "SELECT": re.compile(r"(?is)^[\s(]*SELECT\b.+\bFROM\b"),
    "WITH": re.compile(r"(?is)^[\s(]*WITH\b.+\bAS\s*\(.+\bSELECT\b"),
    "INSERT": re.compile(r"(?is)^[\s(]*INSERT\s+(?:ALL\s+)?INTO\b"),
    "UPDATE": re.compile(r"(?is)^[\s(]*UPDATE\s+\S+(?:\s+\w+)?\s+SET\b"),
    "DELETE": re.compile(r"(?is)^[\s(]*DELETE\s+(?:FROM\s+)?\S+"),
    "MERGE": re.compile(r"(?is)^[\s(]*MERGE\s+INTO\b"),
    "CREATE": re.compile(r"(?is)^[\s(]*CREATE\s+(?:OR\s+REPLACE\s+)?(?:GLOBAL\s+TEMPORARY\s+|UNIQUE\s+)?"
                         r"(?:TABLE|INDEX|VIEW|USER|PROCEDURE|FUNCTION|TRIGGER|SEQUENCE|SCHEMA|DATABASE|ROLE|PACKAGE)\b"),
    "DROP": re.compile(r"(?is)^[\s(]*DROP\s+(?:TABLE|INDEX|VIEW|USER|PROCEDURE|FUNCTION|TRIGGER|SEQUENCE|SCHEMA|DATABASE|ROLE|PACKAGE)\b"),
    "ALTER": re.compile(r"(?is)^[\s(]*ALTER\s+(?:TABLE|INDEX|VIEW|USER|PROCEDURE|SESSION|SYSTEM|DATABASE|ROLE)\b"),
    "TRUNCATE": re.compile(r"(?is)^[\s(]*TRUNCATE\s+TABLE\b"),
    "GRANT": re.compile(r"(?is)^[\s(]*GRANT\b.+\b(?:ON|TO)\b"),
    "REVOKE": re.compile(r"(?is)^[\s(]*REVOKE\b.+\b(?:ON|FROM)\b"),
}
_NAME = r"[A-Za-z_#@\[\"`][\w$#@.\[\]\"`]*"
SQL_TABLE = re.compile(r"(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE|USING|CALL|EXEC(?:UTE)?)\s+(?!\()(?!SELECT\b)(" + _NAME + ")")
# DELETE without FROM (Oracle) and the rest of a comma-separated FROM list (FROM A x, B y).
SQL_DELETE = re.compile(r"(?i)^\s*DELETE\s+(?!FROM\b)(" + _NAME + ")")
SQL_FROM_LIST = re.compile(r"(?i)\bFROM\s+([^()]+?)(?=\s+(?:WHERE|GROUP|ORDER|CONNECT|START|HAVING|UNION|MINUS|"
                           r"INTERSECT|EXCEPT|FETCH|LIMIT|FOR|JOIN|INNER|LEFT|RIGHT|FULL|CROSS)\b|\)|;|$)")
SQL_NOT_TABLES = {"DUAL", "SET", "VALUES", "SELECT", "WHERE", "ONLY", "LATERAL", "TABLE", "?"}
IBATIS_ID = re.compile(r"^\{((?:conn|pstm|stmt|rset)-\d+)\}")
MDC_KEYS = {"traceid": "trace.id", "trace_id": "trace.id", "x-b3-traceid": "trace.id", "trace.id": "trace.id",
            "spanid": "span.id", "span_id": "span.id", "x-b3-spanid": "span.id", "span.id": "span.id",
            "user": "user.name", "username": "user.name", "user.name": "user.name", "userid": "user.name"}


def find_sql(first, rest):
    """(statement start text) of an SQL statement in the event, or None."""
    candidates = []
    for m in SQL_MARKER.finditer(first):
        tail = first[m.end():]
        candidates.append((tail + ("\n" + rest if rest else ""), True))
    candidates.append((first + ("\n" + rest if rest else ""), False))
    if rest:
        for m in re.finditer(r"(?m)^", rest):
            candidates.append((rest[m.start():], False))
            if len(candidates) > 40:
                break
    for text, marked in candidates:
        stripped = text.lstrip()
        if not stripped:
            if marked and rest and SQL_START.match(rest):
                stripped = rest.lstrip()
            else:
                continue
        start = SQL_START.match(stripped)
        if not start:
            continue
        verb = start.group(1).upper()
        verb = "EXECUTE" if verb == "EXEC" else verb
        shape = SQL_SHAPE.get(verb)
        if not marked and (shape is None or not shape.match(stripped[:20000])):
            continue
        if marked and shape is not None and verb in ("SELECT", "WITH") and not shape.match(stripped[:20000]):
            continue
        return verb, stripped
    return None


def analyse(doc, first, rest):
    """Exception and SQL fields of one event."""
    tags = []
    lines = ([first] if first else []) + (rest.split("\n") if rest else [])
    classes, frames, top_frame, err_msg, stack_start = [], 0, None, None, None
    root_msg = None
    for i, line in enumerate(lines):
        m = THROWABLE_LINE.match(line)
        if m is None and i == 0:
            m = THROWABLE_ANY.search(line)
        if m:
            if stack_start is None:
                stack_start = i
                err_msg = (m.group("msg") or "").strip() or None
            if not classes or classes[-1] != m.group("cls") or line.lstrip().startswith(("Caused", "nested")):
                classes.append(m.group("cls"))
            root_msg = (m.group("msg") or "").strip() or None
            continue
        f = FRAME_LINE.match(line)
        if f and i > 0:
            frames += 1
            if top_frame is None:
                top_frame = f.group("frame")
            if stack_start is None:
                stack_start = i
    if classes:
        tags.append("exception")
        set_field(doc, "error.type", classes[0])
        set_field(doc, "error.message", err_msg)
        uniq = list(dict.fromkeys(classes))
        set_field(doc, "javalog.exception.classes", uniq)
        set_field(doc, "javalog.exception.root_cause", classes[-1])
        set_field(doc, "javalog.exception.root_cause_message", root_msg)
    if frames or (classes and len(lines) > 1 and stack_start is not None and stack_start < len(lines) - 1):
        tags.append("stack_trace")
        set_field(doc, "error.stack_trace", "\n".join(lines[stack_start:]).rstrip())
        set_field(doc, "javalog.exception.top_frame", top_frame)
        if frames:
            set_field(doc, "javalog.exception.frame_count", frames)
    obj = IBATIS_ID.match(first or "")
    if obj:
        set_field(doc, "javalog.sql.object_id", obj.group(1))
    sql = find_sql(first or "", rest)
    if sql:
        verb, text = sql
        statement = " ".join(text.split())
        tags.append("sql")
        set_field(doc, "javalog.sql.verb", verb)
        set_field(doc, "javalog.sql.statement", statement)
        tables = []
        found = SQL_TABLE.findall(statement) + SQL_DELETE.findall(statement)
        for listed in SQL_FROM_LIST.findall(statement):
            found += [part.split()[0] for part in listed.split(",")[1:] if part.split()]
        for t in found:
            name = t.strip("[]\"`").upper().rstrip(",;")
            if name and name not in SQL_NOT_TABLES and name not in tables:
                tables.append(name)
        set_field(doc, "javalog.sql.tables", tables[:50])
    return tags


# --------------------------------------------------------------------------- input

class FileProfile:
    """The host the logs came from: only what the command line says."""

    def __init__(self, hostname, host_os=None, local_tz=None):
        self.hostname = sanitize_hostname(hostname)
        self.host_os = host_os
        self.tz, self.tz_name = None, None
        if local_tz:
            self.tz = _named_zone(local_tz)
            if self.tz is None:
                raise ValueError(f"--local-tz '{local_tz}' is neither a UTC offset (+08:00) nor a time"
                                 " zone name this Python knows")
            self.tz_name = local_tz

    def fields(self):
        doc = {}
        set_field(doc, "host.name", self.hostname)
        set_field(doc, "host.os.type", self.host_os)
        return doc


def find_files(paths):
    files = []
    for p in map(Path, paths):
        if p.is_dir():
            found = [x for x in p.rglob("*") if x.is_file() and not x.name.startswith(".")]
            files += [(x, x.relative_to(p).as_posix()) for x in found]
        elif p.is_file():
            files.append((p, p.name))
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    return sorted(files, key=lambda fr: rotation_sort_key(fr[1]))


SERVICE_SUFFIX = re.compile(r"(?:[._-]\d{4}-?\d{2}-?\d{2}(?:[._-]?\d{2,6})?(?:[._-]\d+)?|\.(?:log|txt|out|err))$", re.I)


def service_from_name(name):
    """'stwg-server.log' -> 'stwg-server', 'catalina.2026-11-26.log' -> 'catalina', 'app.log.3.gz' -> 'app'."""
    base = rotation_family(name)
    for _ in range(4):
        new = SERVICE_SUFFIX.sub("", base)
        if new == base:
            break
        base = new
    return base or name


class Plan:
    """How one file is read: its layouts (best first) and its date context."""

    def __init__(self, path, rel, layouts, ctx, hits):
        self.path, self.rel, self.layouts, self.ctx, self.hits = path, rel, layouts, ctx, hits


def plan_file(path, rel, args, profile, user_layouts):
    lines = read_head(path, SNIFF_BYTES)
    if not lines:
        return None, "empty or binary"
    lines = [x.rstrip("\r") for x in lines if x.strip()]
    if user_layouts:
        hits = score_layouts(lines, user_layouts)
        if not hits:
            return None, "no --pattern matches its first lines"
        order = sorted(hits, key=lambda lay: (-hits[lay], -lay.specificity, user_layouts.index(lay)))
        layouts = order + [x for x in user_layouts if x not in hits]
    else:
        if not detect(path):
            return None, "not a Java log layout this importer knows (use --pattern)"
        specific, generic = builtin_layouts()
        hits = score_layouts(lines, specific + generic)
        best = pick(hits, specific + generic)
        others = sorted((x for x in hits if x is not best and x in specific),
                        key=lambda lay: (-hits[lay], -lay.specificity))
        layouts = [best] + others + [x for x in generic if x is not best]
    ctx = FileContext(path, rel, profile.tz, args.date_order, args.log_date)
    raws = []
    for line in lines:
        for lay in layouts[:1]:
            m = lay.match(line)
            if m:
                raws.extend(m.group(g) for g, (k, _) in lay.groups.items() if k == "date" and m.group(g))
    ctx.learn_orders(raws)
    return Plan(path, rel, layouts, ctx, hits), None


def collect(_ev, profile, args):
    items, skipped = [], []
    for f, rel in find_files(args.paths):
        plan, why = plan_file(f, rel, args, profile, args.user_layouts)
        if plan is None:
            skipped.append((rel, why))
            continue
        items.append(plan)
    print(f"{len(items)} Java log file(s)")
    for plan in items:
        print(f"  {plan.rel}: layout {plan.layouts[0].name} ({plan.hits.get(plan.layouts[0], 0)} of the first"
              f" lines are event headers)")
        for note in plan.ctx.notes:
            print(f"    note: {note}")
    if skipped:
        print(f"  skipped {len(skipped)} file(s): " + ", ".join(f"{r} ({w})" for r, w in skipped[:5])
              + (" ..." if len(skipped) > 5 else ""))
    if items and profile.tz is None:
        print("  WARNING: no --local-tz given; times without an offset are read as UTC")
    return items


def item_label(plan):
    extra = ""
    if plan.ctx.base_source:
        extra = f"; date from {plan.ctx.base_source} {plan.ctx.base_date().isoformat()}"
    return f"{plan.rel} ({plan.layouts[0].name}{extra})"


# --------------------------------------------------------------------------- parsing

class Event:
    """One log event being read: its header line and the continuation lines merged into it."""
    __slots__ = ("offset", "layout", "match", "header", "lines", "chars", "truncated", "count", "stamp",
                 "stamp_note")

    def __init__(self, offset, layout, match, header, stamp, stamp_note=None):
        self.offset, self.layout, self.match, self.header, self.stamp = offset, layout, match, header, stamp
        self.stamp_note = stamp_note
        self.lines, self.chars, self.truncated, self.count = [], 0, False, 1


def iter_lines(path):
    with io.TextIOWrapper(open_compressed(path), encoding="utf-8", errors="replace", newline="") as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if offset == 0:
                line = line.lstrip("﻿")
            yield offset, line


def header_of(line, layouts):
    if not line or line[0] in " \t":
        return None, None
    for lay in layouts:
        m = lay.match(line)
        if m:
            return lay, m
    return None, None


def raw_stamp(lay, m, ctx):
    """(raw date text, parsed datetime or None, has_date)."""
    for g, (kind, _) in lay.groups.items():
        if kind == "date":
            raw = m.group(g)
            parsed = lay.date.parse(raw, ctx) if raw else None
            if parsed is None:
                return raw, None, True
            return raw, parsed[0], parsed[1]
    return None, None, True


def count_rollovers(plan):
    """Midnights crossed in a time-only file (its mtime is the last day, not the first)."""
    days, prev = 0, None
    for _offset, line in iter_lines(plan.path):
        lay, m = header_of(line, plan.layouts)
        if lay is None:
            continue
        _raw, stamp, has_date = raw_stamp(lay, m, plan.ctx)
        if stamp is None or has_date:
            continue
        t = stamp.hour * 3600 + stamp.minute * 60 + stamp.second
        if prev is not None and t < prev - 3600:
            days += 1
        prev = t
    return days


def parse(_ev, profile, args, plan, report):
    ctx = plan.ctx
    family = rotation_family(PurePosixPath(plan.rel).name)
    service = args.service or service_from_name(PurePosixPath(plan.rel).name)
    tz_name = profile.tz_name or "UTC"
    max_chars = args.max_message_chars
    seen = parse.seen
    state = {"day": 0, "prev": None, "last": None}

    def stamp_of(lay, m):
        raw, stamp, has_date = raw_stamp(lay, m, ctx)
        if stamp is None:
            return raw, None
        if not has_date:
            if ctx.base_source is None and not ctx.log_date and not DATE_IN_NAME.search(PurePosixPath(plan.rel).name):
                ctx.rollover_days = count_rollovers(plan)
            base = ctx.base_date()
            t = stamp.hour * 3600 + stamp.minute * 60 + stamp.second
            if state["prev"] is not None and t < state["prev"] - 3600:
                state["day"] += 1
            state["prev"] = t
            day = base + dt.timedelta(days=state["day"])
            stamp = stamp.replace(year=day.year, month=day.month, day=day.day)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=profile.tz or dt.timezone.utc)
        return raw, stamp

    def build(ev, orphan=False):
        lay, m = ev.layout, ev.match
        doc = {"@timestamp": iso_utc(ev.stamp)}
        first = ""
        mdc = []
        if m is not None:
            for g, (kind, option) in lay.groups.items():
                value = m.group(g)
                if value is None:
                    continue
                value = value.strip()
                if kind == "message":
                    first = value
                    continue
                if kind == "date" or not value or value in ("?", "-"):
                    if kind == "date":
                        set_field(doc, "javalog.timestamp_original", value)
                    continue
                if kind == "level":
                    set_field(doc, "log.level", value.upper())
                elif kind == "logger":
                    set_field(doc, "log.logger", value)
                elif kind == "class":
                    set_field(doc, "javalog.class", value)
                elif kind == "method":
                    set_field(doc, "log.origin.function", value)
                elif kind == "line" and value.isdigit():
                    set_field(doc, "log.origin.file.line", int(value))
                elif kind == "file":
                    set_field(doc, "log.origin.file.name", value)
                elif kind == "location":
                    set_field(doc, "javalog.location", value)
                    loc = re.match(r"^(?P<cls>.+)\.(?P<meth>[^.(]+)\((?P<file>[^:)]*)(?::(?P<line>\d+))?\)$", value)
                    if loc:
                        doc.setdefault("javalog", {}).setdefault("class", loc.group("cls"))
                        doc.setdefault("log", {}).setdefault("origin", {}).setdefault("function", loc.group("meth"))
                        if loc.group("file"):
                            doc["log"]["origin"].setdefault("file", {}).setdefault("name", loc.group("file"))
                        if loc.group("line"):
                            doc["log"]["origin"].setdefault("file", {}).setdefault("line", int(loc.group("line")))
                elif kind == "thread":
                    set_field(doc, "process.thread.name", value)
                elif kind in ("tid", "pid", "relative", "sequence") and value.isdigit():
                    target = {"tid": "process.thread.id", "pid": "process.pid", "relative": "javalog.relative_ms",
                              "sequence": "javalog.sequence"}[kind]
                    set_field(doc, target, int(value))
                elif kind == "mdc":
                    if option:
                        mdc.append(f"{option}={value}")
                        ecs = MDC_KEYS.get(option.lower())
                        if ecs and not (doc.get(ecs.split(".")[0]) or {}).get(ecs.split(".")[1]):
                            set_field(doc, ecs, value)
                    else:
                        mdc.append(value)
                elif kind == "ndc":
                    set_field(doc, "javalog.ndc", value)
                elif kind == "marker":
                    set_field(doc, "javalog.marker", value)
                elif kind == "context":
                    set_field(doc, "javalog.context", value)
                elif kind == "appname":
                    set_field(doc, "service.name", value)
        set_field(doc, "javalog.mdc", mdc)
        rest = "\n".join(ev.lines).rstrip()
        text = (first + ("\n" + rest if rest else "")) if not orphan else rest
        tags = []
        if ev.truncated:
            tags.append("message_truncated")
        if orphan:
            tags.append("orphan_lines")
            first = ev.lines[0].strip() if ev.lines else ""
            tags += analyse(doc, "", rest)
        else:
            tags += analyse(doc, first, rest)
        if ev.lines and not orphan:
            tags.insert(0, "multiline")
        doc["message"] = text
        set_field(doc, "javalog.first_line", first)
        set_field(doc, "javalog.line_count", ev.count)
        set_field(doc, "javalog.layout", lay.name if lay else None)
        set_field(doc, "javalog.pattern", lay.pattern if lay else None)
        doc.setdefault("service", {}).setdefault("name", service)
        set_field(doc, "event.kind", "event")
        set_field(doc, "event.dataset", DATASET)
        set_field(doc, "event.timezone", tz_name)
        set_field(doc, "labels.type", PREFIX)
        set_field(doc, "log.file.path", plan.rel)
        set_field(doc, "log.offset", ev.offset)
        if ev.stamp_note:
            tags.append(ev.stamp_note)
        set_field(doc, "tags", tags)
        key = hashlib.sha1((ev.header + "\n" + "\n".join(ev.lines)).encode("utf-8", "replace")).digest()
        n = seen.get((family, key), 0)
        seen[(family, key)] = n + 1
        parse.layouts[lay.name if lay else "orphan_lines"] = parse.layouts.get(lay.name if lay else "orphan_lines", 0) + 1
        return [family, key.hex(), n], doc

    orphans = None
    current = None
    for offset, line in iter_lines(plan.path):
        lay, m = header_of(line, plan.layouts)
        if lay is not None:
            raw, stamp = stamp_of(lay, m)
            note = None
            if stamp is None:
                if state["last"] is None:
                    lay = None      # an unreadable date before any event: keep it as text
                else:
                    stamp, note = state["last"], "timestamp_unparsed"
            if lay is not None:
                if current is not None:
                    yield build(current)
                elif orphans is not None:
                    orphans.stamp = stamp
                    yield build(orphans, orphan=True)
                    orphans = None
                current = Event(offset, lay, m, line, stamp, note)
                state["last"] = stamp
                continue
        target = current
        if target is None:
            if not line.strip():
                continue
            if orphans is None:
                orphans = Event(offset, None, None, "", None)
                orphans.count = 0
            target = orphans
        target.count += 1
        if target.truncated:
            continue
        if target.chars + len(line) + 1 > max_chars:
            target.truncated = True
            continue
        target.lines.append(line)
        target.chars += len(line) + 1
    if current is not None:
        yield build(current)
    elif orphans is not None:
        yield None, "lines with no event header (no layout matched any line)"


parse.seen = {}
parse.layouts = {}


def missing(_ev, _profile, _args):
    return 1, "No Java application logs found."


JAVALOG = LogSource("javalog", PREFIX, DATASET, collect, parse, item_label, missing=missing, templates="java")


# --------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Load Java application logs (Log4j, Log4j 2, Logback, JUL, Spring Boot)"
                                             " into SOF-ELK (index javalog-<hostname>), merging stack traces and"
                                             " multi-line SQL into their events",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Built-in layouts: " + ", ".join(n for n, _ in BUILTIN_LAYOUTS))
    ap.add_argument("paths", nargs="+", help="Log files or folders (searched recursively; .gz, .bz2 and .xz are fine)")
    ap.add_argument("--hostname", required=True, help="The host the logs came from (index javalog-<hostname>)")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--local-tz", help="Time zone of times without an offset: +08:00 or an IANA name"
                                       " (Asia/Singapore). Default UTC")
    ap.add_argument("--pattern", action="append", default=[],
                    help="The application's pattern layout, e.g. '%%d{yy-MM-dd HH:mm:ss.SSS} %%-5p %%c [%%M :%%L] %%m%%n'"
                         " (repeat for several appenders; replaces the built-in layouts)")
    ap.add_argument("--pattern-file", action="append", default=[],
                    help="log4j.properties, log4j2.xml/.properties/.yaml or logback.xml to read the patterns from")
    ap.add_argument("--date-order", choices=ORDERS,
                    help="Order of numeric dates such as 26-11-25 or 11/05/2026 (default: from the data;"
                         " yy-MM-dd for '-', MM/dd for '/', dd.MM for '.')")
    ap.add_argument("--log-date", help="Date (YYYY-MM-DD) of a time-only log (default: from the file name, else"
                                       " its modification time)")
    ap.add_argument("--service", help="service.name for every document (default: the log file name without"
                                      " extension and rotation suffix)")
    ap.add_argument("--host-os", choices=HOST_OS, help="host.os.type of the host (default: unset)")
    ap.add_argument("--max-message-chars", type=int, default=DEFAULT_MAX_CHARS,
                    help=f"Longest event kept, in characters; longer ones are cut and tagged message_truncated"
                         f" (default {DEFAULT_MAX_CHARS})")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true", help="Parse everything and show sample documents; send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    add_client_arguments(ap)
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    if args.max_message_chars < 1000:
        sys.exit("--max-message-chars must be at least 1000")
    if args.log_date:
        try:
            args.log_date = dt.date.fromisoformat(args.log_date)
        except ValueError:
            sys.exit(f"--log-date '{args.log_date}' is not YYYY-MM-DD")
    patterns = list(args.pattern)
    for cfg in args.pattern_file:
        try:
            found = patterns_from_config(cfg)
        except OSError as exc:
            sys.exit(f"Cannot read --pattern-file {cfg}: {exc}")
        if not found:
            sys.exit(f"No pattern layout found in {cfg}")
        print(f"Patterns from {cfg}: " + " | ".join(found))
        patterns += [p for p in found if p not in patterns]
    args.user_layouts = []
    for i, p in enumerate(patterns, 1):
        try:
            args.user_layouts.append(Layout("custom" if len(patterns) == 1 else f"custom-{i}", p))
        except (ValueError, re.error) as exc:
            sys.exit(f"Cannot use pattern '{p}': {exc}")
    try:
        profile = FileProfile(args.hostname, args.host_os, args.local_tz)
    except ValueError as exc:
        sys.exit(str(exc))
    print(f"Host: '{profile.hostname}'" + (f" ({profile.host_os})" if profile.host_os else "")
          + f"; local times read as {profile.tz_name or 'UTC'}")

    es = None
    if not args.dry_run:
        es = ES(args.es, args.user, args.password, args.insecure)
        try:
            status, info = es.call("GET", "/")
        except error.URLError as exc:
            sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {exc.reason}")
        if status >= 300:
            sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
        print(f"Connected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    parse.seen, parse.layouts = {}, {}
    code = run_source(JAVALOG, None, profile, args, es)
    if parse.layouts:
        print("Events per layout: " + ", ".join(f"{k} {v}" for k, v in sorted(parse.layouts.items())))
    if es is not None and code == 0:
        print("In Kibana, use the 'javalog-*' data view (time field @timestamp); ES|QL: FROM javalog-* METADATA _index.")
    return code


if __name__ == "__main__":
    sys.exit(main())
