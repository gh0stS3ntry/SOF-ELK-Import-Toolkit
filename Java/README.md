# Java application logs (Log4j, Logback, JUL, Spring Boot)

`javalog2sofelk.py` loads Java application logs written through a **pattern layout** (Log4j 1
`ConversionPattern`, Log4j 2 `PatternLayout`, Logback `<pattern>`, java.util.logging, Spring Boot,
Tomcat, WildFly) into SOF-ELK, one index per evidence host: `javalog-<hostname>`.

One document is one log **event**: the header line (date, level, logger, ...) plus every line after
it that does not start a new event. Exception stack traces (`\tat ...`, `Caused by: ...`,
`nested exception is:`), SQL statements that iBATIS/MyBatis/Hibernate print over many lines, and
XML/JSON payloads are merged into the event they belong to, so a whole stack trace or SQL statement
is one document and can be searched, counted and timelined as one.

## Usage

```bash
python3 Java/javalog2sofelk.py /cases/IR-42/app01/logs --hostname APP01 --local-tz +08:00 --dry-run
python3 Java/javalog2sofelk.py /cases/IR-42/app01/logs --hostname APP01 --local-tz Asia/Singapore --case IR-42
# the application's own pattern, as written in its configuration
python3 Java/javalog2sofelk.py server.log --hostname APP01 --local-tz +08:00 \
    --pattern '%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n'
python3 Java/javalog2sofelk.py logs/ --hostname APP01 --local-tz +08:00 \
    --pattern-file /cases/IR-42/app01/WEB-INF/classes/log4j.properties
```

Folders are searched recursively; `.gz`, `.bz2` and `.xz` files are read without unpacking.
Rotated files (`server.log.1`, `app.2026-11-26.log.gz`) are read oldest first. Files that do not
look like Java logs are skipped and listed.

| Option | Meaning |
|---|---|
| `--hostname` | Evidence host (required): index `javalog-<hostname>`, `host.name` |
| `--local-tz` | Zone of times without an offset: `+08:00` or an IANA name. Default UTC, with a warning. A date with its own offset (`XXX`, `Z`) or a `%d{...}{TZ}` option wins |
| `--pattern` | The application's pattern layout (repeat for several appenders). Replaces the built-in layouts |
| `--pattern-file` | Read the patterns from `log4j.properties`, `log4j2.xml`/`.properties`/`.yaml`/`.json` or `logback.xml` |
| `--date-order` | `ymd`, `dmy` or `mdy` for numeric dates such as `26-11-25` or `11/05/2026` (default: from the data, see below) |
| `--log-date` | Date of a time-only log (default: from the file name, else the file's modification time) |
| `--service` | `service.name` for every document (default: the file name without extension and rotation suffix) |
| `--host-os` | `host.os.type` (windows, linux, macos, unix) |
| `--max-message-chars` | Longest event kept (default 100000); longer ones are cut and tagged `message_truncated` |
| `--case`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--dry-run`, `--sample-docs`, `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file` | As every other importer |

`SOF-ELK_ImportWrapper.py` finds these logs on its own: every file that no other importer (or the
NCSA access log detector) claimed is checked with this importer's `detect()`, and the wrapper's
`--local-tz` is passed on. Files keep their folder layout, so `log.file.path` is the path under the
wrapper's input folder.

## Layouts

Without `--pattern`, the first 400 lines of each file decide which built-in layout fits best (most
header lines, then most fields). Every built-in layout uses a lenient date, so `yyyy-MM-dd`,
`yy-MM-dd`, `dd/MM/yyyy`, `dd-MMM-yyyy`, `dd MMM yyyy`, ISO 8601 with `T` and an offset, comma or
dot before the milliseconds, AM/PM, and time-only dates all work.

| Layout name (`javalog.layout`) | Pattern | Example header line |
|---|---|---|
| `log4j-logger-method-line` | `%d %-5p %c [%M :%L] %m` | `26-11-26 00:01:16.063 ERROR com.clt.server.mail.MailReceive [getMail :255] ...` |
| `log4j-logger-method-line-compact` | `%d %-5p %c [%M:%L] %m` | `2026-11-26 10:00:00,123 INFO  com.x.Svc [run:42] ...` |
| `spring-boot-3` | `%d %5p %pid --- [%applicationName] [%t] %-40.40c : %m` | `2026-11-26T10:57:51.112+08:00  INFO 45469 --- [demo] [main] c.e.Demo : Started` |
| `spring-boot` | `%d %5p %pid --- [%t] %-40.40c : %m` | `2026-11-26 10:57:51.112  INFO 45469 --- [main] o.s.b.w.e.t.TomcatWebServer : Tomcat started` |
| `logback-default` | `%d [%t] %-5p %c - %m` | `23:59:58.100 [main] INFO  com.example.App - Starting` (Logback and Log4j 2 defaults) |
| `log4j-thread-logger-line` | `%d [%t] %-5p %c:%L - %m` | |
| `log4j-level-thread-logger-line` | `%d %-5p [%t] %c:%L - %m` | `2026-11-26 10:00:00,123 ERROR [main] com.example.Dao:88 - query failed` |
| `log4j-level-thread-logger` | `%d %-5p [%t] %c - %m` | |
| `log4j-level-logger-line` | `%d %-5p %c:%L - %m` | `2026-11-26 10:00:00 INFO  Dao:88 - ...` (`%c{1}:%L`) |
| `log4j-level-logger` | `%d %-5p %c - %m` | |
| `log4j-level-bracket-logger-line` | `%d %-5p [%c:%L] %m` | |
| `wildfly` | `%d %-5p [%c] (%t) %m` | `2026-11-26 10:00:00,123 INFO  [org.jboss.as] (MSC service thread 1-2) WFLYSRV0049: ...` |
| `log4j-level-bracket-logger` | `%d %-5p [%c] %m` | |
| `jul-oneline` | `%d %p [%t] %c %m` | `26-Nov-2026 10:00:00.123 SEVERE [main] org.apache.catalina.core.StandardWrapperValve.invoke ...` (Tomcat `catalina.*.log`) |
| `bracket-date-thread-level-logger`, `bracket-date-level-logger` | `[%d] [%t] %-5p %c - %m`, `[%d] %-5p %c - %m` | |
| `level-first-thread-logger`, `level-first-logger-line` | `%-5p %d [%t] %c: %m`, `%-5p %d %c:%L - %m` | |
| `generic-*` | date and level only (`%d %-5p %m`, `%d [%-5p] %m`, `[%d] %-5p %m`, ...) | any other "date level message" header; the rest stays in `message` |

A file may mix layouts (for example a console and a file appender writing to the same file): the
best layout is tried first on every line, then every other built-in layout seen in the file, then
the generic ones. `javalog.layout` and `javalog.pattern` record which one read each event.

With `--pattern`/`--pattern-file`, only those patterns are used. The Log4j/Logback conversion words
understood are `%d`/`%date{format}{zone}` (SimpleDateFormat letters, named formats such as
`ISO8601`, `ABSOLUTE`, `DATE`, `COMPACT`, `UNIX_MILLIS`), `%p`/`%level`, `%c`/`%logger`, `%C`/`%class`,
`%M`/`%method`, `%L`/`%line`, `%F`/`%file`, `%l`/`%location`, `%t`/`%thread`, `%T`/`%tid`,
`%pid`/`${PID}`, `%X{key}`/`%mdc`, `%x`/`%NDC`, `%marker`, `%r`/`%relative`, `%sn`, `%cn`, `%m`/`%msg`,
`%n`, `%%`; format modifiers (`%-5p`, `%.30c`, `%-40.40logger{39}`); composite words (`%highlight(...)`,
`%clr(...){faint}`, `%replace(...)`, Log4j 2's `%highlight{...}`, `%style{...}`, `%enc{...}`); and
`${NAME:-default}` properties. Exception words (`%ex`, `%wEx`, `%throwable`, ...) print on the lines
after the header, so they are read as continuation lines. Words not listed match anything and are
not stored.

### Dates

- Two-digit numeric dates such as `26-11-26` fit both `yy-MM-dd` and `dd-MM-yy`. Every date seen in
  the first lines of a file is checked: an order that would give a month above 12 or a day above 31
  is ruled out. When more than one order is still possible, `-` means `yy-MM-dd`, `/` means
  `MM/dd`, and `.` means `dd.MM`, and the run prints a note. Use `--date-order` when that is wrong.
- Time-only layouts (Logback's default `HH:mm:ss.SSS`) take their date from `--log-date`, else from
  a date in the file name (`app.2026-11-26.log`), else from the file's modification time (minus the
  midnights the file crosses). A time that goes back more than an hour is the next day.
- An unreadable date on a header line keeps the event, with the previous event's time and the tag
  `timestamp_unparsed`.

## Fields

Mapping: `Java/index_templates/index-javalog.json` plus the toolkit's Linux common component
(`Linux/index_templates/component-toolkit-linux-common.json`). `dynamic: false`; ECS names where
ECS has one. See [`docs/schemas/javalog.md`](../docs/schemas/javalog.md) for types.

| Pattern / content | Field |
|---|---|
| `%d` | `@timestamp` (UTC), `javalog.timestamp_original` (as written), `event.timezone` |
| `%p` | `log.level` (upper case) |
| `%c` | `log.logger` |
| `%C` | `javalog.class` |
| `%M` | `log.origin.function` |
| `%F`, `%L` | `log.origin.file.name`, `log.origin.file.line` |
| `%l` | `javalog.location`, plus class, method, file and line taken from it |
| `%t`, `%T` | `process.thread.name`, `process.thread.id` |
| `%pid`, `${PID}` | `process.pid` |
| `%X{key}` | `javalog.mdc` (`key=value`, one per key); `traceId`/`spanId`/`user`/`username` also go to `trace.id`, `span.id`, `user.name` |
| `%x`, `%marker`, `%cn` | `javalog.ndc`, `javalog.marker`, `javalog.context` |
| `%r`, `%sn` | `javalog.relative_ms`, `javalog.sequence` |
| Spring Boot 3 `[app]` | `service.name` (otherwise the file name, e.g. `stwg-server`, or `--service`) |
| `%m` + continuation lines | `message` (the whole event), `javalog.first_line` (the header line's message), `javalog.line_count` |
| exception | `error.type` (first exception class), `error.message`, `error.stack_trace`, `javalog.exception.classes` (every class: `Caused by:`, `Suppressed:`, `nested exception is:`), `javalog.exception.root_cause` and `.root_cause_message` (the last one), `javalog.exception.top_frame` (first `at` frame), `javalog.exception.frame_count` |
| SQL statement | `javalog.sql.statement` (whitespace collapsed), `javalog.sql.verb` (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `WITH`, `CALL`, `CREATE`, `DROP`, `ALTER`, `TRUNCATE`, `GRANT`, `REVOKE`, ...), `javalog.sql.tables` (tables and procedures after `FROM`, `JOIN`, `INTO`, `UPDATE`, `DELETE`, `CALL`, upper case), `javalog.sql.object_id` (iBATIS `{conn-N}` / `{pstm-N}` / `{rset-N}`) |

Every document also has `host.name`, `event.kind` `event`, `event.dataset` `java.log`, `labels.type`
`javalog`, `log.file.path` (path under the folder given), `log.offset` (line number of the header
line, from 0), `service.name`, and `case` / `host.os.type` when given. `tags`: `multiline`
(continuation lines were merged), `exception`, `stack_trace`, `sql`, `orphan_lines` (lines before
the first header of a file, such as the end of a stack trace in a rotated file; loaded with the
first event's time), `message_truncated`, `timestamp_unparsed`.

SQL is recognised after an SQL marker on the header line (`Executing Statement:`, `Preparing Call:`,
`Preparing:`, `Hibernate:`, `SQL:`, `Query:`, ...) or, without one, when a line starts a statement
of a recognisable shape (`SELECT ... FROM`, `INSERT INTO`, `UPDATE x SET`, `DELETE FROM`, ...), so
messages such as "Update finished" are not taken for SQL. `javalog.sql.tables` is a best-effort
extraction for pivoting; the statement itself is always kept.

`message` and `javalog.sql.statement` are keywords up to 8191 characters with a `.text` sub-field
for full-text search. A longer event (a long stack trace or a large `INSERT ... VALUES`) is still
stored in full (and in `message.text` for Kibana full-text search), but ES|QL sees an empty `message`
for it; the exception and SQL fields are still filled in.

`_id` is built from the host, the log family (the file name without a rotation suffix), the event's
text and its occurrence number, so re-running, or loading a log again after rotation renamed it,
overwrites instead of duplicating, while an event the application wrote twice (for example a logger
attached to two appenders with additivity on) keeps both documents.

## ES|QL examples

```esql
// Exceptions per host, class and root cause
FROM javalog-* METADATA _index
| WHERE error.type IS NOT NULL
| STATS events = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp)
    BY _index, service.name, error.type, javalog.exception.root_cause
| SORT events DESC
| LIMIT 200
```

```esql
// Write and DDL statements, newest first
FROM javalog-* METADATA _index
| WHERE javalog.sql.verb IN ("INSERT", "UPDATE", "DELETE", "MERGE", "CREATE", "DROP", "ALTER", "TRUNCATE", "GRANT", "REVOKE")
| KEEP @timestamp, _index, service.name, log.file.path, javalog.sql.verb, javalog.sql.tables, javalog.sql.statement
| SORT @timestamp DESC
| LIMIT 500
```

```esql
// Log4Shell-style lookups and deserialization gadgets in messages or stack traces
FROM javalog-* METADATA _index
| WHERE message LIKE "*${jndi:*" OR message LIKE "*${${*"
    OR error.stack_trace LIKE "*InvokerTransformer*" OR error.stack_trace LIKE "*ysoserial*"
| KEEP @timestamp, _index, service.name, log.level, log.logger, javalog.first_line
| SORT @timestamp
| LIMIT 200
```

Standard library only (Python 3.9+). Tests: `python3 tests/test_javalog.py -v`.
