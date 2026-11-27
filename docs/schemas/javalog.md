# Java application log schema (`javalog-*`)

Loaded by `Java/javalog2sofelk.py` into `javalog-<hostname>`, one document per log event (header
line plus merged continuation lines: stack traces, multi-line SQL). Mapping:
`Linux/index_templates/component-toolkit-linux-common.json` plus
`Java/index_templates/index-javalog.json`, installed as index template `sofelk-toolkit-javalog`
(composed of `sofelk-toolkit-linux-common`). `dynamic: false`, so a field not listed here is not
searchable. Field sources and parsing rules are in [`Java/README.md`](../../Java/README.md).

Common fields: `@timestamp` (UTC), `case`, `host.name`, `host.os.type`, `event.kind` (`event`),
`event.dataset` (`java.log`), `event.timezone`, `labels.type` (`javalog`), `log.file.path` (path
under the folder given), `log.offset` (header line number, from 0), `tags`.

| Field | Type | Content |
|---|---|---|
| `message` | keyword (8191) + `.text` | the whole event, continuation lines included |
| `log.level` | keyword | `%p`, upper case (`DEBUG`, `ERROR`, `SEVERE`, ...) |
| `log.logger` | keyword | `%c` |
| `log.origin.function` | keyword | `%M` |
| `log.origin.file.name` / `.line` | keyword / long | `%F`, `%L` |
| `process.pid` | long | `%pid`, `${PID}` |
| `process.thread.name` / `.id` | keyword / long | `%t`, `%T` |
| `service.name` | keyword | Spring Boot 3 application name, `--service`, else the log file name without extension and rotation suffix |
| `error.type` | keyword | first exception class in the event |
| `error.message` | keyword (8191) + `.text` | that exception's message |
| `error.stack_trace` | text | from the first exception (or `at`) line to the end of the event |
| `trace.id`, `span.id`, `user.name` | keyword | from MDC keys `traceId`, `spanId`, `user`/`username`/`userId` |
| `javalog.layout` | keyword | built-in layout name, or `custom` / `custom-<n>` for `--pattern` |
| `javalog.pattern` | keyword | the pattern that read the event |
| `javalog.timestamp_original` | keyword | the date as written |
| `javalog.first_line` | keyword (8191) + `.text` | the header line's message only |
| `javalog.line_count` | integer | lines in the event |
| `javalog.class` | keyword | `%C` (or from `%l`) |
| `javalog.location` | keyword | `%l` |
| `javalog.ndc`, `javalog.marker`, `javalog.context` | keyword | `%x`, `%marker`, `%cn` |
| `javalog.mdc` | keyword | `%X{key}` values as `key=value` (or the whole `%X` text) |
| `javalog.relative_ms`, `javalog.sequence` | long | `%r`, `%sn` |
| `javalog.exception.classes` | keyword | every exception class, in order (`Caused by:`, `Suppressed:`, `nested exception is:`) |
| `javalog.exception.root_cause` / `.root_cause_message` | keyword / keyword + `.text` | the last one |
| `javalog.exception.top_frame` | keyword | first `at` frame |
| `javalog.exception.frame_count` | integer | `at` frames |
| `javalog.sql.statement` | keyword (8191) + `.text` | SQL statement, whitespace collapsed |
| `javalog.sql.verb` | keyword | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `WITH`, `CALL`, DDL/DCL verbs |
| `javalog.sql.tables` | keyword | tables and procedures named in the statement, upper case (best effort) |
| `javalog.sql.object_id` | keyword | iBATIS `{conn-N}`, `{pstm-N}`, `{stmt-N}`, `{rset-N}` |

Tags: `multiline`, `exception`, `stack_trace`, `sql`, `orphan_lines`, `message_truncated`,
`timestamp_unparsed`.
