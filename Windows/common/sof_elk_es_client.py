#!/usr/bin/env python3
"""Shared standard-library Elasticsearch client for the SOF-ELK importers.

Every importer sends its HTTP traffic through EsClient so that all of them get the
same behaviour:

* Whole-request retry with exponential backoff and jitter on connection errors,
  timeouts and HTTP 429/500/502/503/504 (Retry-After is honoured when sent).
* Per-item retry for _bulk: items rejected with 429/502/503/504 (for example
  es_rejected_execution_exception when the write queue is full) are re-sent on
  their own, and their final results are merged back into the original order.
* Optional log file (--log-file) recording the command line, every retry, every
  bulk request summary and every item-level error.
* One index per evidence host, named <prefix>-<hostname> (see resolve_index).

Retrying a _bulk request is safe because every importer sends "index" actions with a
deterministic _id: a replayed document overwrites itself instead of duplicating.
"""
from __future__ import annotations

import base64
import json
import logging
import random
import re
import socket
import ssl
import sys
import threading
import time
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from urllib import error, request

LOGGER_NAME = "sof_elk"
log = logging.getLogger(LOGGER_NAME)

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
RETRY_ITEM_STATUSES = frozenset({429, 502, 503, 504})

DEFAULTS = {"max_retries": 5, "backoff": 2.0, "max_backoff": 60.0, "timeout": 300}
_defaults_lock = threading.Lock()


class EsUnavailable(error.URLError):
    """Elasticsearch could not be reached after all retries.

    Subclasses URLError (and therefore OSError) so existing `except URLError` handlers
    in the importers keep working.
    """

    def __str__(self):
        return str(self.reason)


def configure(max_retries=None, backoff=None, max_backoff=None, timeout=None):
    """Set process-wide defaults used by every EsClient created afterwards."""
    with _defaults_lock:
        if max_retries is not None:
            if max_retries < 0:
                raise ValueError("--max-retries must be zero or a positive integer")
            DEFAULTS["max_retries"] = int(max_retries)
        if backoff is not None:
            if backoff <= 0:
                raise ValueError("--retry-backoff must be a positive number of seconds")
            DEFAULTS["backoff"] = float(backoff)
        if max_backoff is not None:
            DEFAULTS["max_backoff"] = float(max_backoff)
        if timeout is not None:
            if timeout <= 0:
                raise ValueError("--timeout must be a positive number of seconds")
            DEFAULTS["timeout"] = float(timeout)


class _ConsoleFilter(logging.Filter):
    """Keep per-item detail (extra={'file_only': True}) out of the console."""

    def filter(self, record):
        return not getattr(record, "file_only", False)


def setup_logging(log_file=None):
    """Retries and failures go to stderr; with log_file, everything is appended there too."""
    log.setLevel(logging.DEBUG)
    log.propagate = False
    for handler in list(log.handlers):
        log.removeHandler(handler)
        handler.close()
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.WARNING)
    console.addFilter(_ConsoleFilter())
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(console)
    if log_file:
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(script)s] %(message)s"))
        script = re.sub(r"\.py$", "", sys.argv[0].replace("\\", "/").rsplit("/", 1)[-1]) or "python"
        handler.addFilter(_ScriptName(script))
        log.addHandler(handler)
        log.info("command: %s", " ".join(mask_argv(sys.argv)))


class _ScriptName(logging.Filter):
    def __init__(self, script):
        super().__init__()
        self.script = script

    def filter(self, record):
        record.script = self.script
        return True


def mask_argv(argv):
    """Copy of argv with the --password value replaced, for logging."""
    out, hide_next = [], False
    for arg in argv:
        if hide_next:
            out.append("****")
            hide_next = False
        elif arg == "--password":
            out.append(arg)
            hide_next = True
        elif arg.startswith("--password="):
            out.append("--password=****")
        else:
            out.append(arg)
    return out


def add_client_arguments(parser):
    """CLI options shared by every importer for retry behaviour and logging."""
    parser.add_argument("--max-retries", type=int, default=DEFAULTS["max_retries"],
                        help="Retries for a failed Elasticsearch request or rejected bulk item "
                             "(timeouts, connection errors, HTTP 429/5xx); 0 disables retrying")
    parser.add_argument("--retry-backoff", type=float, default=DEFAULTS["backoff"],
                        help="Base delay in seconds for exponential backoff between retries")
    parser.add_argument("--timeout", type=float, default=DEFAULTS["timeout"],
                        help="Seconds to wait for each Elasticsearch HTTP response")
    parser.add_argument("--log-file", help="Append retries, bulk results and item errors to this file")


def apply_client_arguments(args):
    """Apply add_client_arguments() options; exits with a message on invalid values."""
    try:
        configure(max_retries=args.max_retries, backoff=args.retry_backoff, timeout=args.timeout)
        setup_logging(args.log_file)
    except (ValueError, OSError) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc


INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def resolve_index(prefix, hostname, override=None):
    """Target index: <prefix>-<hostname>.

    An --index override may change the prefix, but must still end in -<hostname> so
    that each evidence host keeps its own index.
    """
    default = f"{prefix}-{hostname}"
    if not override:
        return default
    index = override.strip().lower()
    suffix = f"-{hostname}"
    if not index.endswith(suffix) or len(index) == len(suffix) or not INDEX_RE.match(index):
        raise SystemExit(
            f"ERROR: --index '{override}' must be named <prefix>-{hostname} (one index per "
            f"evidence host), for example '{default}'.")
    if index != override:
        print(f"note: Elasticsearch index names must be lower-case, using '{index}'")
    return index


def _retry_after(headers):
    value = headers.get("Retry-After") if headers else None
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


def _decode(content):
    try:
        return json.loads(content) if content else {}
    except ValueError:
        return {"raw": content.decode("utf-8", "replace")}


def _short(payload, limit=300):
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + "..."


class EsClient:
    """Thread-safe urllib client; safe to share between bulk worker threads."""

    def __init__(self, url, user=None, password=None, insecure=False, timeout=None,
                 max_retries=None, backoff=None, max_backoff=None):
        self.url = url.rstrip("/")
        self.headers = {}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
            self.headers["Authorization"] = f"Basic {token}"
        self.ssl_context = ssl._create_unverified_context() if insecure else None
        self.timeout = DEFAULTS["timeout"] if timeout is None else timeout
        self.max_retries = DEFAULTS["max_retries"] if max_retries is None else max_retries
        self.backoff = DEFAULTS["backoff"] if backoff is None else backoff
        self.max_backoff = DEFAULTS["max_backoff"] if max_backoff is None else max_backoff

    def delay(self, attempt, retry_after=None):
        """Full-jitter exponential backoff, at least Retry-After when the server sent one."""
        wait = random.uniform(0, min(self.max_backoff, self.backoff * (2 ** attempt)))
        if retry_after is not None:
            wait = max(wait, min(retry_after, self.max_backoff))
        return wait

    def _send_once(self, method, path, data, content_type):
        headers = {**self.headers, "Content-Type": content_type}
        req = request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                return response.status, response.read(), response.headers
        except error.HTTPError as exc:
            try:
                content = exc.read()
            except (OSError, HTTPException):
                content = b""
            return exc.code, content, exc.headers

    def request(self, method, path, body=None, content_type="application/json", retry=True):
        """Send one request; returns (status, decoded JSON payload).

        body may be bytes, str, or a JSON-serialisable object. Transport failures and
        HTTP 429/5xx are retried; once retries are exhausted a 429/5xx status is returned
        to the caller, and a transport failure raises EsUnavailable.
        """
        if body is None or isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        attempts = 1 + (self.max_retries if retry else 0)
        for attempt in range(attempts):
            last = attempt == attempts - 1
            try:
                status, content, headers = self._send_once(method, path, data, content_type)
            except (error.URLError, socket.timeout, TimeoutError, ConnectionError, HTTPException) as exc:
                reason = getattr(exc, "reason", None) or exc.__class__.__name__ + (f": {exc}" if str(exc) else "")
                if last:
                    log.error("%s %s failed after %d attempt(s): %s", method, path, attempt + 1, reason)
                    raise EsUnavailable(reason) from exc
                wait = self.delay(attempt)
                log.warning("%s %s failed (%s); retry %d/%d in %.1fs",
                            method, path, reason, attempt + 1, self.max_retries, wait)
                time.sleep(wait)
                continue
            payload = _decode(content)
            if status in RETRY_STATUSES and not last:
                wait = self.delay(attempt, _retry_after(headers))
                log.warning("%s %s returned HTTP %d (%s); retry %d/%d in %.1fs",
                            method, path, status, _short(payload, 200), attempt + 1, self.max_retries, wait)
                time.sleep(wait)
                continue
            if status in RETRY_STATUSES:
                log.error("%s %s still returned HTTP %d after %d attempt(s): %s",
                          method, path, status, attempt + 1, _short(payload))
            return status, payload
        raise AssertionError("unreachable")

    def bulk(self, lines):
        """POST NDJSON action/source lines to /_bulk with per-item retry.

        lines is a list of already-serialised NDJSON strings (an action line followed by
        its source line, except for delete actions). Returns (status, payload) like
        request(); on success payload["items"] holds one final result per action, in the
        original order, after rejected items were retried.
        """
        actions = []
        i = 0
        while i < len(lines):
            action_line = lines[i]
            op = next(iter(json.loads(action_line)), "index")
            if op == "delete":
                actions.append((action_line,))
                i += 1
            else:
                actions.append((action_line, lines[i + 1]))
                i += 2
        if not actions:
            return 200, {"errors": False, "items": []}

        results = [None] * len(actions)
        todo = list(range(len(actions)))
        took = 0
        for attempt in range(self.max_retries + 1):
            body = "\n".join(line for idx in todo for line in actions[idx]) + "\n"
            status, payload = self.request("POST", "/_bulk", body, "application/x-ndjson")
            items = payload.get("items") if isinstance(payload, dict) else None
            if status >= 300 or not isinstance(items, list) or len(items) != len(todo):
                if attempt == 0:
                    log.error("bulk request of %d action(s) failed: HTTP %d: %s", len(todo), status, _short(payload))
                    return status, payload
                # Only previously rejected items were in flight; keep their last rejection.
                log.error("bulk retry of %d rejected item(s) failed: HTTP %d: %s; keeping them as errors",
                          len(todo), status, _short(payload))
                break
            took += payload.get("took", 0) or 0
            retry = []
            for idx, item in zip(todo, items):
                results[idx] = item
                result = next(iter(item.values()), {}) if isinstance(item, dict) else {}
                if result.get("status") in RETRY_ITEM_STATUSES and "error" in result:
                    retry.append(idx)
            ok = len(todo) - sum(1 for idx in todo if "error" in next(iter(results[idx].values()), {}))
            log.info("bulk %s: %d action(s), %d ok, %d rejected-retryable",
                     "request" if attempt == 0 else f"retry {attempt}", len(todo), ok, len(retry))
            if not retry:
                break
            if attempt == self.max_retries:
                log.error("%d bulk item(s) still rejected after %d retries", len(retry), self.max_retries)
                break
            wait = self.delay(attempt)
            log.warning("%d of %d bulk item(s) rejected (e.g. HTTP %s %s); retrying them in %.1fs (%d/%d)",
                        len(retry), len(todo),
                        next(iter(results[retry[0]].values())).get("status"),
                        _item_reason(results[retry[0]]), wait, attempt + 1, self.max_retries)
            time.sleep(wait)
            todo = retry

        errors = False
        for item in results:
            result = next(iter(item.values()), {})
            if "error" in result:
                errors = True
                log.warning("item error: _id=%s status=%s %s", result.get("_id"), result.get("status"),
                            _item_reason(item), extra={"file_only": True})
        return 200, {"took": took, "errors": errors, "items": results}


def _item_reason(item):
    result = next(iter(item.values()), {})
    err = result.get("error")
    if isinstance(err, dict):
        return f"{err.get('type', 'error')}: {err.get('reason', '')}"
    return str(err)
