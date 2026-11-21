# LOLRMM snapshot

The indicators behind the generated RMM queries (Windows [C2-10 to C2-15](../../queries/windows/TA0011-command-and-control/), Linux [LC2-05](../../queries/linux/TA0011-command-and-control/LC2-05-lolrmm-rmm-tools-on-linux/) and [LC2-06](../../queries/linux/TA0011-command-and-control/LC2-06-lolrmm-rmm-domains-on-linux/)), taken from the [LOLRMM](https://lolrmm.io) catalog (Apache 2.0, by MagicSword and contributors).

| File | What it is |
|---|---|
| `source.json` | Where and when `rmm_tools.json` was fetched, its SHA-256, the number of tools and each tool's `LastModified` date. The next run compares against it to list tools added, removed and modified. |
| `indicators.json` | The hunting indicators extracted from it, by kind, each with the LOLRMM tools it belongs to. This is what the queries are rendered from, and what decides whether an update needs new queries. |

Indicator kinds: `win_exe` / `win_exe_glob` (program names), `win_path` (install folders and programs), `win_file` (logs, configuration and other files), `service` / `service_glob`, `task`, `registry`, `domain` (matched with subdomains) / `domain_glob`, `ip`, `sha256`, `sha1`, `linux_path`, `linux_exe`, `linux_unit`. Paths are lower case LIKE globs with single backslashes; registry keys have no hive and no `WOW6432Node`.

## Updating

```
python3 hunting/tools/lolrmm.py --check     # fetch and compare only: exit 10 if the indicators changed, 0 if not
python3 hunting/tools/lolrmm.py             # fetch, rewrite source.json, indicators.json and the eight query.esql files
python3 hunting/tools/check_queries.py
java -cp lucene-core-10.2.2.jar hunting/tools/LuceneRegexCheck.java hunting/queries
```

The script fetches `https://lolrmm.io/api/rmm_tools.json` and falls back to the same file in the LOLRMM GitHub repository (`website/public/api/rmm_tools.json` on `main`), which the site is built from; `--source FILE` reads a downloaded copy. A change to `rmm_tools.json` that does not change any hunting indicator (descriptions, references, certificates) gives exit 0 with `--check`: no query changes are needed. A scheduled task checks for updates on the 1st of every month and opens a pull request when the indicators change.

When an update changes the indicators, review the diff of `indicators.json` before merging: new generic names or shared domains that slipped through the safety rules belong in the lists at the top of `tools/lolrmm.py` (`GENERIC_EXE`, `GENERIC_DIRS`, `SHARED_DOMAINS`, ...). LOLRMM schema changes (new artifact types in `Artifacts.Other`, renamed keys) show up as indicator counts that drop; the script prints the counts per kind on every run.

## Safety rules

The generator follows LOLRMM's own [detection-generation policy](https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/docs/detection-generation.md):

- generic program names (`agent.exe`, `svchost.exe`, `installer.exe`, `setup.exe`, Windows binaries, names of three letters or fewer) are used only with their documented folder;
- extension-only and catch-all globs (`*.exe`, `C:\Program Files\*`) are dropped; a pattern needs at least one folder or file name that names a product;
- domains marked `Detection: false`, `user_managed` and `<placeholder>` entries, public suffixes and shared hosting roots (`amazonaws.com`, `github.com`, `blob.core.windows.net`, ...) are dropped; tenant names under them are kept;
- placeholders (`<version>`, `{SID}`, `%ProgramData%`) become wildcards.

Matches are leads, not verdicts: most of these tools are legitimate software.
