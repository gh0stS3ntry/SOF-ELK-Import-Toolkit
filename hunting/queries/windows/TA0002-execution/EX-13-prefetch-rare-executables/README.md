# EX-13 Prefetch: rare executables, low run counts and loads from user-writable paths

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1036 Masquerading |
| Indexes | `prefetch-*` |
| Needs | PECmd output. Prefetch is on by default on clients, off by default on servers |
| Roles | end-user workstation; servers only if Prefetch was enabled |

**What it finds.** Prefetch files whose executable loaded files from a user-writable or staging folder, matches a tool or LOLBin name, exists on only one host, or ran three times or fewer.

**Reading the output.** `kape.prefetch.last_run` and `prefetch.previous_runs` are the last eight run times (proof of execution). `first_run_approx` is the `.pf` file's creation time, usually about ten seconds after the first run. `dirs` lists the directories the program touched; the executable's own folder is among them, since Prefetch stores only the name. `kape.prefetch.hash` is the path hash, so two `.pf` files with the same name and different hashes ran from different folders.

**Tuning.** Remove LOLBins you expect (`rundll32`, `certutil`) from `f_tool` on admin-heavy servers.
