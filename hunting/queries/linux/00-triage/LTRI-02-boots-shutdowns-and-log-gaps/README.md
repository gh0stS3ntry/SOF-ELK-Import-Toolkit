# LTRI-02 Boots, shutdowns and crashes, with the log coverage of each boot

| | |
|---|---|
| Tactic | Triage (first cut) |
| ATT&CK | T1070.002 Clear Linux or Mac System Logs |
| Indexes | `logstash-*`, `wtmp-*` |
| Needs | journal or text syslog in logstash-*, wtmp-* |
| Applies to | every Linux host |

**What it finds.** A timeline of every boot: the journal's boots (first and last entry of each `_BOOT_ID`, and how many entries it holds), the boot, shutdown and crash records in `wtmp`, and kernel start lines in text syslog. A boot the journal does not have, a boot with far fewer entries than its neighbours, or a journal that starts long after the first `wtmp` boot shows where logs were rotated away, vacuumed or deleted.

**Reading the output.** Read it top to bottom per host. Each `journal boot` row should line up with a `wtmp boot` row a few seconds earlier and end at a `wtmp shutdown` (or a crash). Gaps to look at: a `wtmp boot` with no journal boot next to it (that boot's journal is gone), a journal boot whose `end` stops hours before the next `wtmp shutdown` (journald stopped or its files were removed), and `wtmp crash` rows (power loss, a kernel panic, or a hard reset after tampering). `kernel` is the kernel release `wtmp` recorded at boot: a change outside a package upgrade is worth checking with [LTRI-04](../LTRI-04-software-installed-and-removed/). The journal keeps a size budget, so old boots disappearing is normal; a missing boot in the middle is not.

**If it errors or looks empty.** `Unknown column [wtmp.logout_type]` or `[wtmp.host]`: no `wtmp-*` index exists (Alpine and some containers keep no wtmp); remove `wtmp-*` from `FROM` and replace those fields with `null`. No journal rows: the journal export was not loaded (see [LTRI-01](../LTRI-01-linux-data-coverage/)).

**Next.** [LDE-01](../../TA0112-defense-impairment/LDE-01-log-and-history-tampering/) for log and history tampering.
