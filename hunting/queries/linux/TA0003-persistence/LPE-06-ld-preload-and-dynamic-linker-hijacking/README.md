# LPE-06 LD_PRELOAD and dynamic linker hijacking: ld.so.preload, library paths, preloaded libraries in odd places

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1574.006 Dynamic Linker Hijacking |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* or bodyfile-*; logstash-*, auditd-* for commands and loader errors |
| Applies to | every Linux host |

**What it finds.** Everything that can make the dynamic loader inject a library into every program: `/etc/ld.so.preload` (its presence alone is rare and suspicious), the library paths in `/etc/ld.so.conf` and `ld.so.conf.d`, `LD_PRELOAD` or `LD_LIBRARY_PATH` in commands, shell startup files, systemd unit environments and sudoers (`env_preserved`), loader error messages about a preloaded object that cannot be found (a rootkit removed badly), and shared objects stored in temporary, hidden, `/etc`, web or root-home folders.

**Reading the output.** Score 5 is `/etc/ld.so.preload` existing or being parsed: read the library it names, check that library in the bodyfile (owner, times, hash) and whether a package owns it. Userland rootkits (Azazel, Jynx, libprocesshider and miners that hide themselves) work this way, and they hide their own files from tools on the live host, but not from a bodyfile made from a disk image. `ld.so.conf.d` entries added by software (`fakeroot`, Oracle, CUDA) are normal; a folder under `/tmp` or a home directory is not. `ts` is the event time for log rows, the inode-change time for bodyfile rows, and the source file's modification time for `linux.*` rows.

**If it errors or looks empty.** `Unknown column [linuxconfig.ld.entry]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [file.hash.sha1]`: no `bodyfile-*`; replace `file.hash.sha1` and `file.owner` with `null`.

**Next.** [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) for hidden files, [LPE-08](../LPE-08-kernel-modules-and-rootkit-signs/) for kernel rootkits.
