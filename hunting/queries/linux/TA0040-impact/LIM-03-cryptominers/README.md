# LIM-03 Cryptominers: miner binaries and configurations, mining pool connections in command lines, persistence and logs

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1496 Resource Hijacking |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*`, `packages-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, bodyfile-*, packages-* |
| Applies to | every Linux host; internet-facing servers and container hosts first |

**What it finds.** Coin miners and the botnets that install them (Kinsing, TeamTNT, WatchBog, Skidmap): miner names (`xmrig`, `xmr-stak`, `cpuminer`, `kdevtmpfsi`, `kinsing`), pool URLs (`stratum+tcp://`) and pool names, `--donate-level` and `--coin` options in command lines, journal messages, cron entries, units and startup files; miner binaries anywhere outside `/usr` and `config.json` files in hidden or temporary folders; and out-of-memory kills, which miners often cause.

**Reading the output.** Any score 4 row (a miner or pool in a command, a log line or persistence) is a confirmed infection: take its first time, then find how it got in ([LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) for exploited web apps, [LIA-01](../../TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) for SSH brute force, exposed Docker or Redis) and the persistence it set ([LPE-01](../../TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../../TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-04](../../TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) for planted keys). Miners often hide as `kworker`, `kthreaddi` or `.X11-unix/` binaries; [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) catches those names. A `config.json` in a hidden folder is a weak signal on its own (score 1).

**If it errors or looks empty.** `Unknown column [package.name]` cannot occur (packages are only in `FROM` for their command lines). `Unknown column [file.hash.sha1]`: no `bodyfile-*` index exists; replace `file.hash.sha1` and `file.owner` with `null`.

**Next.** [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) for masquerading process and file names.
