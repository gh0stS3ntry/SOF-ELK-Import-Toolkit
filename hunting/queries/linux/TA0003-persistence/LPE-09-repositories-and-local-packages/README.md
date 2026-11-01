# LPE-09 Package repositories added or unsigned, and packages installed from local files rather than a repository

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1195.002 Compromise Software Supply Chain, T1072 Software Deployment Tools |
| Indexes | `linuxconfig-*`, `packages-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* (repositories) and packages-* |
| Applies to | every Linux host |

**What it finds.** Where the host's software comes from: every configured repository (apt `sources.list` and deb822 files, yum/dnf, zypper, apk) with its enabled, `gpgcheck` and `trusted=yes` settings; repository changes zypper logged; repository and signing-key files with their inode-change times; commands that add repositories or keys or install local package files (`dpkg -i`, `rpm -i`, `apt install ./x.deb`, `apk add --allow-untrusted`); and packages that dpkg installed but no apt transaction did (installed from a file, not a repository).

**Reading the output.** Repositories are always listed; the rest only when they score. Leads: a repository with `trusted=yes` or `gpgcheck=0` (`unsigned_repository`), a repository or key added inside the incident window, a package dpkg installed with no apt record (`from_dpkg` > 0 and `from_frontend` 0) that is not a known local install (kernel packages built in place, vendor `.deb` downloads such as Chrome or VS Code), and an `apt-key add` or `dpkg -i` run by an account that does not administer the host. dpkg logs and apt history rotate on different schedules, so very old packages can be dpkg-only for that reason alone. Set `since` first.

**If it errors or looks empty.** `Unknown column [linuxconfig.repository.urls]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [package.name]`: no `packages-*` index exists; remove it and the `package.*` fields.

**Next.** [LTRI-04](../../00-triage/LTRI-04-software-installed-and-removed/) for every install by hour.
