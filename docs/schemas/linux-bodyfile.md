# Linux bodyfile schema (`bodyfile-*`)

Loaded by `Linux/bodyfile2sofelk.py` (`event.dataset` `bodyfile`) into `bodyfile-<hostname>`. Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-bodyfile.json` (index template `sofelk-toolkit-bodyfile`, `dynamic: false`). Common fields: see [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

Input is a bodyfile in the Sleuth Kit 3.x format, `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`, as written by UAC (`bodyfile/bodyfile.txt`), `fls -r -m /` and mac-robber. One document per line (file, directory, symlink, device, socket or FIFO).

| Field | Type | Source |
|---|---|---|
| `@timestamp` | date | `mtime` (else ctime, crtime, atime; entries with no time at all have no `@timestamp`) |
| `file.path` | keyword | name, without TSK's ` (deleted)` suffix and without ` -> target` for symlinks |
| `file.name` / `file.directory` / `file.extension` | keyword | from `file.path` (extension lower case, files only) |
| `file.target_path` | keyword | symlink target (the part after ` -> `) |
| `file.type` | keyword | `file`, `dir`, `symlink`, `char-device`, `block-device`, `fifo`, `socket` (first mode character; TSK's `r/r...` form is read too) |
| `file.mode` | keyword | octal permissions with setuid/setgid/sticky, e.g. `4755`, `1777` |
| `file.inode` | keyword | inode (TSK's `1234-128-1` form is kept as is) |
| `file.uid` / `file.gid` | keyword | numeric owner and group |
| `file.owner` / `file.group` | keyword | names from the collected `/etc/passwd` and `/etc/group` (at collection time) |
| `file.size` | long | size in bytes |
| `file.accessed` / `file.mtime` / `file.ctime` / `file.created` | date | atime, mtime, ctime (inode change), crtime (birth; left out when 0) |
| `file.hash.md5` / `sha1` / `sha256` | keyword | UAC `hash_executables/hash_executables.{md5,sha1,sha256}` joined on the path; also the bodyfile's own MD5 column when it is not 0 |
| `bodyfile.mode_string` | keyword | the mode column as written (`-rwsr-xr-x`, `r/rrw-r--r--`) |
| `bodyfile.setuid` / `setgid` / `sticky` | boolean | from the mode |
| `bodyfile.world_writable` | boolean | others may write (symlinks excluded) |
| `bodyfile.executable` | boolean | regular file with any execute bit |
| `bodyfile.hidden` | boolean | name starts with `.` |
| `bodyfile.deleted` | boolean | TSK marked the entry `(deleted)` |
| `bodyfile.regular_file_in_dev` | boolean | regular file under `/dev` (a hiding place: `/dev/shm`, `/dev/.udev`) |

`log.file.path` is the bodyfile read and `log.offset` its line number. The `_id` is derived from the host, the path, the inode and the deleted flag, so loading a later collection of the same host updates the entries in place.

## Reading the times

- **crtime** is only recorded by filesystems that keep a birth time (ext4, XFS v5, Btrfs). On ext3 and UFS1 it is always 0 and `file.created` is missing.
- **atime** is usually `relatime`: updated at most once a day, or when older than mtime/ctime. The collector itself reads files, so atime close to the collection time means little.
- **mtime and ctime** can be set by an attacker (`touch -d` changes atime/mtime; ctime changes only with the system clock). A ctime later than mtime on a binary is worth a look.
- **Deleted files** only appear in a TSK bodyfile made from an image (`fls -r -m /`, flagged `bodyfile.deleted`); UAC walks the live file system and lists only what exists.
- The `system/*.txt` lists UAC writes (suid, sgid, hidden, world-writable) are covered by the flags above.

## ES|QL examples

```esql
FROM bodyfile-* METADATA _index
| WHERE bodyfile.setuid == true AND NOT file.directory IN ("/usr/bin", "/usr/sbin", "/usr/lib/openssh", "/usr/lib/dbus-1.0")
| KEEP _index, file.path, file.owner, file.mode, file.mtime, file.ctime, file.hash.sha1
```

```esql
FROM bodyfile-* METADATA _index
| WHERE bodyfile.executable == true AND (STARTS_WITH(file.path, "/tmp/") OR STARTS_WITH(file.path, "/dev/shm/") OR STARTS_WITH(file.path, "/var/tmp/"))
| KEEP _index, file.path, file.owner, file.size, file.mtime, file.ctime, file.hash.md5, file.hash.sha1
| SORT file.mtime DESC
```
