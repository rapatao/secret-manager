# Backup

`secret-manager backup` prints every path and its data as JSON; `--output F` writes it to `F` with `0600` permissions instead. `--history` adds the versions of each path. Versions of deleted paths are not included.

`secret-manager restore F` (`-` for stdin) replaces the data of every path in the file. Paths not in the file are kept. Each changed path is recorded as a new version and its targets are synced, like any other write. Versions in the file are restored only for paths that have none yet, renumbered from 1 and limited to `--history-limit`; a path that already has versions only gets a new one for the restored data. Restoring the same file twice changes nothing. Every path and key is checked before anything is written.

Without a key, the file holds every value in plain text. With `SECRET_MANAGER_BACKUP_KEY` set to a base64 AES-256 key (`openssl rand -base64 32`), `backup` encrypts the document with AES-256-GCM into `{"encryption": "aes-256-gcm", "data": "<base64>"}`. `restore` decrypts such a file with the same variable, and fails with `is encrypted; set SECRET_MANAGER_BACKUP_KEY` without it, or `cannot decrypt backup, wrong backup key?` with another key. Keep the backup key apart from the backups, and apart from the [encryption](storage.md#encryption) key. To move to a new server, or to keep a copy before an upgrade, back up from the old server and restore on the new one; any client version with `backup` can talk to both, see [Compatibility](api.md#compatibility).

## Scheduled backups

With `--backup-dir DIR`, the server writes a backup to `DIR/backup-<UTC time>.json` (`0600`) every `--backup-interval` (default `24h`) and keeps the newest `--backup-keep` files (default `7`). `--backup-history` adds versions. The first backup is written one interval after the server starts. Each run is logged as an audit entry with `source` `schedule` and `op` `backup` (category [`backups`](observability.md#event-categories)); a failed run is logged at `WARN` and tried again on the next interval.

With `SECRET_MANAGER_BACKUP_KEY` set on the server, every scheduled backup is encrypted like `secret-manager backup` does with that variable, and the summary page shows the schedule as encrypted. Restore one with `secret-manager restore` and the same key.

In the chart, set `backup.enabled=true` (`backup.interval`, `backup.keep`, `backup.history`). To encrypt the files, create a Secret holding the key and set `backup.encryption.existingSecret` (and `backup.encryption.key`, default `key`). Backups go to a `ReadWriteOnce` PersistentVolumeClaim named `<release>-backups` (`backup.persistence.size`, default `1Gi`, and `backup.persistence.storageClass`), or to `backup.persistence.existingClaim`. Helm keeps the claim when the release is uninstalled. The image has no shell, so to copy a file out, mount the claim in another pod. Without a backup key, the same plain-text warning applies to these files.
