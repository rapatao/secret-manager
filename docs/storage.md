# Storage and encryption

## Storage

Storage is pluggable behind a small interface (`internal/storage.Backend`), selected with `--storage`.

`kubernetes` (default): each path is a Secret in the server's namespace (`/kubernetes/app` is stored as `sm.kubernetes.app`, labeled `secretmanager.rapatao.com/store=true`). There is no database or volume to run. Each write that changes a path is also stored as a version, unless history is disabled: a Secret named `smh.<path>.<version>` (`/kubernetes/app` version 3 is `smh.kubernetes.app.3`), labeled `secretmanager.rapatao.com/history=true` and `secretmanager.rapatao.com/path-hash=<first 32 hex digits of the SHA-256 of the path>`, so the versions of one path are listed without reading the others. On start, the server adds the `path-hash` label to every version Secret that lacks it. See [History](history.md). Integration tokens are kept in the Secret `sm-tokens`, the newest audit events in `sm-audit`, and the [SecretSync policy](secretsync.md#sync-policy) in `sm-sync-policy`.

`file`: every path, version, integration, kept audit event and the SecretSync policy is in one JSON file (`--file`, mode `0600`), loaded into memory at start and rewritten atomically on every write. The file or its directory can be a symlink: when the link points to an existing file, writes replace that file and keep the link. A dangling link is replaced by a regular file.

`postgres`: paths, versions, integrations, kept audit events and the SecretSync policy are rows in the tables `sm_paths`, `sm_versions`, `sm_tokens`, `sm_audit` and `sm_sync_policy`, created on start when missing. Values are stored as `jsonb`, encrypted when an [encryption](#encryption) key is set. The connection URL is read from `SECRET_MANAGER_DATABASE_URL`, for example `postgres://secret-manager:PASSWORD@db.example.com:5432/secrets?sslmode=verify-full`; when it is unset, the standard `PG*` environment variables (`PGHOST`, `PGUSER`, `PGPASSWORD`, ...) are used. To keep the tables apart from other data in a shared database, add `search_path=SCHEMA` to the URL. The database user needs to create tables on the first start, then to read and write them. Back up the database with its own tools (`pg_dump`), or with [secret-manager backups](backup.md). The server still runs as a single replica.

The SecretSync policy is left out of [backups](backup.md).

To add a backend, implement `storage.Backend`, run `storagetest.Run` against it in its tests, and add a case to the `--storage` switch in `cmd/secret-manager/main.go`.

## Version retention

Adding a version keeps the newest `keep` versions of the path by rank and removes the rest. Version numbers can have gaps after versions were deleted, so the kept versions are the newest ones that exist, not the ones within `keep` numbers of the new version. `keep` must be at least 1: every backend returns an error for a lower value and writes nothing.

## Keys and values

Keys match `[-._a-zA-Z0-9]+` and cannot be `.` or `..`. Values cannot start with `enc:v1:`, the prefix of encrypted stored values, whether or not an encryption key is set. The API answers `400` for either, and a backup restore with such a key or value writes nothing.

A stored value that starts with that prefix behaves according to how it was written:

- Written while no encryption key was set, it is kept as plaintext and cannot be read. Without a key, reads fail with `stored value is encrypted but no encryption key is set`. With a key, reads and updates of the path fail with `malformed encrypted value` or `decrypt failed, wrong encryption key?`, and the path is listed in the startup warning `stored values not readable with the encryption keys`.
- Written with an encryption key set, it is stored encrypted and reads back normally. Backup exports it as plaintext, so a restore of that backup is rejected as a whole. In the Web UI, other keys of the path can still be edited, but saving a changed value that starts with the prefix fails and nothing is saved.

Deleting the path and writing it again replaces the current data, but the stored versions of the path keep the old value. See [Unreadable versions](#unreadable-versions).

## Encryption

Set `SECRET_MANAGER_ENCRYPTION_KEY` to a base64 AES-256 key (`openssl rand -base64 32`) to encrypt every stored value, in paths and versions, with AES-256-GCM before it reaches the storage backend. Paths, key names and version times stay readable. In the chart, put the key in a Secret and set `encryption.existingSecret` (and `encryption.key`, default `key`):

```sh
kubectl -n secret-manager create secret generic secret-manager-encryption \
  --from-literal=key="$(openssl rand -base64 32)"
```

The API, the Web UI, `SecretSync` targets and backups still see plain values. On start, the server encrypts every path and version still holding a plaintext value. Values written with a key cannot be read without it: a server started without the key, or with another one, answers `500` for them and logs the path and key. Keep a copy of the key apart from the stored data; losing it loses the data.

To rotate the key, set the new key in `SECRET_MANAGER_ENCRYPTION_KEY` and the old one in `SECRET_MANAGER_PREVIOUS_ENCRYPTION_KEY`, then restart the server. Reads accept values encrypted with either key. On start, the server rewrites every path and version encrypted with the previous key, or still plaintext, with the new key, and logs them as `encrypted stored values with the current key`. Values that neither key decrypts are left as they are and logged as `stored values not readable with the encryption keys`. Both logs list a path as `/path` and a version as `/path version N`. Once the server has started with both keys and that warning is absent, remove the previous key. In the chart, add the old key to the same Secret and set `encryption.previousKey` to its key name:

```sh
kubectl -n secret-manager create secret generic secret-manager-encryption \
  --from-literal=key="$(openssl rand -base64 32)" \
  --from-literal=previous="$OLD_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
helm upgrade secret-manager ... --set encryption.previousKey=previous
```

## Unreadable versions

A version is flagged unreadable when one of its values cannot be opened with the configured keys: `SECRET_MANAGER_ENCRYPTION_KEY`, and `SECRET_MANAGER_PREVIOUS_ENCRYPTION_KEY` when set. The history lists it with `"unreadable": true` and without keys or values. It cannot be viewed, compared or rolled back to (`400`), and copying or moving the path fails with `400` until that version is deleted. Backups with history leave it out and log a warning naming the path and version. Other versions stay usable. Deleting versions works, and leaves the stored value of every other unreadable version byte for byte as it was, since an old key may still open it. With history enabled, the version is removed once newer versions push it past the keep limit. With history disabled, no version is added or removed, so it stays.

A wrong or rotated-away key flags every version sealed under another key, and a server started without a key flags every encrypted version. Deleting such versions, or letting the keep limit trim them, removes ciphertext that the old key could still open. Restore the right key before deleting versions.

## Secrets the server refuses

The `kubernetes` storage trusts only Secrets that carry the label of their kind: `store` for a path, `history` for a version, `tokens`, `audit` and `sync-policy` (all `secretmanager.rapatao.com/<name>=true`). A Secret that also carries the label `secretmanager.rapatao.com/owner` was written by a [SecretSync](secretsync.md), so a user who can create SecretSyncs controls its content, and the server never reads or overwrites it. Nothing is cleaned up automatically.

List the Secrets written by SecretSyncs, and read the `secretmanager.rapatao.com/owner` annotation of one to see which SecretSync wrote it. Fix or delete that SecretSync first, or the controller writes the Secret again:

```sh
kubectl -n <ns> get secret -l secretmanager.rapatao.com/owner
kubectl -n <ns> get secret <name> -o jsonpath='{.metadata.annotations}'
```

What happens, and how to recover, per Secret. A Secret of unknown origin, such as one detached from a SecretSync, which loses its owner label, must be deleted, never relabelled. A SecretSync itself deletes, instead of detaching, an `Orphan` target in this namespace named like one of the server's Secrets:

| Secret | Effect | Recovery |
|--------|--------|----------|
| `sm-tokens` | Reading or writing the integrations fails with an error naming the Secret | Delete it and create the integrations again. Only if you wrote or verified its content and it merely lost its label, restore it: `kubectl -n <ns> label secret sm-tokens secretmanager.rapatao.com/tokens=true` |
| `sm-audit` | The server does not start. If the Secret appears while the server runs, every audit flush fails until it is removed | Delete it, or, only if you wrote or verified its content, restore its label with `secretmanager.rapatao.com/audit=true`; a running server needs no restart |
| `sm-sync-policy` | The policy is loaded on first use and only a successful load is kept in memory. Before that load, every read fails: the policy API and the reconcile of every SecretSync. After it, reads keep using the loaded policy and only saving the policy fails. Restore its label with `secretmanager.rapatao.com/sync-policy=true` only if you wrote or verified its content; no restart is needed. Otherwise delete it and run `secret-manager sync-policy set --file policy.json` to write the policy again. A missing Secret reads as an empty policy, which is disabled: a server started without it runs every SecretSync unrestricted, while a running server keeps the policy it loaded, so write the policy again before restarting |
| `sm.*` (a path) | Ignored: reads return `404`, the path is not listed, writes fail with `not managed` | Delete it, then write the path again or restore it from a [backup](backup.md) |
| `smh.*` (a version) | Ignored: not part of the history | `kubectl -n <ns> delete secret -l secretmanager.rapatao.com/history=true,secretmanager.rapatao.com/owner` |
