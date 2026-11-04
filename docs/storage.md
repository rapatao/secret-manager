# Storage and encryption

## Storage

Storage is pluggable behind a small interface (`internal/storage.Backend`), selected with `--storage`.

`kubernetes` (default): each path is a Secret in the server's namespace (`/kubernetes/app` is stored as `sm.kubernetes.app`, labeled `secretmanager.rapatao.com/store=true`). There is no database or volume to run. Each write that changes a path is also stored as a version, unless history is disabled: a Secret named `smh.<path>.<version>` (`/kubernetes/app` version 3 is `smh.kubernetes.app.3`), labeled `secretmanager.rapatao.com/history=true` and `secretmanager.rapatao.com/path-hash=<first 32 hex digits of the SHA-256 of the path>`, so the versions of one path are listed without reading the others. On start, the server adds the `path-hash` label to version Secrets written before it existed. See [History](history.md). Integration tokens are kept in the Secret `sm-tokens` and the newest audit events in `sm-audit`.

`file`: every path, version, integration and kept audit event is in one JSON file (`--file`, mode `0600`), loaded into memory at start and rewritten atomically on every write.

To add a backend (SQLite, Postgres, ...), implement `storage.Backend`, run `storagetest.Run` against it in its tests, and add a case to the `--storage` switch in `cmd/secret-manager/main.go`.

## Encryption

Set `SECRET_MANAGER_ENCRYPTION_KEY` to a base64 AES-256 key (`openssl rand -base64 32`) to encrypt every stored value, in paths and versions, with AES-256-GCM before it reaches the storage backend. Paths, key names and version times stay readable. In the chart, put the key in a Secret and set `encryption.existingSecret` (and `encryption.key`, default `key`):

```sh
kubectl -n secret-manager create secret generic secret-manager-encryption \
  --from-literal=key="$(openssl rand -base64 32)"
```

The API, the Web UI, `SecretSync` targets and backups still see plain values. On start, the server encrypts every path and version still holding a plaintext value. Values written with a key cannot be read without it: a server started without the key, or with another one, answers `500` for them and logs the path and key. Keep a copy of the key outside the cluster; losing it loses the data.

To rotate the key, set the new key in `SECRET_MANAGER_ENCRYPTION_KEY` and the old one in `SECRET_MANAGER_PREVIOUS_ENCRYPTION_KEY`, then restart the server. Reads accept values encrypted with either key. On start, the server rewrites every path and version encrypted with the previous key, or still plaintext, with the new key, and logs them as `encrypted stored values with the current key`. Values that neither key decrypts are left as they are and logged as `stored values not readable with the encryption keys`. Once the server has started with both keys and that warning is absent, remove the previous key. In the chart, add the old key to the same Secret and set `encryption.previousKey` to its key name:

```sh
kubectl -n secret-manager create secret generic secret-manager-encryption \
  --from-literal=key="$(openssl rand -base64 32)" \
  --from-literal=previous="$OLD_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -
helm upgrade secret-manager ... --set encryption.previousKey=previous
```
