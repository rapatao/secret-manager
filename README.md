# secret-manager

A small, self-hosted key-value secret manager for Kubernetes.

- Secrets are organized by path (`/kubernetes/app`, `/tools`) and managed with a CLI or a Web UI.
- A `SecretSync` resource syncs one or more paths into Kubernetes Secrets, in any namespace, optionally shaped with Go templates.
- Deployments, StatefulSets and DaemonSets that opt in are restarted when a Secret they use changes.
- `secret-manager run` injects secrets as environment variables into local commands, and keeps working from an encrypted cache while the server is unreachable.
- Every write is kept as a version, so a path can be inspected or rolled back, even after it is deleted.
- `secret-manager backup` and `restore` copy every path, optionally with its versions, to and from a JSON file.

One binary contains the controller, the REST API, the Web UI and the CLI. The controller is optional, and with the `file` storage backend the server runs without Kubernetes.

## Compared to other tools

| | secret-manager | [External Secrets Operator](https://external-secrets.io) | [Infisical](https://infisical.com) | [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) |
|---|---|---|---|---|
| Stores secrets | Yes, as Kubernetes Secrets | No, reads an external store (Vault, cloud providers, ...) | Yes, in PostgreSQL | Encrypted in git |
| Extra components | None | The external store | PostgreSQL and Redis | None |
| Web UI and CLI | Yes | No | Yes | CLI to encrypt (`kubeseal`) |
| Users, roles, environments | No, one admin token for the Web UI plus integration tokens scoped to a path | From the external store | Yes | Git permissions |
| Secret history | Yes, last N versions per path | From the external store | Yes | Git history |
| Restarts workloads on change | Yes | No, needs a tool like Reloader | Yes | No |

Choose secret-manager for a small cluster where one person or a small team manages the secrets and running a database for them is not worth it. Choose External Secrets Operator if you already have a secret store, Infisical if you need users and environments, and Sealed Secrets if secrets must live in git.

## How it works

```
CLI / Web UI --HTTP--> secret-manager server --> storage backend (Kubernetes Secrets)
                              |
                              +--> controller --> target Secrets --> workload restarts
```

Writes made through the API reach target Secrets immediately. Every `SecretSync` also resyncs on its `refreshInterval`, which repairs drift and picks up changes made directly on the store.

### Storage

Storage is pluggable behind a small interface (`internal/storage.Backend`), selected with `--storage`.

`kubernetes` (default): each path is a Secret in the server's namespace (`/kubernetes/app` is stored as `sm.kubernetes.app`, labeled `secretmanager.rapatao.com/store=true`). There is no database or volume to run. Each write that changes a path is also stored as a version, unless history is disabled: a Secret named `smh.<path>.<version>` (`/kubernetes/app` version 3 is `smh.kubernetes.app.3`), labeled `secretmanager.rapatao.com/history=true`. See [History](#history).

`file`: every path and version is kept in one JSON file (`--file`, mode `0600`), loaded into memory at start and rewritten atomically on every write.

### Encryption

Set `SECRET_MANAGER_ENCRYPTION_KEY` to a base64 AES-256 key (`openssl rand -base64 32`) to encrypt every stored value, in paths and versions, with AES-256-GCM before it reaches the storage backend. Paths, key names and version times stay readable. In the chart, put the key in a Secret and set `encryption.existingSecret` (and `encryption.key`, default `key`):

```sh
kubectl -n secret-manager create secret generic secret-manager-encryption \
  --from-literal=key="$(openssl rand -base64 32)"
```

The API, the Web UI, `SecretSync` targets and backups still see plain values. On start, the server encrypts every path still holding a plaintext value. Versions written before the key was set stay plaintext until they are pruned by newer ones. Values written with a key cannot be read without it: a server started without the key, or with another one, answers `500` for them and logs the path and key. Keep a copy of the key outside the cluster; losing it loses the data. Changing the key is not supported: to move to a new key, `backup`, start the server with the new key on an empty store, then `restore`.

To add a backend (SQLite, Postgres, ...), implement `storage.Backend`, run `storagetest.Run` against it in its tests, and add a case to the `--storage` switch in `cmd/secret-manager/main.go`.

## Install

Create the admin token (at least 32 characters) that signs in to the Web UI, then install the chart:

```sh
kubectl create namespace secret-manager
kubectl -n secret-manager create secret generic secret-manager-token \
  --from-literal=token="$(openssl rand -base64 36)"

helm install secret-manager oci://ghcr.io/rapatao/charts/secret-manager -n secret-manager \
  --set auth.existingSecret=secret-manager-token \
  --set ingress.enabled=true --set ingress.host=secrets.example.com
```

Add `--version 1.2.0` to pin a release. Set `historyLimit` (default `10`, `0` disables history) to change how many versions are kept per path. From a checkout, use `charts/secret-manager` instead of the `oci://` reference.

The chart installs the `SecretSync` CRD. Helm does not upgrade CRDs, so apply them after upgrading:

```sh
helm pull oci://ghcr.io/rapatao/charts/secret-manager --untar --untardir /tmp/sm
kubectl apply -f /tmp/sm/secret-manager/crds
```

The server runs as a single replica: writes are serialized in process.

Set `controller.enabled=false` to only store secrets: the `SecretSync` controller does not run, no Secret outside the release namespace is written, no workload is restarted, and the chart installs a Role limited to Secrets in the release namespace instead of a ClusterRole. Add `--skip-crds` to `helm install` to leave out the `SecretSync` CRD.

### Without Kubernetes

```sh
export SECRET_MANAGER_TOKEN="$(openssl rand -base64 36)"
secret-manager server --storage=file --file=/var/lib/secret-manager/store.json --controller=false
```

The CLI, Web UI, history and backups work the same; `SecretSync` is not available.

### Server flags

The chart sets these; set them yourself when running `secret-manager server` outside it.

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | Listen address of the API and Web UI |
| `--metrics-addr` | `:8081` | Listen address of the Prometheus metrics, `0` disables them |
| `--storage` | `kubernetes` | Storage backend: `kubernetes` or `file` |
| `--namespace` | `$POD_NAMESPACE` | Namespace holding the stored secrets and their versions (`kubernetes` storage) |
| `--file` | `secret-manager.json` | File holding the stored secrets and their versions (`file` storage) |
| `--controller` | `true` | Run the `SecretSync` controller. Requires access to a cluster |
| `--history-limit` | `10` | Versions kept per path, current included, `0` disables history |
| `--last-used-flush` | `30m` | Time between saves of the last use of every [integration](#integrations), also saved on shutdown |
| `--backup-dir` | | Directory receiving [scheduled backups](#scheduled-backups), empty disables them |
| `--backup-interval` | `24h` | Time between scheduled backups |
| `--backup-keep` | `7` | Scheduled backup files kept |
| `--backup-history` | `false` | Include versions in scheduled backups |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |

The Web UI admin token is read from `SECRET_MANAGER_TOKEN`, the optional [encryption](#encryption) key from `SECRET_MANAGER_ENCRYPTION_KEY`.

## SecretSync

```yaml
apiVersion: secretmanager.rapatao.com/v1alpha1
kind: SecretSync
metadata:
  name: app
  namespace: app
spec:
  sources:
    - path: /kubernetes/app
    - path: /kubernetes/shared
      recursive: true
  refreshInterval: 60s
  targets:
    - name: app-secrets
    - name: repo-creds
      namespace: argo
      creationPolicy: Orphan
      metadata:
        labels:
          argocd.argoproj.io/secret-type: repository
      template:
        data:
          url: "https://{{ .REGISTRY_USERNAME }}:{{ .REGISTRY_TOKEN }}@git.example.com/repo.git"
```

| Field | Description |
|-------|-------------|
| `sources[].path` | Path to read. Sources are merged in order; later sources win on duplicate keys. |
| `sources[].recursive` | Also read nested paths. Paths are merged in alphabetical order, so on duplicate keys a nested path wins over its parents, and between sibling branches the later name wins (`/a/z` over `/a/b/c`). |
| `refreshInterval` | Resync period, default `60s`. |
| `targets[].name` / `namespace` | Secret to write. `namespace` defaults to the SecretSync namespace. |
| `targets[].creationPolicy` | `Owner` (default) deletes the Secret when the SecretSync or the target is removed. `Orphan` keeps it. |
| `targets[].type` | Secret type, default `Opaque`. |
| `targets[].metadata` | Labels and annotations set on the Secret. |
| `targets[].template.data` | Go templates for each key; `{{ .KEY }}` reads a source value. Without a template, every key is copied. |

The controller never overwrites a Secret it did not create; the `Ready` condition reports the conflict instead. `kubectl get secretsync` shows `Ready` and `Reason`.

`kubectl describe secretsync` lists events: `Synced` when a target Secret is created or updated, `WorkloadsRestarted` when workloads are restarted, and a `Warning` with the condition reason (`SourceError`, `SyncFailed`) when a sync starts failing or its error changes.

### Restarting workloads

Annotate a Deployment, StatefulSet or DaemonSet to restart it whenever a synced Secret it references (`envFrom`, `env.valueFrom`, `volumes`, projected volumes) changes:

```yaml
metadata:
  annotations:
    secretmanager.rapatao.com/auto-reload: "true"
```

## CLI

Install the CLI with Go, or build it with `make build`. A `go install` build reports its version as `dev`; `make build` uses `git describe`:

```sh
go install github.com/rapatao/secret-manager/cmd/secret-manager@latest
```

```sh
secret-manager servers login --server https://secrets.example.com   # approve in the browser, see Servers and login

secret-manager list
secret-manager set --path /tools GITHUB_TOKEN=abc OTHER=1
secret-manager set --path /tools --env-file .env       # or --env-file - for stdin
secret-manager keys --path /tools                      # key names, no values
secret-manager keys --path /tools --recursive          # PATH KEY for every nested path
secret-manager get --path /tools GITHUB_TOKEN
secret-manager get --path /tools --recursive           # dotenv output
secret-manager export --path /tools --format json
secret-manager delete --path /tools OTHER
secret-manager delete --path /tools --all
secret-manager run --path /tools -- make updates
secret-manager history --path /tools                   # list versions
secret-manager history --path /tools 3                 # print version 3 as dotenv
secret-manager rollback --path /tools 3
secret-manager backup --history --output backup.json  # every path and its versions, see Backup
secret-manager restore backup.json
secret-manager version                                 # client and server versions, server capabilities
```

### Servers and login

Log in once per server:

```sh
secret-manager servers login --server https://secrets.example.com             # approve in a browser on this computer
secret-manager servers login --server https://secrets.example.com --device    # approve from any browser
echo "$TOKEN" | secret-manager servers login --server https://secrets.example.com --token-stdin
secret-manager servers                                # list logged-in servers, marks the default
secret-manager servers use https://secrets.example.com
secret-manager servers logout --server https://secrets.example.com
```

`servers login` creates an [integration](#integrations) approved in the Web UI:

1. The CLI opens the server's approval page in the default browser. Sign in with the admin token if needed.
2. Pick the integration's name (default `cli-<hostname>`), path, access and expiry (default 90 days), then Allow, or Deny.
3. The browser hands an authorization code to the CLI on `http://127.0.0.1:<random port>/callback`. The CLI exchanges it for the token with its PKCE verifier (RFC 7636). A code works once, and only with that verifier.

With `--device`, over SSH (`SSH_CONNECTION` is set) or when no browser can be opened, the CLI prints the approval page URL and a code like `ABCD-2345` instead. Open the URL in any browser, check that the page shows the same code, and approve; the CLI polls the server and picks up the token. A login not approved within 5 minutes fails.

`--token-stdin` stores an existing token instead, such as one created in the Web UI, after checking it against the server. Either way the server becomes the default. You can be logged in to several servers at once: `servers use` switches the default, and `--server` picks one for a single command. A request with an expired or revoked token fails with `401` and a hint to run `servers login` again.

Without a login, set `SECRET_MANAGER_URL` and `SECRET_MANAGER_TOKEN` to a server and an integration token, as in CI.

Tokens are stored in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) under the service `secretmanager.rapatao.com`, one entry per server. Without a usable keychain, as on headless Linux, they fall back to `~/.config/secretmanager.rapatao.com/credentials.json` with `0600` permissions and a warning is printed. The list of servers and the default are kept in `config.json` in the same directory (`$XDG_CONFIG_HOME` is honored).

### Resolution order

The server is `--server`, then `SECRET_MANAGER_URL`, then the default from `servers`.

`SECRET_MANAGER_TOKEN` belongs to `SECRET_MANAGER_URL` and is only sent to that server. Any other server, chosen with `--server` or as the default, uses its token stored by `servers login`. Setting `SECRET_MANAGER_TOKEN` without `SECRET_MANAGER_URL` is an error.

| Set | Server | Token |
|---|---|---|
| `SECRET_MANAGER_URL` + `SECRET_MANAGER_TOKEN` | env URL | env token |
| `--server X` (X is not the env URL) | X | stored token for X |
| nothing | default | stored token for default |
| `SECRET_MANAGER_TOKEN` only | - | error |

No command accepts the token as a flag.

`run` adds the secrets to the current environment, overriding variables with the same name, and exits with the command's exit code.

### Offline cache

`get`, `export` and `run` keep the last secrets they read from each server, path and `--recursive` setting. When the server is unreachable (connection error, or a `502`, `503` or `504` from the Ingress), they use the cached secrets and print a warning with the time they were read. Any other answer, such as `401` or `404`, is reported as an error and the cache is not used. Writes do not update the cache; the next successful read does.

Cached secrets are used for up to 7 days after they were read. `SECRET_MANAGER_CACHE_MAX_AGE` changes that, as a Go duration (`24h`, `30m`); `0` disables the cache, so nothing is written or read. Expired entries are removed when found.

Entries are encrypted with AES-256-GCM and stored in the `cache` directory next to `config.json`, `0600` files in a `0700` directory. The key is kept only in the OS keychain (account `offline-cache-key` under `secretmanager.rapatao.com`), so without a usable keychain nothing is cached. `servers logout` removes the cached secrets of that server; delete the `cache` directory to remove all of them.

## History

Every write that changes a path (setting keys, deleting a key) stores the path's new data as a version numbered one above the previous, and so does every rollback. A rollback to a version holding the current data is rejected with `400`; the Web UI marks the newest version as current, marks older versions holding the same data as "same as current", and offers no diff or restore for either. Other writes that change nothing, and changes made directly on the stored Secrets, are not recorded. The newest versions are kept, current one included, up to `--history-limit` (chart value `historyLimit`, default `10`). Lowering the limit removes the extra versions of a path on its next write. `0` stops recording; versions already stored stay until removed by hand (`kubectl delete secret -l secretmanager.rapatao.com/history=true`).

`secret-manager history --path P --diff N` lists the keys added (`+`), removed (`-`) or changed (`~`) from version `N` to the current data; `--diff N M` compares two versions. Values are not printed; `history --path P N` prints a version. The Web UI shows the same changes for each version, compared with the version before it. Its Diff button opens a dialog comparing the version with the current data, values included, and the restore and save dialogs show the same comparison. Added keys are green, removed keys red and changed keys amber. A long comparison scrolls inside the dialog, and a long value scrolls inside its cell.

Deleting a path keeps its versions, so `rollback` can bring it back. Rolling back writes the old data as a new version, so it can itself be undone. Rolling back a synced path updates its targets like any other write.

A path written while history is disabled has no versions until its next change.

## Backup

`secret-manager backup` prints every path and its data as JSON; `--output F` writes it to `F` with `0600` permissions instead. `--history` adds the versions of each path. Versions of deleted paths are not included.

`secret-manager restore F` (`-` for stdin) replaces the data of every path in the file. Paths not in the file are kept. Each changed path is recorded as a new version and its targets are synced, like any other write. Versions in the file are restored only for paths that have none yet, renumbered from 1 and limited to `--history-limit`; a path that already has versions only gets a new one for the restored data. Restoring the same file twice changes nothing. Every path and key is checked before anything is written.

The file holds every value in plain text. Encrypt it before storing it elsewhere, for example `secret-manager backup | age -r KEY > backup.json.age`. To move to a new server, or to keep a copy before an upgrade, back up from the old server and restore on the new one; any client version with `backup` can talk to both, see [Compatibility](#compatibility).

### Scheduled backups

With `--backup-dir DIR`, the server writes a backup to `DIR/backup-<UTC time>.json` (`0600`) every `--backup-interval` (default `24h`) and keeps the newest `--backup-keep` files (default `7`). `--backup-history` adds versions. The first backup is written one interval after the server starts. Each run is logged as an audit entry with `source` `schedule` and `op` `backup`; a failed run is logged at `WARN` and tried again on the next interval.

In the chart, set `backup.enabled=true` (`backup.interval`, `backup.keep`, `backup.history`). Backups go to a `ReadWriteOnce` PersistentVolumeClaim named `<release>-backups` (`backup.persistence.size`, default `1Gi`, and `backup.persistence.storageClass`), or to `backup.persistence.existingClaim`. Helm keeps the claim when the release is uninstalled. The image has no shell, so to copy a file out, mount the claim in another pod. The same plain-text warning applies to these files.

## Integrations

An integration is a token (`smt_...`) for API clients: the CLI, CI jobs, other machines, `secret-manager run`. The API accepts only integration tokens; the admin token signs in to the Web UI.

| Setting | Values |
|---|---|
| Name | `[a-z0-9-]`, up to 63 characters, unique. Fixed once created |
| Path | A path; the integration covers it and every path nested below it |
| Read-only | Reads only, or reads and writes |
| Expires | 7, 30 or 90 days, 1 year, the end of a chosen day (UTC), or never |

What an integration can do:

| Operation | Path `P` | Path `/` |
|---|---|---|
| `info`, `list` (only paths under its path) | yes | yes |
| Read data, keys and history | under `P` | every path |
| Set and delete keys, delete paths, roll back (not read-only) | under `P` | every path |
| Backup | no | yes |
| Restore (not read-only) | no | yes |

A request outside the integration's scope gets `403`; an unknown, revoked or expired token gets `401`. Managing integrations and approving logins happen only in the Web UI.

### Creating integrations

- `servers login` creates one after approval in the browser, see [Servers and login](#servers-and-login).
- The Integrations page of the Web UI creates one after a confirmation dialog that shows its name, path, access and expiry. The token is shown once. Use it with `SECRET_MANAGER_URL` and `SECRET_MANAGER_TOKEN`, or `servers login --token-stdin`.

The server keeps only the SHA-256 hash of each token, in the storage backend (a Secret named `sm-tokens` with the `kubernetes` backend). Integrations are loaded once and kept in memory, so changes made directly on the stored tokens need a server restart.

### Managing integrations

The Integrations page lists every integration with its path, access, creation time, expiry and last use. Expired integrations stay listed, marked expired, until revoked.

- Edit changes the path, read-only access and expiry, keeping the token. The expiry can stay as it is or take any of the values above. Save opens a confirmation dialog listing the current and new values; clients get the new access on their next request. Save without changes closes the dialog. Cancel with unsaved changes asks whether to discard them or keep editing, and Cancel in the confirmation dialog discards the edit.
- Revoke deletes the integration after a confirmation dialog.

The last use is tracked in memory and saved every `--last-used-flush` (default `30m`) and on shutdown. It can lag behind, and a crash loses the uses since the last save.

## Web UI

Open the server URL and sign in with the admin token. The header shows the server version next to the name, and links to Integrations and Sign out. The UI follows the system light or dark theme.

Paths
- One field filters paths as you type, matching anywhere in the path. It opens the typed path when it exists, or creates it after a confirmation dialog.
- Deleted paths that still have versions are listed separately; restoring one of their versions brings them back.
- Deleting a path is in the collapsed danger zone of its page, and requires typing the path in a confirmation dialog.

Keys
- Values stay hidden until expanded. The copy button copies a value to the clipboard.
- Adding keys, editing values and deleting keys are staged on the page: a deleted key is struck through until saved, and Undo brings it back.
- A new key cannot reuse the name of an existing key or of another new key; existing keys change in their own row.
- Save changes is enabled once something is staged. It opens a confirmation dialog listing the keys added (`+`), changed (`~`) and deleted (`-`) with their current and new values, and writes every staged change as one version.

History
- Each version can be compared with the current data and restored after a confirmation dialog, see [History](#history).

Integrations and logins
- The Integrations page manages [integrations](#integrations). `/authorize` approves or denies CLI logins, see [Servers and login](#servers-and-login).

The server rejects every change made without its confirmation, or with one that does not match. Filtering paths, editing keys, the copy button and the integration dialogs need JavaScript; browsers without invoker commands (`commandfor`) also use it to open the dialogs.

Sessions last 12 hours and survive server restarts; changing the admin token signs every session out. Signing out deletes the session cookie in the browser. The session cookie is `Secure`: use HTTPS (an Ingress with TLS) or `localhost`.

## API

All endpoints except `/healthz`, `/readyz` and the two login endpoints require `Authorization: Bearer <token>`, an [integration](#integrations) token allowed to use the endpoint and path. The admin token is not accepted.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/info` | `{"version": "v1.4.0", "capabilities": [...]}`, see [Compatibility](#compatibility) |
| `GET` | `/api/v1/paths` | `{"paths": [...]}` |
| `GET` | `/api/v1/secrets?path=P&recursive=true` | `{"data": {"KEY": "value"}}` |
| `PUT` | `/api/v1/secrets?path=P` | Merge a JSON object of string values into P |
| `DELETE` | `/api/v1/secrets/{key}?path=P` | Delete one key |
| `DELETE` | `/api/v1/paths?path=P` | Delete a path (nested paths are kept) |
| `GET` | `/api/v1/backup?history=true` | `{"format": 1, "version": "...", "time": "...", "paths": [{"path": "/a", "data": {...}, "versions": [...]}]}`, `versions` only with `history=true` |
| `POST` | `/api/v1/restore` | Restore a backup document, returns `{"paths": N}` |
| `GET` | `/api/v1/history?path=P` | `{"versions": [{"version": 3, "time": "...", "keys": [...]}]}`, newest first, without values |
| `GET` | `/api/v1/history/{version}?path=P` | `{"version": 3, "time": "...", "data": {"KEY": "value"}}` |
| `POST` | `/api/v1/history/{version}/rollback?path=P` | Replace the data at P with that version |
| `POST` | `/api/v1/authorize/device` | Start a device login from `{"name": "cli-box"}`, returns `{"deviceCode": "...", "userCode": "ABCD-2345", "verificationUri": "/authorize?user_code=ABCD-2345", "expiresIn": 300, "interval": 2}`. No token needed |
| `POST` | `/api/v1/authorize/token` | Collect the token of an approved login, once: `{"code": "...", "codeVerifier": "..."}` for a loopback login, `{"deviceCode": "..."}` for a device login. Returns `{"name", "path", "readOnly", "expires", "token"}`; `400` with `authorization_pending` until a device login is approved, `403` with `access_denied` when denied. No token needed |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness: 503 when the storage backend cannot be read |

Paths look like `/a/b`, with segments of `[a-z0-9-]`. Keys match `[-._a-zA-Z0-9]+`.

A loopback login starts in the browser at `/authorize?redirect_uri=http://127.0.0.1:PORT/callback&state=S&code_challenge=C&name=N`, where `C` is the base64url SHA-256 of the client's verifier. `redirect_uri` must be `http` on `127.0.0.1`, `::1` or `localhost` with a port. After approval the browser is redirected to `redirect_uri?code=...&state=S`, or `?error=access_denied&state=S`. Pending logins live in the server's memory for 5 minutes, at most 100 at a time, and are lost on restart.

### Compatibility

Clients and servers of different versions work together, as long as the server has the features a command uses.

`GET /api/v1/info` lists those features as capabilities: `paths`, `secrets`, `history`, `backup` and `integrations`. A command that needs a feature checks its capability first and fails with `server v1.2.0 at URL does not support X; upgrade the server`. Servers without `/api/v1/info` are treated as having `paths`, `secrets` and `history`, and their version is shown as unknown. A capability never changes meaning; changed behavior gets a new capability.

Authentication depends on the `integrations` capability:

| Server | API token | CLI login |
|---|---|---|
| With `integrations` | An integration token | `servers login` in the browser, or `--token-stdin` with an integration token |
| Without `integrations` | The admin token | `servers login --token-stdin` with the admin token; browser login fails with `server does not support browser login; upgrade it or log in with --token-stdin` |

A CLI without browser login works against a server with `integrations` using an integration token, through `SECRET_MANAGER_TOKEN` or its `servers login` prompt.

`secret-manager version` prints the client version and, when a server is set (see [Resolution order](#resolution-order)), the server version and capabilities:

```
client: v1.5.0
server: v1.4.0 (https://secrets.example.com)
capabilities: backup, history, integrations, paths, secrets
```

## Observability

### Metrics

Prometheus metrics are served on `:8081/metrics` (`--metrics-addr`, `0` disables them) and exposed on the Service port `metrics`. Besides the controller-runtime and Go runtime metrics (`controller_runtime_reconcile_total`, `workqueue_depth`, ...), the server exports:

| Metric | Description |
|--------|-------------|
| `secretmanager_sync_failures_total{reason}` | Reconciles that left `Ready` False, by reason |
| `secretmanager_workload_restarts_total{kind}` | Deployments, StatefulSets and DaemonSets restarted because a synced Secret changed, by kind |

With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` to match your Prometheus selector) to create a `ServiceMonitor`.

### Logs

Logs are JSON on stderr. `--log-level` (chart value `logLevel`) sets the level: `debug`, `info` (default), `warn` or `error`. Unexpected errors are logged as `secret operation failed` with the request `method`, `url` and secret `path`.

### Audit log

Every change made through the API or the Web UI, every backup, every Web UI login and every failed authentication is logged as a JSON line with `"msg":"audit"`:

```json
{"level":"INFO","msg":"audit","source":"api","op":"set","remote":"10.42.0.7:51234","forwarded_for":"203.0.113.9","path":"/tools","keys":["GITHUB_TOKEN"]}
{"level":"WARN","msg":"audit","source":"ui","op":"login","remote":"10.42.0.7:51240","error":"invalid token"}
```

`op` is one of `set`, `delete_key`, `delete_path`, `create_path`, `rollback`, `backup`, `restore`, `create_token`, `update_token`, `revoke_token` (with the integration `name`), `authorize` (a CLI login approved or denied in the Web UI), `login` and `auth` (API bearer token, including expired tokens and requests an integration is not allowed to make). Requests made with an integration token carry its name in `token`. Key names are logged, values never are. Failed operations are logged at `WARN` with `error`. `forwarded_for` is the client supplied `X-Forwarded-For` header and is only as trustworthy as your Ingress. Other reads are not logged.

## Security notes

- Without [encryption](#encryption), values are only as protected as the storage backend: Secrets in your cluster, or the `file` backend's file. Set an encryption key, or enable encryption at rest in the cluster (k3s: `--secrets-encryption`), and restrict who can read Secrets in the server namespace. The encryption key is as sensitive as the admin token.
- Old values stay readable in history Secrets after they are changed or deleted. To purge a leaked value, delete its versions: `kubectl -n secret-manager get secrets -l secretmanager.rapatao.com/history=true` lists them.
- The CLI caches the secrets it reads, encrypted with a key in the OS keychain, for up to 7 days. Anyone who can use your keychain can read them. Set `SECRET_MANAGER_CACHE_MAX_AGE=0` on shared machines.
- Backup files hold every value in plain text. Encrypt them and keep them out of git.
- With the `file` backend, restrict access to the file and its directory. Without an encryption key, values are stored in plain text in it.
- With the controller enabled, the server can manage Secrets in every namespace, where `SecretSync` targets live. With `controller.enabled=false` it can only manage Secrets in its own namespace.
- The metrics port has no authentication. It exposes no secret values, but restrict it with a NetworkPolicy if other workloads should not read it.
- The admin token signs in to the Web UI, which can read every value and create integrations. Keep it long and random, and rotate it by updating its Secret and restarting the server. Give every client its own [integration](#integrations), as narrow and short-lived as it allows, and revoke it when it is no longer used.
- Approve a CLI login only if you started it. For a device login, check that the code on the approval page matches the one in your terminal.

## Development

Requires the Go version in `go.mod`, `golangci-lint` v2 and `helm`.

```sh
make generate   # deepcopy and CRD (controller-gen, pinned as a go tool)
make test
make lint
make build      # bin/secret-manager
make run        # local server on :8080, file storage in .local/, no cluster
make docker
make helm-lint
make check-generated   # fails if generated files are out of date
```

## CI and releases

- `ci.yaml` runs on pushes to `main` and on pull requests: generated files check, tests, lint, build, chart lint, and a multi-arch image build without push.
- `release.yaml` runs on `v*` tags. It pushes `linux/amd64` and `linux/arm64` images tagged with the version and `major.minor`, then the Helm chart as an OCI artifact. The image goes to `ghcr.io/rapatao/secret-manager` and the chart to `oci://ghcr.io/rapatao/charts/secret-manager`, using `GITHUB_TOKEN`. The chart's `version` and `appVersion` are set from the tag (`v1.2.0` becomes `1.2.0`). After the image and chart are pushed, it creates a release for the tag. The notes list the commit subjects since the previous tag.

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE). If you distribute a modified secret-manager or offer it as a network service, you must make its source available to its users under the same license.
