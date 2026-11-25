# Install

The server runs on Kubernetes with the Helm chart, or [without Kubernetes](#without-kubernetes) from the binary or the container image. A [local vault](local-vault.md) needs only the CLI and no server.

## Kubernetes

Create the admin token (at least 32 characters) that signs in to the Web UI, then install the chart:

```sh
kubectl create namespace secret-manager
kubectl -n secret-manager create secret generic secret-manager-token \
  --from-literal=token="$(openssl rand -base64 36)"

helm install secret-manager oci://ghcr.io/rapatao/charts/secret-manager -n secret-manager \
  --set auth.existingSecret=secret-manager-token \
  --set ingress.enabled=true --set ingress.host=secrets.example.com
```

Add `--version 1.2.0` to pin a release. Set `historyLimit` (default `10`, `0` disables history) to change how many versions are kept per path, `events` to choose which [audit events](observability.md#event-categories) are logged or kept, and `revisionHistoryLimit` (default `10`) to change how many old ReplicaSets the Deployment keeps for `kubectl rollout undo`. From a checkout, use `charts/secret-manager` instead of the `oci://` reference.

The chart installs the `SecretSync` CRD, whose validation rule (`refreshInterval` at most 1h) needs Kubernetes 1.25 or later. Its schema also limits the target `type`, see below. Helm does not upgrade CRDs, so apply them after upgrading:

```sh
helm pull oci://ghcr.io/rapatao/charts/secret-manager --untar --untardir /tmp/sm
kubectl apply -f /tmp/sm/secret-manager/crds
```

Before Kubernetes 1.30, the API server checks the rule on every update of a SecretSync, including the controller's finalizer and status writes. A SecretSync whose `refreshInterval` is above 1h then cannot be updated: its status stops changing and, once deleted, it stays in `Terminating`. Before applying the CRD on such a cluster, list the SecretSyncs and lower every `refreshInterval` above 1h:

```sh
kubectl get secretsync -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.refreshInterval}{"\n"}{end}'
kubectl -n NAMESPACE patch secretsync NAME --type merge -p '{"spec":{"refreshInterval":"1h"}}'
```

If the CRD is already applied, the same patch recovers a stuck SecretSync. From Kubernetes 1.30, a value that was already stored and did not change is accepted, so existing SecretSyncs keep working and the controller resyncs them every hour at most.

A target `type` must be `Opaque`, `kubernetes.io/dockerconfigjson`, `kubernetes.io/tls`, `kubernetes.io/basic-auth` or `kubernetes.io/ssh-auth`, or empty for `Opaque`; see [SecretSync](secretsync.md). Before applying the CRD, list the types in use:

```sh
kubectl get secretsync -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.targets[*].type}{"\n"}{end}'
```

Before Kubernetes 1.30, a SecretSync with another type, such as `kubernetes.io/service-account-token` or `kubernetes.io/dockercfg`, cannot be updated once the CRD is applied: its status stops changing and, once deleted, it stays in `Terminating`. Fix its `type` first with `kubectl edit secretsync`. A Secret's type is immutable, so changing a target's `type` does not change a Secret that already exists: the target reports the mismatch until the Secret is deleted or the target is renamed. From Kubernetes 1.30, an unchanged stored type is accepted, and the controller sets such a SecretSync to `SyncFailed`.

A SecretSync that already wrote a Secret of a type now refused, any type outside the allowed ones (for example `kubernetes.io/service-account-token`, `bootstrap.kubernetes.io/token` or `kubernetes.io/dockercfg`), goes `SyncFailed` once the controller runs. That Secret stays in place: it is not updated or released, and a token it carries stays valid until the Secret is deleted. Find the Secrets written by SecretSyncs with a type outside the allowed ones, delete them, and rotate any credential they held that may have been read:

```sh
kubectl get secrets -A -l secretmanager.rapatao.com/owner \
  -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type \
  | grep -Ev 'Opaque|kubernetes.io/(dockerconfigjson|tls|basic-auth|ssh-auth)$'
kubectl -n NAMESPACE delete secret NAME
```

The listing's header line is also printed, since it does not match; the rows that follow are the Secrets to delete.

Change the target's `type` or delete the SecretSync, otherwise it stays `SyncFailed`. The controller does not recreate a deleted Secret of a disallowed type.

The server runs as a single replica: writes are serialized in process.

Set `controller.enabled=false` to only store secrets: the `SecretSync` controller does not run, no Secret outside the release namespace is written, no workload is restarted, and the chart installs a Role limited to Secrets in the release namespace instead of a ClusterRole. Add `--skip-crds` to `helm install` to leave out the `SecretSync` CRD.

With the controller enabled, the [sync policy](secretsync.md#sync-policy) limits what SecretSyncs may read and write. It lives in the server, is edited in the Web UI, the API or the CLI, and is off by default. A save is refused when the policy changed since it was read; this check covers one server process, so run a single replica.

The server loads the policy on first use and keeps it in memory, so a change made outside the Web UI, the API and the CLI, such as editing the `sm-sync-policy` Secret or the storage file, takes effect after a restart. A missing policy reads as a disabled one, which restricts nothing: this is deliberate, and a server whose stored policy was deleted before it started runs every SecretSync unrestricted until a policy is saved. Versions of the server without the sync policy do not read it, so after a downgrade every SecretSync is unrestricted. With the `kubernetes` and `postgres` storage the stored policy stays where it is, in the `sm-sync-policy` Secret or the policy table, and applies again once the server is upgraded. With the `file` storage the policy is a field of the one state file, which an older server does not know and drops the first time it writes the file, so the policy is lost: keep a copy with `secret-manager sync-policy get` before downgrading.

## Without Kubernetes

```sh
export SECRET_MANAGER_TOKEN="$(openssl rand -base64 36)"
secret-manager server --storage=file --file=/var/lib/secret-manager/store.json --controller=false
```

Install the binary as described in [CLI](cli.md), or run the image `ghcr.io/rapatao/secret-manager` with the same arguments after its `server` command. The image runs as user `65532`, so the directory holding `--file` must be writable by that user. See [Storage](storage.md#storage) for the `file` backend.

To store secrets in PostgreSQL instead of a file:

```sh
export SECRET_MANAGER_DATABASE_URL="postgres://secret-manager:PASSWORD@db.example.com:5432/secrets?sslmode=verify-full"
secret-manager server --storage=postgres --controller=false
```

See [Storage](storage.md#storage) for the `postgres` backend.

The CLI, Web UI, history and backups work the same; `SecretSync` and workload restarts are not available. The Web UI session cookie is `Secure`, so serve the server over HTTPS, through a reverse proxy with TLS, or open it on `localhost`.

## Server flags

The chart sets these; set them yourself when running `secret-manager server` outside it.

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | Listen address of the API and Web UI |
| `--metrics-addr` | `:8081` | Listen address of the Prometheus metrics, `0` disables them |
| `--storage` | `kubernetes` | Storage backend: `kubernetes`, `file` or `postgres` |
| `--namespace` | `$POD_NAMESPACE` | Namespace holding the stored secrets and their versions (`kubernetes` storage) |
| `--file` | `secret-manager.json` | File holding the stored secrets and their versions (`file` storage) |
| `--controller` | `true` | Run the `SecretSync` controller. Requires access to a cluster |
| `--history-limit` | `10` | Versions kept per path, current included, `0` disables history |
| `--cache-max-age` | `168h` | How long clients may use the secrets they read while the server is unreachable, `0` disables their [offline cache](cli.md#offline-cache). Integrations may override it |
| `--trusted-proxies` | | Comma-separated CIDRs or addresses of the proxies in front of the server, see [Client address](client-address.md) |
| `--events` | `reads=none,lists=none,logins=audit,backups=audit` | Where each category of audit events goes, see [Event categories](observability.md#event-categories) |
| `--last-used-flush` | `30m` | Time between saves of the last use of every [integration](integrations.md), also saved on shutdown |
| `--backup-dir` | | Directory receiving [scheduled backups](backup.md#scheduled-backups), empty disables them |
| `--backup-interval` | `24h` | Time between scheduled backups |
| `--backup-keep` | `7` | Scheduled backup files kept |
| `--backup-history` | `false` | Include versions in scheduled backups |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |

The API and Web UI listener, and the one a [local vault](local-vault.md) serves for `ui`, wait 10 seconds for the request headers, read the whole request within 10 minutes, which bounds the upload of a restore, take at most 2 minutes to write a response, and close idle connections after 2 minutes. Backup downloads and restores extend their write deadline to 12 minutes, the read timeout plus the write timeout, so a large store can outlast the 2 minutes. The metrics listener, which the server runs itself whether or not the controller does, waits 10 seconds for the headers, takes at most 1 minute to write and closes idle connections after 2 minutes. The loopback callback a CLI browser login waits on waits 10 seconds for the headers, reads within 10 minutes, writes within 1 minute and closes idle connections after 2 minutes.

The Web UI admin token is read from `SECRET_MANAGER_TOKEN`, the optional [encryption](storage.md#encryption) key from `SECRET_MANAGER_ENCRYPTION_KEY`, the key being rotated out from `SECRET_MANAGER_PREVIOUS_ENCRYPTION_KEY`, the optional [backup](backup.md#scheduled-backups) passphrase from `SECRET_MANAGER_BACKUP_PASSPHRASE`, and the `postgres` storage connection URL from `SECRET_MANAGER_DATABASE_URL`.
