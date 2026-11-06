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

The chart installs the `SecretSync` CRD. Helm does not upgrade CRDs, so apply them after upgrading:

```sh
helm pull oci://ghcr.io/rapatao/charts/secret-manager --untar --untardir /tmp/sm
kubectl apply -f /tmp/sm/secret-manager/crds
```

The server runs as a single replica: writes are serialized in process.

Set `controller.enabled=false` to only store secrets: the `SecretSync` controller does not run, no Secret outside the release namespace is written, no workload is restarted, and the chart installs a Role limited to Secrets in the release namespace instead of a ClusterRole. Add `--skip-crds` to `helm install` to leave out the `SecretSync` CRD.

## Without Kubernetes

```sh
export SECRET_MANAGER_TOKEN="$(openssl rand -base64 36)"
secret-manager server --storage=file --file=/var/lib/secret-manager/store.json --controller=false
```

Install the binary as described in [CLI](cli.md), or run the image `ghcr.io/rapatao/secret-manager` with the same arguments after its `server` command. The image runs as user `65532`, so the directory holding `--file` must be writable by that user. See [Storage](storage.md#storage) for the `file` backend.

The CLI, Web UI, history and backups work the same; `SecretSync` and workload restarts are not available. The Web UI session cookie is `Secure`, so serve the server over HTTPS, through a reverse proxy with TLS, or open it on `localhost`.

## Server flags

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
| `--cache-max-age` | `168h` | How long clients may use the secrets they read while the server is unreachable, `0` disables their [offline cache](cli.md#offline-cache). Integrations may override it |
| `--trusted-proxies` | | Comma-separated CIDRs or addresses of the proxies in front of the server, see [Client address](client-address.md) |
| `--events` | `reads=none,lists=none,logins=audit,backups=audit` | Where each category of audit events goes, see [Event categories](observability.md#event-categories) |
| `--last-used-flush` | `30m` | Time between saves of the last use of every [integration](integrations.md), also saved on shutdown |
| `--backup-dir` | | Directory receiving [scheduled backups](backup.md#scheduled-backups), empty disables them |
| `--backup-interval` | `24h` | Time between scheduled backups |
| `--backup-keep` | `7` | Scheduled backup files kept |
| `--backup-history` | `false` | Include versions in scheduled backups |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |

The Web UI admin token is read from `SECRET_MANAGER_TOKEN`, the optional [encryption](storage.md#encryption) key from `SECRET_MANAGER_ENCRYPTION_KEY`, the key being rotated out from `SECRET_MANAGER_PREVIOUS_ENCRYPTION_KEY`, and the optional [backup](backup.md#scheduled-backups) passphrase from `SECRET_MANAGER_BACKUP_PASSPHRASE`.
