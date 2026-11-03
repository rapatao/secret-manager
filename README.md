# secret-manager

A small, self-hosted key-value secret manager for Kubernetes.

- Secrets are organized by path (`/kubernetes/app`, `/tools`) and managed with a CLI or a Web UI.
- A `SecretSync` resource syncs one or more paths into Kubernetes Secrets, in any namespace, optionally shaped with Go templates.
- Deployments that opt in are restarted when a Secret they use changes.
- `secret-manager run` injects secrets as environment variables into local commands.

One binary contains the controller, the REST API, the Web UI and the CLI.

## How it works

```
CLI / Web UI --HTTP--> secret-manager server --> storage backend (Kubernetes Secrets)
                              |
                              +--> controller --> target Secrets --> Deployment restarts
```

Writes made through the API reach target Secrets immediately. Every `SecretSync` also resyncs on its `refreshInterval`, which repairs drift and picks up changes made directly on the store.

### Storage

Storage is pluggable behind a small interface (`internal/storage.Backend`). The only backend today is `kubernetes`: each path is a Secret in the server's namespace (`/kubernetes/app` is stored as `sm.kubernetes.app`, labeled `secretmanager.rapatao.com/store=true`). There is no database or volume to run.

To add a backend (SQLite, Postgres, ...), implement `storage.Backend`, run `storagetest.Run` against it in its tests, and add a case to the `--storage` switch in `cmd/secret-manager/main.go`.

## Install

Create the admin token (at least 32 characters), then install the chart:

```sh
kubectl create namespace secret-manager
kubectl -n secret-manager create secret generic secret-manager-token \
  --from-literal=token="$(openssl rand -base64 36)"

helm install secret-manager charts/secret-manager -n secret-manager \
  --set auth.existingSecret=secret-manager-token \
  --set ingress.enabled=true --set ingress.host=secrets.example.com
```

The chart installs the `SecretSync` CRD from `charts/secret-manager/crds`. Helm does not upgrade CRDs, so apply that directory with `kubectl apply -f` after upgrading.

The server runs as a single replica: writes are serialized in process.

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
| `sources[].recursive` | Also read nested paths. The deeper path wins on duplicate keys. |
| `refreshInterval` | Resync period, default `60s`. |
| `targets[].name` / `namespace` | Secret to write. `namespace` defaults to the SecretSync namespace. |
| `targets[].creationPolicy` | `Owner` (default) deletes the Secret when the SecretSync or the target is removed. `Orphan` keeps it. |
| `targets[].type` | Secret type, default `Opaque`. |
| `targets[].metadata` | Labels and annotations set on the Secret. |
| `targets[].template.data` | Go templates for each key; `{{ .KEY }}` reads a source value. Without a template, every key is copied. |

The controller never overwrites a Secret it did not create; the `Ready` condition reports the conflict instead. `kubectl get secretsync` shows `Ready` and `Reason`.

### Restarting Deployments

Annotate a Deployment to restart it whenever a synced Secret it references (`envFrom`, `env.valueFrom`, `volumes`, projected volumes) changes:

```yaml
metadata:
  annotations:
    secretmanager.rapatao.com/auto-reload: "true"
```

## CLI

```sh
export SECRET_MANAGER_URL=https://secrets.example.com
export SECRET_MANAGER_TOKEN=...

secret-manager list
secret-manager set --path /tools GITHUB_TOKEN=abc OTHER=1
secret-manager set --path /tools --env-file .env       # or --env-file - for stdin
secret-manager get --path /tools GITHUB_TOKEN
secret-manager get --path /tools --recursive           # dotenv output
secret-manager export --path /tools --format json
secret-manager delete --path /tools OTHER
secret-manager delete --path /tools --all
secret-manager run --path /tools -- make updates
```

### Servers and login

Instead of environment variables, log in once per server:

```sh
secret-manager servers login --server https://secrets.example.com    # prompts for the token
echo "$TOKEN" | secret-manager servers login --server https://secrets.example.com --token-stdin
secret-manager servers                                # list logged-in servers, marks the default
secret-manager servers use https://secrets.example.com
secret-manager servers logout --server https://secrets.example.com
```

`servers login` checks the token against the server before storing it, then makes that server the default. You can be logged in to several servers at once: `servers use` switches the default, and `--server` picks one for a single command.

Tokens are stored in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) under the service `secretmanager.rapatao.com`, one entry per server. Without a usable keychain, as on headless Linux, they fall back to `~/.config/secretmanager.rapatao.com/credentials.json` with `0600` permissions and a warning is printed. The list of servers and the default are kept in `config.json` in the same directory (`$XDG_CONFIG_HOME` is honored).

### Resolution order

The server is `--server`, then `SECRET_MANAGER_URL`, then the default from `servers`.

`SECRET_MANAGER_TOKEN` belongs to `SECRET_MANAGER_URL` and is only sent to that server. Any other server, chosen with `--server` or as the default, uses its token stored by `servers login`. Setting `SECRET_MANAGER_TOKEN` without `SECRET_MANAGER_URL` is an error, so a leftover token is never sent to the default server.

| Set | Server | Token |
|---|---|---|
| `SECRET_MANAGER_URL` + `SECRET_MANAGER_TOKEN` | env URL | env token |
| `--server X` (X is not the env URL) | X | stored token for X |
| nothing | default | stored token for default |
| `SECRET_MANAGER_TOKEN` only | - | error |

The token is never accepted as a flag, so it doesn't end up in shell history or the process list.

`run` adds the secrets to the current environment, overriding variables with the same name, and exits with the command's exit code.

## Web UI

Open the server URL and sign in with the admin token. The UI lists paths and lets you create and delete paths and keys; values stay hidden until expanded. Sessions last 12 hours and are lost when the server restarts. The session cookie is `Secure`, so use HTTPS (an Ingress with TLS) or `localhost`.

## API

All endpoints except `/healthz` require `Authorization: Bearer <token>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/paths` | `{"paths": [...]}` |
| `GET` | `/api/v1/secrets?path=P&recursive=true` | `{"data": {"KEY": "value"}}` |
| `PUT` | `/api/v1/secrets?path=P` | Merge a JSON object of string values into P |
| `DELETE` | `/api/v1/secrets/{key}?path=P` | Delete one key |
| `DELETE` | `/api/v1/paths?path=P` | Delete a path (nested paths are kept) |
| `GET` | `/healthz` | Liveness |

Paths look like `/a/b`, with segments of `[a-z0-9-]`. Keys match `[-._a-zA-Z0-9]+`.

## Security notes

- With the `kubernetes` backend, values are only as protected as Secrets in your cluster. Enable encryption at rest (k3s: `--secrets-encryption`) and restrict who can read Secrets in the server namespace.
- The server needs cluster-wide permission to manage Secrets, because targets can live in any namespace.
- The admin token grants full access. Keep it long and random, and rotate it by updating its Secret and restarting the server.

## Development

Requires the Go version in `go.mod`, `golangci-lint` v2 and `helm`.

```sh
make generate   # deepcopy and CRD (controller-gen, pinned as a go tool)
make test
make lint
make build      # bin/secret-manager
make docker
```

## CI and releases

The canonical repository is `git.rapatao.com/rapatao/secret-manager`, mirrored to `github.com/rapatao/secret-manager`. The workflows in `.github/workflows` run on both: Gitea Actions uses that folder when there's no `.gitea/workflows`.

- `ci.yaml` runs on pushes to `main` and on pull requests: generated files check, tests, lint, build, chart lint, and a multi-arch image build without push.
- `release.yaml` runs on `v*` tags. It pushes `linux/amd64` and `linux/arm64` images tagged with the version and `major.minor`, then the Helm chart as an OCI artifact. The chart's `version` and `appVersion` are set from the tag (`v1.2.0` becomes `1.2.0`), and its default image points at the same registry:
  - on GitHub: image `ghcr.io/rapatao/secret-manager`, chart `oci://ghcr.io/rapatao/charts/secret-manager`, using `GITHUB_TOKEN`
  - on Gitea: image `git.rapatao.com/rapatao/secret-manager`, chart `oci://git.rapatao.com/rapatao/charts/secret-manager`, using the `REGISTRY_TOKEN` repository secret (a token with `write:package`)

Install a released chart with:

```sh
helm install secret-manager oci://ghcr.io/rapatao/charts/secret-manager --version 1.2.0 \
  -n secret-manager --set auth.existingSecret=secret-manager-token
```

Setup:

- Gitea: add the `REGISTRY_TOKEN` secret and register an act_runner with the `ubuntu-latest` label and Docker access.
- Push mirror to GitHub: the GitHub token needs the `workflow` scope, otherwise GitHub rejects pushes that change `.github/workflows`. Tags must be mirrored for releases to run there.
