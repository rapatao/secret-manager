# secret-manager

A small, self-hosted key-value secret manager for Kubernetes.

- Secrets are organized by path (`/kubernetes/app`, `/tools`) and managed with a CLI or a Web UI.
- A `SecretSync` resource syncs one or more paths into Kubernetes Secrets, in any namespace, optionally shaped with Go templates.
- Deployments, StatefulSets and DaemonSets that opt in are restarted when a Secret they use changes.
- `secret-manager run` injects secrets as environment variables into local commands, masks their values in the command's output, and keeps working from an encrypted cache while the server is unreachable.
- A `.secret-manager` file in a directory sets the default path and server for commands run there.
- Every write is kept as a version, so a path can be inspected or rolled back, even after it is deleted. A version holding a leaked value can be deleted.
- `secret-manager backup` and `restore` copy every path, optionally with its versions, to and from a JSON file, optionally encrypted.
- Stored values can be encrypted with AES-256-GCM, and the key can be rotated.
- Changes, sign-ins and failed authentications are written to an audit log and kept on the Web UI Audit page; reads and listings can be logged too, per [event category](docs/observability.md#event-categories).
- A [local vault](docs/local-vault.md) keeps secrets in an encrypted file on your machine, used by the CLI and Web UI without running a server.

One binary contains the controller, the REST API, the Web UI and the CLI. The controller is optional, with the `file` storage backend the server runs without Kubernetes, and with a local vault no server runs at all.

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

## Documentation

- [Install](docs/install.md): Helm chart, running without Kubernetes, server flags
- [Storage and encryption](docs/storage.md): storage backends, encrypting stored values, key rotation
- [SecretSync](docs/secretsync.md): syncing paths into Kubernetes Secrets, restarting workloads
- [CLI](docs/cli.md): commands, servers and login, resolution order, offline cache
- [Local vault](docs/local-vault.md): an encrypted file used without a server
- [History](docs/history.md): versions, diffs, rollback, copy and move
- [Backup](docs/backup.md): backup and restore, scheduled backups
- [Integrations](docs/integrations.md): API tokens, scopes, allowed addresses
- [Web UI](docs/web-ui.md): pages, sign-in limits, sessions
- [Client address](docs/client-address.md): trusted proxies and `X-Forwarded-For`
- [API](docs/api.md): REST endpoints, compatibility between versions
- [Observability](docs/observability.md): metrics, logs, audit log
- [Security notes](docs/security-notes.md)
- [Development](docs/development.md): building, testing, CI and releases

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0](LICENSE). If you distribute a modified secret-manager or offer it as a network service, you must make its source available to its users under the same license.
