# Observability

## Metrics

Prometheus metrics are served on `:8081/metrics` (`--metrics-addr`, `0` disables them) and, in the chart, exposed on the Service port `metrics`. Besides the controller-runtime and Go runtime metrics (`controller_runtime_reconcile_total`, `workqueue_depth`, ...), the server exports:

| Metric | Description |
|--------|-------------|
| `secretmanager_sync_failures_total{reason}` | Reconciles that left `Ready` False, by reason |
| `secretmanager_workload_restarts_total{kind}` | Deployments, StatefulSets and DaemonSets restarted because a synced Secret changed, by kind |

With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` to match your Prometheus selector) to create a `ServiceMonitor`.

## Logs

Logs are JSON on stderr. `--log-level` (chart value `logLevel`) sets the level: `debug`, `info` (default), `warn` or `error`. Unexpected errors are logged as `secret operation failed` with the request `method`, `url` and secret `path`.

## Audit log

Changes, backups, sign-ins, CLI logins and failed authentications are logged as a JSON line with `"msg":"audit"`; reads can be too, see [Event categories](#event-categories):

```json
{"level":"INFO","msg":"audit","source":"api","op":"set","remote":"10.42.0.7:51234","forwarded_for":"203.0.113.9","path":"/tools","keys":["GITHUB_TOKEN"]}
{"level":"WARN","msg":"audit","source":"ui","op":"login","remote":"10.42.0.7:51240","error":"invalid token"}
```

Requests made with an integration token carry its name in `token`. `client` is the [client address](client-address.md) when trusted proxies resolve one that differs from `remote`. Key names are logged, values never are. Failed operations are logged at `WARN` with `error`. `forwarded_for` is the client supplied `X-Forwarded-For` header and is only as trustworthy as your reverse proxy or Ingress. Audited events are also kept on the Web UI [Audit](web-ui.md) page, which shows the newest 500, and saved in storage.

### Event categories

`--events` (chart value `events`) sets where each category goes, as comma-separated `category=level`, such as `--events reads=log,lists=log`. The levels are `none` (dropped), `log` (the JSON log only) and `audit` (the JSON log, the Audit page and storage). Categories not named keep their default. The server logs the levels in use on start, as `events` in the `starting secret-manager` line.

| Category | Levels | Default | `op` |
|----------|--------|---------|------|
| `reads` | `none`, `log`, `audit` | `none` | `read`: every `GET /api/v1/secrets` and `GET /api/v1/secrets/{key}` with the key names returned (and `recursive`), and every Web UI path page view with source `ui`; `export`: every Web UI download of a path, with source `ui`; `read_version`: every `GET /api/v1/history/{version}` with the `version` |
| `lists` | `none`, `log`, `audit` | `none` | `info` (`GET /api/v1/info`), `list_paths` (`GET /api/v1/paths`), `list_deleted_paths` (`GET /api/v1/paths?deleted=true`), `list_history` (`GET /api/v1/history`, with the `path`) |
| `logins` | `log`, `audit` | `audit` | `login` (Web UI sign-in), `authorize` (a CLI login approved or denied in the Web UI), `authorize_start` (a CLI device login started, with the requested `name`), `authorize_token` (a CLI login code that is invalid, expired or denied) |
| `backups` | `log`, `audit` | `audit` | `backup` (API, Web UI download with source `ui`, or scheduled with source `schedule`), `restore` |

Every other event is always audited: `set`, `delete_key`, `delete_path`, `create_path`, `copy_path` and `move_path` (with the target in `to`), `rollback`, `delete_version` (with the `version`), `create_token`, `update_token`, `revoke_token` (with the integration `name`) and `auth` (API bearer token rejected, including expired tokens and requests an integration is not allowed to make).

`get`, `export` and `run` served from the [offline cache](cli.md#offline-cache) do not reach the server and are not logged. Reads can far outnumber changes, so with `reads=audit` the Audit page may show only recent reads; `reads=log` keeps them out of it.
