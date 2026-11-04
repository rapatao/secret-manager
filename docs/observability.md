# Observability

## Metrics

Prometheus metrics are served on `:8081/metrics` (`--metrics-addr`, `0` disables them) and exposed on the Service port `metrics`. Besides the controller-runtime and Go runtime metrics (`controller_runtime_reconcile_total`, `workqueue_depth`, ...), the server exports:

| Metric | Description |
|--------|-------------|
| `secretmanager_sync_failures_total{reason}` | Reconciles that left `Ready` False, by reason |
| `secretmanager_workload_restarts_total{kind}` | Deployments, StatefulSets and DaemonSets restarted because a synced Secret changed, by kind |

With the Prometheus Operator, set `metrics.serviceMonitor.enabled=true` (and `metrics.serviceMonitor.labels` to match your Prometheus selector) to create a `ServiceMonitor`.

## Logs

Logs are JSON on stderr. `--log-level` (chart value `logLevel`) sets the level: `debug`, `info` (default), `warn` or `error`. Unexpected errors are logged as `secret operation failed` with the request `method`, `url` and secret `path`.

## Audit log

Every change made through the API or the Web UI, every backup, every Web UI login and every failed authentication is logged as a JSON line with `"msg":"audit"`:

```json
{"level":"INFO","msg":"audit","source":"api","op":"set","remote":"10.42.0.7:51234","forwarded_for":"203.0.113.9","path":"/tools","keys":["GITHUB_TOKEN"]}
{"level":"WARN","msg":"audit","source":"ui","op":"login","remote":"10.42.0.7:51240","error":"invalid token"}
```

`op` is one of `read` and `read_version` (only with `--audit-reads`), `set`, `delete_key`, `delete_path`, `create_path`, `copy_path` and `move_path` (with the target in `to`), `rollback`, `delete_version` (with the `version`), `backup`, `restore`, `create_token`, `update_token`, `revoke_token` (with the integration `name`), `authorize` (a CLI login approved or denied in the Web UI), `login` and `auth` (API bearer token, including expired tokens and requests an integration is not allowed to make). Requests made with an integration token carry its name in `token`. `client` is the [client address](client-address.md) when trusted proxies resolve one that differs from `remote`. Key names are logged, values never are. Failed operations are logged at `WARN` with `error`. `forwarded_for` is the client supplied `X-Forwarded-For` header and is only as trustworthy as your Ingress. Reads are not logged unless the server runs with `--audit-reads` (chart value `auditReads`): then every `GET /api/v1/secrets` is logged as `read` with the key names returned (and `recursive`), every `GET /api/v1/history/{version}` as `read_version` with the `version`, and every Web UI path page view as `read` with source `ui`. `get`, `export` and `run` served from the [offline cache](cli.md#offline-cache) do not reach the server and are not logged. Reads can far outnumber changes, so the Audit page, which keeps the newest 500 events, may then show only recent reads. The newest events are also shown on the Web UI [Audit](web-ui.md) page.
