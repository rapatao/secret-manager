# API

All endpoints except `/healthz`, `/readyz` and the two login endpoints require `Authorization: Bearer <token>`, an [integration](integrations.md) token allowed to use the endpoint and path. The admin token is not accepted.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/info` | `{"version": "v1.4.0", "capabilities": [...]}`, see [Compatibility](#compatibility) |
| `GET` | `/api/v1/paths` | `{"paths": [...]}` |
| `GET` | `/api/v1/secrets?path=P&recursive=true` | `{"data": {"KEY": "value"}, "cacheMaxAge": 604800}`, `cacheMaxAge` in seconds, see [Offline cache](cli.md#offline-cache) |
| `PUT` | `/api/v1/secrets?path=P` | Merge a JSON object of string values into P |
| `DELETE` | `/api/v1/secrets/{key}?path=P` | Delete one key |
| `DELETE` | `/api/v1/paths?path=P` | Delete a path (nested paths are kept) |
| `POST` | `/api/v1/paths/copy?path=P&to=Q` | Copy P and its versions to the new path Q; `400` when Q has data or versions |
| `POST` | `/api/v1/paths/move?path=P&to=Q` | Copy, then delete P and its versions |
| `GET` | `/api/v1/backup?history=true` | `{"format": 1, "version": "...", "time": "...", "paths": [{"path": "/a", "data": {...}, "versions": [...]}]}`, `versions` only with `history=true` |
| `POST` | `/api/v1/restore` | Restore a backup document, returns `{"paths": N}` |
| `GET` | `/api/v1/history?path=P` | `{"versions": [{"version": 3, "time": "...", "keys": [...]}]}`, newest first, without values |
| `GET` | `/api/v1/history/{version}?path=P` | `{"version": 3, "time": "...", "data": {"KEY": "value"}}` |
| `DELETE` | `/api/v1/history/{version}?path=P` | Delete that version; `404` when it does not exist |
| `POST` | `/api/v1/history/{version}/rollback?path=P` | Replace the data at P with that version |
| `POST` | `/api/v1/authorize/device` | Start a device login from `{"name": "cli-box"}`, returns `{"deviceCode": "...", "userCode": "ABCD-2345", "verificationUri": "/authorize?user_code=ABCD-2345", "expiresIn": 300, "interval": 2}`. No token needed |
| `POST` | `/api/v1/authorize/token` | Collect the token of an approved login, once: `{"code": "...", "codeVerifier": "..."}` for a loopback login, `{"deviceCode": "..."}` for a device login. Returns `{"name", "path", "readOnly", "expires", "token"}`; `400` with `authorization_pending` until a device login is approved, `403` with `access_denied` when denied. No token needed |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness: 503 when the storage backend cannot be read |

Paths look like `/a/b`, with segments of `[a-z0-9-]`. Keys match `[-._a-zA-Z0-9]+`.

A loopback login starts in the browser at `/authorize?redirect_uri=http://127.0.0.1:PORT/callback&state=S&code_challenge=C&name=N`, where `C` is the base64url SHA-256 of the client's verifier. `redirect_uri` must be `http` on `127.0.0.1`, `::1` or `localhost` with a port. After approval the browser is redirected to `redirect_uri?code=...&state=S`, or `?error=access_denied&state=S`. Pending logins live in the server's memory for 5 minutes, at most 100 at a time, and are lost on restart.

## Compatibility

Clients and servers of different versions work together, as long as the server has the features a command uses.

`GET /api/v1/info` lists those features as capabilities: `paths`, `secrets`, `history`, `history-delete`, `backup`, `integrations` and `paths-copy`. A command that needs a feature checks its capability first and fails with `server v1.2.0 at URL does not support X; upgrade the server`. Servers without `/api/v1/info` are treated as having `paths`, `secrets` and `history`, and their version is shown as unknown. A capability never changes meaning; changed behavior gets a new capability.

Authentication depends on the `integrations` capability:

| Server | API token | CLI login |
|---|---|---|
| With `integrations` | An integration token | `servers login` in the browser, or `--token-stdin` with an integration token |
| Without `integrations` | The admin token | `servers login --token-stdin` with the admin token; browser login fails with `server does not support browser login; upgrade it or log in with --token-stdin` |

A CLI without browser login works against a server with `integrations` using an integration token, through `SECRET_MANAGER_TOKEN` or its `servers login` prompt.

`secret-manager version` prints the client version and, when a server is set (see [Resolution order](cli.md#resolution-order)), the server version and capabilities:

```
client: v1.5.0
server: v1.4.0 (https://secrets.example.com)
capabilities: backup, history, history-delete, integrations, paths, paths-copy, secrets
```
