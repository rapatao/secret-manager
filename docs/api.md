# API

All endpoints except `/healthz`, `/readyz` and the two login endpoints require `Authorization: Bearer <token>`, an [integration](integrations.md) token allowed to use the endpoint and path. The admin token is not accepted.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/info` | `{"version": "v1.4.0", "capabilities": [...]}`, see [Compatibility](#compatibility) |
| `GET` | `/api/v1/generate?format=F&length=N&count=C` | `{"values": [...]}`, random values that are not saved, as [`secret-manager generate`](cli.md#generating-values) makes them; `format` defaults to `alnum`, `count` to 1, up to 100. Any token can call it, whatever its path. `400` for an unknown format or a length or count out of range |
| `GET` | `/api/v1/paths?deleted=true` | `{"paths": [...]}`; with `deleted=true`, the deleted paths that still have versions |
| `GET` | `/api/v1/secrets?path=P&recursive=true` | `{"data": {"KEY": "value"}, "cacheMaxAge": 604800}`, `cacheMaxAge` in seconds, see [Offline cache](cli.md#offline-cache) |
| `GET` | `/api/v1/secrets/{key}?path=P&recursive=true` | Same, with only that key in `data`; `404` when P or the key does not exist |
| `PUT` | `/api/v1/secrets?path=P` | Merge a JSON object of string values into P; `400` for an invalid key or a value starting with `enc:v1:` |
| `DELETE` | `/api/v1/secrets/{key}?path=P` | Delete one key |
| `DELETE` | `/api/v1/paths?path=P` | Delete a path (nested paths are kept) |
| `POST` | `/api/v1/paths/copy?path=P&to=Q` | Copy P and its versions to the new path Q; `400` when Q has data or versions, or when a version of P cannot be decrypted (nothing is written) |
| `POST` | `/api/v1/paths/move?path=P&to=Q` | Copy, then delete P and its versions; `400` as for copy |
| `GET` | `/api/v1/backup?history=true` | `{"format": 1, "version": "...", "time": "...", "paths": [{"path": "/a", "data": {...}, "versions": [...]}]}`, `versions` only with `history=true` |
| `POST` | `/api/v1/restore` | Restore a backup document, returns `{"paths": N}`. `400` when the document is not a backup, has another format, or holds an invalid path, key or value, in the paths or their versions: nothing is written. A storage error while writing stops the restore with `500` after the earlier paths were restored, see [Backup](backup.md) |
| `GET` | `/api/v1/sync-policy` | The [sync policy](secretsync.md#sync-policy): `{"enabled": true, "namespaces": {"team-a": {"paths": ["/apps/team-a"], "targetNamespaces": ["team-b"]}}}`. The `X-Sync-Policy-Digest` response header holds the digest of the stored policy, which `PUT` takes as `base`. Needs a token for `/`; `404` on a server without the `sync-policy` capability |
| `PUT` | `/api/v1/sync-policy?base=D&confirm=C` | Replace the policy with that JSON document, at most 1 MiB, unknown fields rejected; returns the stored policy and its digest in `X-Sync-Policy-Digest`. Needs a read-write token for `/`. `base` is required and is the digest the editor read with `GET`; `400` without it. When the stored policy has another digest, because it changed since it was read, the server answers `409` with `{"error": "..."}`, without `denied`, and saves nothing. The check is made under the policy lock and covers one server process, which is the supported single replica. `400` for an invalid policy, nothing is saved. When the policy is enabled, the controller runs and the new policy disallows SecretSyncs the stored one does not, the server answers `409` with `{"error": "...", "denied": ["namespace/name: reason"], "count": 1, "digest": "..."}` and saves nothing, unless `confirm` is that `digest`. The digest covers the new policy and the list, so it confirms exactly the preview that was returned: a `confirm` that is missing, made up, or from an earlier preview gets the same `409` with the current list and digest, and a changed policy or list changes the digest. The list is computed on every request. `500` when the policy cannot be loaded or previewed, nothing is saved |
| `GET` | `/api/v1/history?path=P` | `{"versions": [{"version": 3, "time": "...", "keys": [...]}]}`, newest first, without values; a version that cannot be decrypted has `"unreadable": true` and no `keys` |
| `GET` | `/api/v1/history/{version}?path=P` | `{"version": 3, "time": "...", "data": {"KEY": "value"}}`; `400` for a version that cannot be decrypted |
| `DELETE` | `/api/v1/history/{version}?path=P` | Delete that version; `404` when it does not exist |
| `POST` | `/api/v1/history/{version}/rollback?path=P` | Replace the data at P with that version; `400` for a version that cannot be decrypted |
| `POST` | `/api/v1/authorize/device` | Start a device login from `{"name": "cli-box"}`, returns `{"deviceCode": "...", "userCode": "ABCD-2345", "verificationUri": "/authorize?user_code=ABCD-2345", "expiresIn": 300, "interval": 2}`. No token needed |
| `POST` | `/api/v1/authorize/token` | Collect the token of an approved login, once: `{"code": "...", "codeVerifier": "..."}` for a loopback login, `{"deviceCode": "..."}` for a device login. Returns `{"name", "path", "readOnly", "expires", "token"}`; `400` with `authorization_pending` until a device login is approved, `403` with `access_denied` when denied. No token needed |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness: 503 when the storage backend cannot be read |

Paths look like `/a/b`, with segments of `[a-z0-9-]`. Keys match `[-._a-zA-Z0-9]+` and cannot be `.` or `..`. Values cannot start with `enc:v1:`, see [Keys and values](storage.md#keys-and-values).

A loopback login starts in the browser at `/authorize?redirect_uri=http://127.0.0.1:PORT/callback&state=S&code_challenge=C&name=N`, where `C` is the base64url SHA-256 of the client's verifier. `redirect_uri` must be `http` on `127.0.0.1`, `::1` or `localhost` with a port. After approval the browser is redirected to `redirect_uri?code=...&state=S`, or `?error=access_denied&state=S`. Pending logins live in the server's memory for 5 minutes, at most 100 at a time, and are lost on restart.

## Compatibility

Clients and servers of different versions work together, as long as the server has the features a command uses.

`GET /api/v1/info` lists those features as capabilities: `paths`, `secrets`, `history`, `history-delete`, `backup`, `integrations`, `paths-copy`, `paths-deleted`, `secrets-key`, `generate` and, when the server holds a sync policy, `sync-policy`. A command that needs a feature checks its capability first and fails with `server v1.2.0 at URL does not support X; upgrade the server`. `get KEY` against a server without `secrets-key` reads the whole path and keeps only that key on the client. Servers without `/api/v1/info` are treated as having `paths`, `secrets` and `history`, and their version is shown as unknown. A capability never changes meaning; changed behavior gets a new capability.

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
capabilities: backup, generate, history, history-delete, integrations, paths, paths-copy, paths-deleted, secrets, secrets-key
```
