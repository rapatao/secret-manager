# Integrations

An integration is a token (`smt_...`) for API clients: the CLI, CI jobs, other machines, `secret-manager run`. The API accepts only integration tokens; the admin token signs in to the Web UI.

| Setting | Values |
|---|---|
| Name | `[a-z0-9-]`, up to 63 characters, unique. Fixed once created |
| Path | A path; the integration covers it and every path nested below it |
| Read-only | Reads only, or reads and writes |
| Expires | 7, 30 or 90 days, 1 year, the end of a chosen day (UTC), or never |
| Offline cache | Server default (`--cache-max-age`), disabled, 1 hour, 1, 7 or 30 days: how long the CLI may use the secrets it read while the server is unreachable |
| Allowed addresses | Optional, comma-separated addresses or CIDRs (`10.0.0.0/8, 192.168.1.5`). Empty accepts the token from any address |

What an integration can do:

| Operation | Path `P` | Path `/` |
|---|---|---|
| `info`, `list` (only paths under its path) | yes | yes |
| Read data, keys and history | under `P` | every path |
| Set and delete keys, delete paths and versions, roll back (not read-only) | under `P` | every path |
| Copy a path (not read-only) | from and to under `P` | every path |
| Move a path (not read-only) | from and to under `P` | every path |
| Backup | no | yes |
| Restore (not read-only) | no | yes |

A request outside the integration's scope, or from a [client address](client-address.md) outside its allowed addresses, gets `403` (`token ci is not allowed from 192.0.2.1`); an unknown, revoked or expired token gets `401`. Managing integrations and approving logins happen only in the Web UI.

## Creating integrations

- `servers login` creates one after approval in the browser, see [Servers and login](cli.md#servers-and-login).
- The Integrations page of the Web UI creates one after a confirmation dialog that shows its name, path, access, expiry, offline cache and allowed addresses. The token is shown once. Use it with `SECRET_MANAGER_URL` and `SECRET_MANAGER_TOKEN`, or `servers login --token-stdin`.

The server keeps only the SHA-256 hash of each token, in the storage backend (a Secret named `sm-tokens` with the `kubernetes` backend). Integrations are loaded once and kept in memory, so changes made directly on the stored tokens need a server restart.

## Managing integrations

The Integrations page lists every integration with its path, access, creation time, expiry, offline cache and last use. Expired integrations stay listed, marked expired, until revoked.

- Edit changes the path, read-only access, expiry, offline cache and allowed addresses, keeping the token. The expiry can stay as it is or take any of the values above. Save opens a confirmation dialog listing the current and new values; clients get the new access on their next request. Save without changes closes the dialog. Cancel with unsaved changes asks whether to discard them or keep editing, and Cancel in the confirmation dialog discards the edit.
- Revoke deletes the integration after a confirmation dialog.

The last use is tracked in memory and saved every `--last-used-flush` (default `30m`) and on shutdown. It can lag behind, and a crash loses the uses since the last save.
