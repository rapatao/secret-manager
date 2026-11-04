# CLI

Install the CLI with Go, or build it with `make build`. A `go install` build reports its version as `dev`; `make build` uses `git describe`:

```sh
go install github.com/rapatao/secret-manager/cmd/secret-manager@latest
```

```sh
secret-manager servers login --server https://secrets.example.com   # approve in the browser, see Servers and login

secret-manager list
secret-manager set --path /tools GITHUB_TOKEN=abc OTHER=1
secret-manager set --path /tools --env-file .env       # or --env-file - for stdin
secret-manager set --path /db --generate PASSWORD      # 32 random letters and digits
secret-manager set --path /db --generate PIN:6         # 6 random letters and digits
secret-manager keys --path /tools                      # key names, no values
secret-manager keys --path /tools --recursive          # PATH KEY for every nested path
secret-manager get --path /tools GITHUB_TOKEN          # only this key leaves the server
secret-manager get --path /tools --recursive           # dotenv output
secret-manager export --path /tools --format json
secret-manager delete --path /tools OTHER
secret-manager delete --path /tools --all
secret-manager copy --path /tools --to /tools-backup   # data and history, see History
secret-manager move --path /tools --to /shared/tools
secret-manager run --path /tools -- make updates
secret-manager history --path /tools                   # list versions
secret-manager history --path /tools 3                 # print version 3 as dotenv
secret-manager history --path /tools --delete 3        # delete version 3, see History
secret-manager rollback --path /tools 3
secret-manager backup --history --output backup.json  # every path and its versions, see Backup
secret-manager restore backup.json
SECRET_MANAGER_BACKUP_KEY=... secret-manager backup    # encrypted backup, see Backup
secret-manager version                                 # client and server versions, server capabilities
secret-manager ui                                      # open the Web UI of the default server
```

## Servers and login

Log in once per server:

```sh
secret-manager servers login --server https://secrets.example.com             # approve in a browser on this computer
secret-manager servers login --server https://secrets.example.com --device    # approve from any browser
echo "$TOKEN" | secret-manager servers login --server https://secrets.example.com --token-stdin
secret-manager servers                                # list logged-in servers, marks the default
secret-manager servers use https://secrets.example.com
secret-manager servers logout --server https://secrets.example.com
```

`servers login` creates an [integration](integrations.md) approved in the Web UI:

1. The CLI opens the server's approval page in the default browser. Sign in with the admin token if needed.
2. Pick the integration's name (default `cli-<hostname>`), path, access, expiry (default 90 days) and offline cache (default: server default), then Allow, or Deny.
3. The browser hands an authorization code to the CLI on `http://127.0.0.1:<random port>/callback`. The CLI exchanges it for the token with its PKCE verifier (RFC 7636). A code works once, and only with that verifier.

With `--device`, over SSH (`SSH_CONNECTION` is set) or when no browser can be opened, the CLI prints the approval page URL and a code like `ABCD-2345` instead. Open the URL in any browser, check that the page shows the same code, and approve; the CLI polls the server and picks up the token. A login not approved within 5 minutes fails.

`--token-stdin` stores an existing token instead, such as one created in the Web UI, after checking it against the server. Either way the server becomes the default. You can be logged in to several servers at once: `servers use` switches the default, and `--server` picks one for a single command. A request with an expired or revoked token fails with `401` and a hint to run `servers login` again.

Without a login, set `SECRET_MANAGER_URL` and `SECRET_MANAGER_TOKEN` to a server and an integration token, as in CI.

A `file://` server URL is a [local vault](local-vault.md), used without a running server.

Tokens are stored in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) under the service `secretmanager.rapatao.com`, one entry per server. Without a usable keychain, as on headless Linux, they fall back to `~/.config/secretmanager.rapatao.com/credentials.json` with `0600` permissions and a warning is printed. The list of servers and the default are kept in `config.json` in the same directory (`$XDG_CONFIG_HOME` is honored).

## Resolution order

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

## Offline cache

`get`, `export` and `run` keep the last secrets they read from each server, path and `--recursive` setting. `get KEY` reads only that key and merges it into the cached path, keeping the time the path was cached so older values still expire on time. A path cached only from `get KEY` serves those keys, not `get`, `export` or `run` of the whole path. When the server is unreachable (connection error, or a `502`, `503` or `504` from the Ingress), they use the cached secrets and print a warning with the time they were read. Any other answer, such as `401` or `404`, is reported as an error and the cache is not used. Writes do not update the cache; the next successful read does.

The server decides how long cached secrets may be used: the integration's offline cache setting, or the server's `--cache-max-age` (default 7 days). Each read returns that max age and the CLI stores it with the entry. A max age of `0` disables the cache for that integration: nothing is written, and the entry of the path read is removed. Servers that send no max age are treated as allowing 7 days.

`SECRET_MANAGER_CACHE_MAX_AGE` can only lower the server's max age, as a Go duration (`24h`, `30m`); `0` disables the cache, so nothing is written or read. Expired entries are removed when found.

Entries are encrypted with AES-256-GCM and stored in the `cache` directory next to `config.json`, `0600` files in a `0700` directory. The key is kept only in the OS keychain (account `offline-cache-key` under `secretmanager.rapatao.com`), so without a usable keychain nothing is cached. `servers logout` removes the cached secrets of that server; delete the `cache` directory to remove all of them.
