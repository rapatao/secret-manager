# Local vault

A local vault is a file on your machine holding paths and their versions, used by the CLI and the Web UI without a running server. Its server URL is `file://` followed by the file path:

```sh
secret-manager servers login --server file://$HOME/.secrets/vault.json   # create or unlock, prompts for the passphrase
secret-manager servers login --server file://$HOME/.secrets/vault.json --lock-after 2h   # stay unlocked for 2h, or never
secret-manager servers lock                           # lock the default vault now
echo "$PASSPHRASE" | secret-manager servers login --server file://$HOME/.secrets/vault.json --token-stdin

secret-manager set --path /tools GITHUB_TOKEN=abc
secret-manager run --path /tools -- make updates
secret-manager ui                                     # Web UI of the default vault
secret-manager ui --server file://$HOME/.secrets/vault.json --addr 127.0.0.1:8090 --no-browser
```

`servers login` creates the vault when the file is missing, asking for the passphrase twice; the passphrase has at least 8 characters. It derives the vault key from the passphrase with Argon2id (3 passes, 64 MiB, 4 threads, random salt; the parameters and salt are stored in the file) and stores the key like a token, in the OS keychain or in `credentials.json`, so later commands do not prompt until the vault [locks](#lock). Logging in again with a wrong passphrase fails. `servers logout` removes the stored key; the vault and its passphrase stay.

## Lock

A vault stays unlocked for 8 hours after its passphrase is given, then locks: the next command removes the stored key and prompts for the passphrase on the terminal, unlocks the vault for another 8 hours and carries on. Without a terminal, as in cron or a pipe with no `/dev/tty`, it fails with `vault ... is locked; run servers login --server file://...`. The time counts from the unlock, not from the last use, and a command already running, such as `run` or `ui`, is not stopped.

`servers login --lock-after` sets how long the vault stays unlocked, as a Go duration (`30m`, `24h`) or `never`. The setting is kept in `config.json` and reused by later logins without `--lock-after`. A vault logged in before locks existed gets the 8 hour default, counted from its next use. `servers lock` removes the stored key now, so the next command prompts. The lock only applies to stored logins: a vault key given in `SECRET_MANAGER_TOKEN` never locks.

The lock is enforced by the CLI. Until a vault locks, its key stays in the OS keychain or `credentials.json`, readable by anything with access to them, and a locked vault has no key stored.

Every command works on a vault, run in-process: values are encrypted with AES-256-GCM as with [encryption](storage.md#encryption), the last 10 versions of each path are kept as [history](history.md), and [backups](backup.md) work the same. Integration tokens and audit events are not kept in the vault: every command and `ui` run uses its own read-write integration, and the Integrations and Audit log pages only show those of the current `ui` run. The [offline cache](cli.md#offline-cache) is not used.

`ui` serves the Web UI of the vault on a loopback address (`--addr`, default `127.0.0.1` on a random port) until Ctrl-C, and opens a sign-in link in the browser. The link works once, within a minute; `--no-browser` only prints it. Run `ui` again to sign in from another browser. For a remote server, `ui` opens its Web UI, which signs in with the admin token, without needing a login.

A vault can be used by several commands at once, including while `ui` runs: each request takes a lock on `<file>.lock` next to the vault and reads the file again. Local vaults need macOS, Linux or another Unix system. To use a vault without a stored login, set `SECRET_MANAGER_URL` to its `file://` URL and `SECRET_MANAGER_TOKEN` to the base64 vault key.

The vault path can be a symlink, as made by dotfile managers such as yadm alternates: writes replace the file it points to and keep the link. The file can be copied to another machine and unlocked there with the same passphrase. A lost passphrase loses the data; there is no way to change it.
