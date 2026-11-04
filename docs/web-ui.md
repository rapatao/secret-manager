# Web UI

Open the server URL, or run `secret-manager ui`, and sign in with the admin token. A [local vault](local-vault.md) has its own Web UI served by `secret-manager ui`. The header shows the server version next to the name, which links to the summary, and links to Secrets (`/secrets`, the path list), Integrations, Audit and Sign out. The UI follows the system light or dark theme and adapts to narrow screens: on phones, the integrations, recent changes, keys and history tables show each row as a list of labeled fields. Every time is shown in UTC as `YYYY-MM-DD HH:MM UTC`.

Summary
- The main page counts paths, keys, deleted paths and stored versions.
- It counts integrations: total, expired, expiring within 7 days, never used, and read-write on `/`.
- It lists the 10 latest versions across every path, deleted paths included, with the keys each one added (`+`), changed (`~`) or deleted (`-`).
- It shows the server settings: version, storage backend, encryption, SecretSync controller, history limit, offline cache default, scheduled backups and the result of the last scheduled backup since the server started.
- It reads every path and its history on each view.

Secrets
- The Secrets page lists every path; each one opens at `/secrets/path?path=<path>`.
- One field filters paths as you type, matching anywhere in the path. It opens the typed path when it exists, or creates it after a confirmation dialog.
- Deleted paths that still have versions are listed separately; restoring one of their versions brings them back.
- Deleting a path is in the collapsed danger zone of its page, and requires typing the path in a confirmation dialog.
- Copy or move, also in the danger zone, asks for the new path in a dialog and opens it afterwards, see [History](history.md).

Keys
- Values show as a fixed-length mask until Show opens the editor; an edited badge marks a value with unsaved changes. The copy button copies a value to the clipboard.
- Changed shows when each key was last added or changed, from the versions kept in history.
- Adding keys, editing values and deleting keys are staged on the page: a deleted key is struck through until saved, and Undo brings it back.
- A new key cannot reuse the name of an existing key or of another new key; existing keys change in their own row.
- Generate, under a value being added or edited, replaces it with 32 random letters and digits made in the browser.
- Save changes is enabled once something is staged. It opens a confirmation dialog listing the keys added (`+`), changed (`~`) and deleted (`-`) with their current and new values, and writes every staged change as one version.

History
- Each version can be compared with the current data and restored after a confirmation dialog, see [History](history.md).
- Compare picks any two versions, or a version and the current data, and shows the keys added, changed and deleted between them with their values. It opens with the version before the newest and the current data selected, and the chosen pair stays in the URL (`&from=2&to=current`).
- Each version can be deleted after a confirmation dialog.

Integrations and logins
- The Integrations page manages [integrations](integrations.md). `/authorize` approves or denies CLI logins, see [Servers and login](cli.md#servers-and-login).

Audit
- The Audit page (`/audit`) lists the newest 500 [audited](observability.md#event-categories) events, newest first: time, source, operation, integration, path, keys, client address and result.
- A filter shows only the events made with one integration's token or acting on that integration (created, updated, revoked, approved).
- The server saves them to the storage backend every minute and on shutdown, and loads them on start, so a crash loses at most the last minute of them. The JSON log holds every event.

The server rejects every change made without its confirmation, or with one that does not match. Filtering paths, editing keys, the copy button and the integration dialogs need JavaScript; browsers without invoker commands (`commandfor`) also use it to open the dialogs.

After 5 failed sign-ins from one address, each further attempt from it must wait 1 second, then 2, 4 and so on up to 1 minute, and gets `429` with `too many failed sign-ins, try again in Ns` until then. A successful sign-in, or 15 minutes without a failure, resets the count. The address is the [client address](client-address.md): without trusted proxies, every client behind an Ingress shares the Ingress address, so the wait never exceeds 1 minute. The counts live in the server's memory.

Sessions last 12 hours and survive server restarts; changing the admin token signs every session out. Signing out deletes the session cookie in the browser. The session cookie is `Secure`: use HTTPS (an Ingress with TLS) or `localhost`.
