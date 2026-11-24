# SecretSync

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
| `sources[].recursive` | Also read nested paths. Paths are merged in alphabetical order, so on duplicate keys a nested path wins over its parents, and between sibling branches the later name wins (`/a/z` over `/a/b/c`). |
| `refreshInterval` | Resync period, default `60s`, at most `1h`. The CRD rejects a longer value, and the controller resyncs a longer value already stored every `1h`. Before Kubernetes 1.30 such a SecretSync cannot be updated until its `refreshInterval` is lowered, see [Install](install.md#kubernetes). |
| `targets[].name` / `namespace` | Secret to write. `namespace` defaults to the SecretSync namespace. |
| `targets[].creationPolicy` | `Owner` (default) deletes the Secret when the SecretSync or the target is removed. `Orphan` keeps it, except when the [sync policy](#sync-policy) disallows the SecretSync. |
| `targets[].type` | Secret type, default `Opaque`. |
| `targets[].metadata` | Labels and annotations set on the Secret. Keys under `secretmanager.rapatao.com/` are reserved and rejected, see [Reserved names and metadata](#reserved-names-and-metadata). |
| `targets[].template.data` | Go templates for each key; `{{ .KEY }}` reads a source value. Without a template, every key is copied. |

The controller never overwrites a Secret it did not create; the `Ready` condition reports the conflict instead. `kubectl get secretsync` shows `Ready` and `Reason`.

`kubectl describe secretsync` lists events: `Synced` when a target Secret is created or updated, `WorkloadsRestarted` when workloads are restarted, `Released` when a target Secret is deleted because the [sync policy](#sync-policy) disallows the SecretSync, and a `Warning` with the condition reason (`SourceError`, `SyncFailed`, `NotAllowed`) when a sync starts failing or its error changes.

## Sync policy

The controller reads secret values with the server's own access, so whoever can create a SecretSync in the cluster chooses which paths it reads and which namespaces it writes to. Without a policy, a SecretSync can read any path and write Secrets in any namespace. The sync policy limits this. It is disabled by default, which leaves SecretSyncs unrestricted.

The policy is stored by the server and edited in the Web UI, on the Sync policy page, see [Web UI](web-ui.md#sync-policy), or with `secret-manager sync-policy get` and `set`, see [CLI](cli.md#sync-policy) and [API](api.md). Both paths preview the change and ask for confirmation before it deletes Secrets. There is no CRD or Helm value for it.

When the policy is enabled:

- The SecretSync namespace must be listed. A namespace with no entry, or an entry with no paths, syncs nothing.
- Every source path must be equal to or under one of the paths listed for the namespace. A recursive source follows the same rule on its root path.
- A target in another namespace needs that namespace listed as a target namespace. A target in the SecretSync's own namespace (including an empty `namespace`) is always allowed.

Warning: enabling the policy takes effect immediately. Every SecretSync whose namespace, sources or targets are not allowed loses all its target Secrets, Orphan ones included. With an empty policy, enabling it deletes the targets of every SecretSync in the cluster. List the namespaces, paths and target namespaces first, then enable the policy.

One violation in any source or target disallows the whole SecretSync. The `Ready` condition becomes `False` with reason `NotAllowed` and the violation as the message, a `Warning` event is emitted, and the controller reads no values and creates or updates no target Secrets. It also deletes every Secret the SecretSync owns, in every namespace, including targets with `creationPolicy: Orphan`. Secrets that exist under the same name but were not created by the SecretSync are not touched. A `Released` event and a log line record each deleted Secret. Deleting a SecretSync always follows `creationPolicy`, even while it is disallowed: `Owner` targets are deleted and `Orphan` targets are detached and kept. If a deletion fails, the reconcile returns the error and retries. If the policy cannot be loaded, the controller changes nothing and retries.

The policy is checked on every reconcile. Saving it queues every SecretSync for a reconcile at once when the controller runs, so a change applies promptly. The request does not depend on the queue of changed paths, and repeated saves before it is handled count once. When the SecretSyncs cannot be listed, the request is repeated after 5 seconds. Every reconcile that completes, including one that reports a disallowed or failing SecretSync, schedules the next one at the SecretSync's `refreshInterval`, so each SecretSync is checked again within its `refreshInterval`, at most 1 hour, at the latest. A reconcile that returns an error, such as a failed deletion or a policy that cannot be read, is retried with backoff instead. When a SecretSync is allowed again, the next reconcile recreates its targets.

Workloads are not changed when targets are removed:

- Running pods keep the environment variables and mounted files they already have.
- A pod restart, scale-up or node drain then fails with `CreateContainerConfigError` for Secrets used as environment variables, or stays in `ContainerCreating` for Secrets mounted as volumes.
- `auto-reload` does nothing on deletion.
- To recover, fix the policy. Saving it triggers a reconcile that recreates the Secrets.

## Reserved names and metadata

The server and the controller mark Secrets with labels and annotations under `secretmanager.rapatao.com/`. A target whose `metadata` has any such key is rejected, in every namespace, with the sorted keys in the message: the SecretSync goes `SyncFailed`, one `Warning` event is emitted and the Secret is not written. Rejected targets are not released: a Secret the SecretSync already wrote stays. When a SecretSync writes an existing target, it replaces the target's labels and annotations, which removes reserved keys added to it by others. When an `Orphan` target is detached, every key under `secretmanager.rapatao.com/` is removed, so a kept Secret never carries the server's labels.

With the `kubernetes` storage, the server keeps its own Secrets in its namespace, the release namespace. A target in that namespace cannot be named `sm`, `sm-tokens`, `sm-audit` or `sm-sync-policy`, or start with `sm.` or `smh.`; the SecretSync goes `SyncFailed` with the name reserved for the server's storage. Other names, including other `sm-*` names, are allowed. The same names are allowed in other namespaces, and with the `file` and `postgres` storage.

The server reads a Secret as its own only when it carries the label of its kind, its name matches, and it does not carry the `secretmanager.rapatao.com/owner` label that marks a SecretSync target. A `sm.*` Secret is a path only with the `store` label and the name of its path. The server refuses the Secrets that fail these checks, see [Secrets the server refuses](storage.md#secrets-the-server-refuses).

A target in the release namespace that uses a reserved name goes `SyncFailed` and is not updated. The Secret stays, and the server refuses it: path and version Secrets are ignored, while `sm-tokens`, `sm-audit` and `sm-sync-policy` make requests fail or stop the start, see [Secrets the server refuses](storage.md#secrets-the-server-refuses). Rename the target or move it to another namespace. With `creationPolicy: Owner` the old Secret is deleted on the next reconcile, once the target is no longer in the SecretSync's targets. An `Orphan` target is detached instead, losing its owner label and reserved keys, and must be deleted by hand.

## Restarting workloads

Annotate a Deployment, StatefulSet or DaemonSet to restart it whenever a synced Secret it references (`envFrom`, `env.valueFrom`, `volumes`, projected volumes) changes:

```yaml
metadata:
  annotations:
    secretmanager.rapatao.com/auto-reload: "true"
```

The Secret's hash is recorded only after the restart succeeds, so a failed restart is retried on the next resync.
