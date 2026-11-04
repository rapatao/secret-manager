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
| `refreshInterval` | Resync period, default `60s`. |
| `targets[].name` / `namespace` | Secret to write. `namespace` defaults to the SecretSync namespace. |
| `targets[].creationPolicy` | `Owner` (default) deletes the Secret when the SecretSync or the target is removed. `Orphan` keeps it. |
| `targets[].type` | Secret type, default `Opaque`. |
| `targets[].metadata` | Labels and annotations set on the Secret. |
| `targets[].template.data` | Go templates for each key; `{{ .KEY }}` reads a source value. Without a template, every key is copied. |

The controller never overwrites a Secret it did not create; the `Ready` condition reports the conflict instead. `kubectl get secretsync` shows `Ready` and `Reason`.

`kubectl describe secretsync` lists events: `Synced` when a target Secret is created or updated, `WorkloadsRestarted` when workloads are restarted, and a `Warning` with the condition reason (`SourceError`, `SyncFailed`) when a sync starts failing or its error changes.

## Restarting workloads

Annotate a Deployment, StatefulSet or DaemonSet to restart it whenever a synced Secret it references (`envFrom`, `env.valueFrom`, `volumes`, projected volumes) changes:

```yaml
metadata:
  annotations:
    secretmanager.rapatao.com/auto-reload: "true"
```
