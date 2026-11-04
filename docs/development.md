# Development

Requires the Go version in `go.mod`, `golangci-lint` v2 and `helm`.

```sh
make generate   # deepcopy and CRD (controller-gen, pinned as a go tool)
make test
make lint
make build      # bin/secret-manager
make run        # local server on :8080, file storage in .local/, no cluster
make docker
make helm-lint
make check-generated   # fails if generated files are out of date
```

## CI and releases

- `ci.yaml` runs on pushes to `main` and on pull requests: generated files check, tests, lint, build, chart lint, and a multi-arch image build without push.
- `release.yaml` runs on `v*` tags. It pushes `linux/amd64` and `linux/arm64` images tagged with the version and `major.minor`, then the Helm chart as an OCI artifact. The image goes to `ghcr.io/rapatao/secret-manager` and the chart to `oci://ghcr.io/rapatao/charts/secret-manager`, using `GITHUB_TOKEN`. The chart's `version` and `appVersion` are set from the tag (`v1.2.0` becomes `1.2.0`). After the image and chart are pushed, it creates a release for the tag. The notes list the commit subjects since the previous tag.
