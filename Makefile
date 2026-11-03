VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= secret-manager:$(VERSION)

DEV_STORE ?= .local/store.json
DEV_TOKEN ?= local-development-token-not-for-production

.PHONY: all generate test lint build run docker helm-lint check-generated

all: generate lint test build

generate:
	go tool controller-gen object paths=./api/...
	go tool controller-gen crd paths=./api/... output:crd:dir=charts/secret-manager/crds

test:
	go test -race ./...

lint:
	golangci-lint run --timeout=10m ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/secret-manager ./cmd/secret-manager

run: build
	@mkdir -p $(dir $(DEV_STORE))
	@echo "export SECRET_MANAGER_URL=http://localhost:8080 SECRET_MANAGER_TOKEN=$(DEV_TOKEN)"
	SECRET_MANAGER_TOKEN=$(DEV_TOKEN) bin/secret-manager server --storage=file --file=$(DEV_STORE) --controller=false --log-level=debug

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

helm-lint:
	helm lint charts/secret-manager --set auth.existingSecret=token

check-generated: generate
	git diff --exit-code -- api charts/secret-manager/crds
