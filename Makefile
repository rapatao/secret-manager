VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= secret-manager:$(VERSION)

.PHONY: all generate test lint build docker helm-lint check-generated

all: generate lint test build

generate:
	go tool controller-gen object paths=./api/...
	go tool controller-gen crd paths=./api/... output:crd:dir=charts/secret-manager/crds

test:
	go test -race ./...

lint:
	golangci-lint run ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/secret-manager ./cmd/secret-manager

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

helm-lint:
	helm lint charts/secret-manager --set auth.existingSecret=token

check-generated: generate
	git diff --exit-code -- api charts/secret-manager/crds
