FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/secret-manager ./cmd/secret-manager

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/secret-manager /secret-manager
USER 65532:65532
ENTRYPOINT ["/secret-manager"]
CMD ["server"]
