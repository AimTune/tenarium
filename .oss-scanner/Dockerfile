# syntax=docker/dockerfile:1
#
# Build image for offline security auditing (Anthropic OSS Scanner), built
# with the repository as the build context. It keeps the checkout at /src,
# downloads every Go module of the three modules (the server, the
# Kubernetes operator and the Terraform provider), builds everything and
# compiles the tests, so the code can be built and tested without network
# access afterwards. Locally:
#
#   docker build -f .oss-scanner/Dockerfile -t tenarium-audit .
FROM golang:1.26-bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git make \
    && rm -rf /var/lib/apt/lists/*

# CGO is not needed; the toolchain in the image is the one go.mod asks for.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

RUN go mod download \
    && (cd operator && go mod download) \
    && (cd terraform-provider && go mod download)

# Build all packages and binaries, and compile every test package so later
# `go test` / `go vet` runs need nothing from the network.
RUN go build ./... \
    && go build -o /usr/local/bin/ ./cmd/... \
    && go vet ./... \
    && go test -count=1 -run '^$' ./... \
    && (cd operator && go build ./... && go test -count=1 -run '^$' ./...) \
    && (cd terraform-provider && go build ./... && go test -count=1 -run '^$' ./...)

# Run the tests that need no external services (integration tests skip
# without their TENARIUM_TEST_* variables); a failure does not abort the
# build.
RUN go test -count=1 -timeout 20m ./... || echo "WARNING: go test reported failures"

# Offline from here on.
ENV GOPROXY=off GOFLAGS="-mod=readonly"
