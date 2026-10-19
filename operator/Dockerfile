# syntax=docker/dockerfile:1
# Build from the repository root, because the operator module uses the
# parent module through a replace directive:
#
#   docker build -f operator/Dockerfile -t tenarium-operator .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY operator/go.mod operator/go.sum ./operator/
RUN cd operator && go mod download
COPY . .
RUN cd operator && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/manager ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/manager /manager
USER 65532:65532
ENTRYPOINT ["/manager"]
