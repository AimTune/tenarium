# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/AimTune/tenarium/pkg/server.Version=${VERSION}" \
      -o /out/tenarium ./cmd/tenarium

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tenarium /usr/local/bin/tenarium
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/tenarium"]
CMD ["-config", "/etc/tenarium/config.yaml"]
