# Contributing

Thanks for your interest in Tenarium!

## Setup

You need Go (see `go.mod` for the version) and Docker for integration tests. Node 22.6+ and
Python 3.9+ are optional; they run the external plugin SDK tests.

```sh
make test               # fast unit tests (-short)
make test-db            # throwaway PostgreSQL on localhost:55432
make test-integration   # full suite, including PostgreSQL
make lint               # golangci-lint
```

Optional integration tests:

| Env var | Enables |
|---|---|
| `TENARIUM_TEST_POSTGRES_DSN` | PostgreSQL store, end-to-end tests with two replicas, `postgres-tenant` |
| `TENARIUM_TEST_KAFKA_BROKERS` | Kafka publishing (`docker compose up -d redpanda`, then `localhost:19092`) |
| `TENARIUM_TEST_LDAP_URL` | LDAP against a real directory (see `plugins/ldap` tests) |
| `TENARIUM_TEST_REDIS_ADDR` | Redis publishing, cache and ACLs (`docker run -p 56379:6379 redis:7-alpine`) |
| `TENARIUM_TEST_SMTP_ADDR` | SMTP against Mailpit (`docker run -p 11025:1025 axllent/mailpit`) |
| `TENARIUM_TEST_KEYCLOAK_URL` | Keycloak provisioning against a real server |
| `TENARIUM_TEST_REMOTE_PLUGIN_URL` | external plugin conformance against a running plugin |
| `TENARIUM_TEST_S3_ENDPOINT` | `s3-tenant` against S3 (e.g. `docker run -p 18333:8333 chrislusf/seaweedfs server -s3`, then `localhost:18333`; `TENARIUM_TEST_S3_ACCESS_KEY`/`_SECRET_KEY` default to any) |
| `TENARIUM_TEST_KUBECONFIG` | `kubernetes-tenant` against a real cluster (kind, k3d); otherwise a fake clientset is used |
| `TENARIUM_TEST_PYTHON` | runs the Python SDK plugin examples from the Go tests (path to a Python 3.9+ interpreter) |

Other plugins have their own integration tests, gated by variables named after the service:
`TENARIUM_TEST_MYSQL_DSN`, `_MONGODB_URI`, `_CLICKHOUSE_URL`, `_OPENSEARCH_URL`, `_GRAFANA_URL`,
`_RABBITMQ_URL`, `_NATS_URL`, `_VAULT_ADDR`, `_OPENFGA_URL`, `_SPICEDB_URL`, `_OPA_URL`,
`_GCS_ENDPOINT`, `_AZURE_CONNECTION_STRING`, `_AZURE_SERVICEBUS_CONNECTION_STRING`,
`_PUBSUB_EMULATOR`, `_AWS_ENDPOINT`, `_ROUTE53_ENDPOINT`, `_CLOUDFLARE_API_TOKEN`,
`_S3_IAM_ENDPOINT`, `_PEBBLE_URL` (ACME), `_TERRAFORM_BIN` and more. Each plugin's
`*_test.go` (or README) lists the variables it reads and how to start the service; see also
[docs/testing.md](docs/testing.md).

## Documentation

The documentation is the Markdown in [docs/](docs), published at
<https://tenarium.aimtune.dev> by a Docusaurus site in [website/](website) (Node 22):

```sh
cd website && npm ci && npm start    # live preview on http://localhost:3000 (or: make docs-serve)
cd website && npm run build          # what CI runs (or: make docs)
```

The build fails on broken links and anchors. Link to other pages with relative `.md` paths
(`users.md#impersonation`) and use the heading ids that GitHub and Docusaurus generate. Pages are
added to the sidebar in `website/sidebars.ts`. The site also has a Turkish locale (`/tr/`): the
landing page, navigation and theme strings are translated in `website/i18n/tr/`, while the docs
themselves are shown in English. The API reference at `/api/` renders
`internal/api/openapi.yaml` with Redoc, copied in by `website/scripts/prepare-api.mjs`.

## Guidelines

- **`pkg/sdk` is the stable contract.** Changes there need extra care: adding is fine, but
  changing or removing breaks third-party plugins. Everything in `internal/` can change freely.
- **Both stores must pass the conformance suite** (`internal/store/storetest`). New store
  methods need tests there.
- **API changes update `internal/api/openapi.yaml`.** A test fails if a route is missing from
  the spec.
- **Plugins** live in `plugins/<name>`, register themselves in `init`, provide a
  `ConfigSchema`, are added to `plugins/all`, and are documented in `docs/plugins/README.md`.
  Test them with `pkg/sdk/sdktest`.
- Keep comments short and explain *why*. Run `gofmt`.

## Commits and pull requests

Small, focused pull requests with a clear description are easiest to review. Include tests for
behaviour changes and mention any compatibility impact.
