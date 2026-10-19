# Fuzz reproducers

Failing inputs found by the Go fuzz targets (`*_fuzz_test.go`) for bugs in
non-test code that are not fixed yet. They live here, outside the packages'
`testdata/fuzz` directories, so the default `go test ./...` keeps passing
until the owner fixes the code.

Layout: `<package path>/<FuzzTarget>/<corpus file>`.

To reproduce, copy the directory into the package's `testdata/fuzz` and run
the target. Go runs every file in `testdata/fuzz/<FuzzTarget>` as a regular
test:

```sh
mkdir -p internal/netguard/testdata/fuzz
cp -r tests/fuzz/reproducers/internal/netguard/FuzzCheckAddr internal/netguard/testdata/fuzz/
go test -run 'FuzzCheckAddr/232faa68ba2f422e' ./internal/netguard
```

After the fix, move the file into the package's `testdata/fuzz` for good,
so it stays a regression test, and delete it here.

| Reproducer | Bug |
|---|---|
| `internal/netguard/FuzzCheckAddr/232faa68ba2f422e` (`::0%0`) | `CheckAddr` lets an unspecified IPv6 address with a zone through: `netip.Addr.IsUnspecified` is false for `::%eth0`. A webhook or SSO URL such as `https://[::%25eth0]/` passes `CheckHost` and the dial-time check, and connecting to `::` reaches the local host on Linux (SSRF). Fix: check `ip.WithZone("")`. |
| `internal/netguard/FuzzCheckHost/b58422bc2bded60d` (`//LoCAlhost`) | `CheckHost` compares `localhost` case-sensitively (and does not strip a trailing dot), so `https://LOCALHOST/` or `https://localhost./` is accepted when the URL is registered. The dial-time address check still blocks the connection, so this is defence in depth only. |
| `pkg/extplugin/FuzzHandler/9ad6aa12eb6739b2` | `handleAuthenticate` ignores the error of `http.NewRequestWithContext`. An `AuthenticateRequest` with an invalid method (e.g. `" "`) or an unparsable path gives a nil request, and `in.Header = ...` panics (nil pointer). `net/http` recovers the panic per connection, but the plugin logs a stack trace and drops the connection instead of answering 400. |
| `plugins/external/FuzzInitResponse/993ce92c45511245` (found by the fuzzer: route `""`), `bad-pattern`, `dup-route` (hand-written) | An external plugin's init response can crash Tenarium at startup. Route patterns are not validated when registered, and `api.Server.Handler` (`mountPluginRoutes`) calls `ServeMux.Handle`, which panics on an invalid pattern (`GET /{x`) or on two conflicting ones (`/a`, `/a`). The process dies with a panic instead of refusing the plugin. Confirmed end to end with `go run ./cmd/tenarium` and a remote plugin answering `{"protocol":1,"routes":["GET /{x"]}`. Fix: validate patterns (or mount them under `recover`) in the registrar or in `external.register`, and return an error from `Init`. |
