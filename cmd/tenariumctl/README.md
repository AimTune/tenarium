# tenariumctl

`tenariumctl` is the command-line client for the Tenarium API. It is built
on [`pkg/client`](../../pkg/client) and uses only the Go standard library.

```sh
go install github.com/AimTune/tenarium/cmd/tenariumctl@latest
tenariumctl [global flags] <command> <verb> [args] [flags]
```

## Authentication and profiles

```sh
# User login. The password comes from stdin; tokens are stored and refreshed automatically.
tenariumctl login --url https://tenarium.example.com --email admin@example.com
echo "$PASSWORD" | tenariumctl login --url http://localhost:8080 --email ada@example.com --tenant acme --password-stdin

# Store an API key in a separate profile.
tenariumctl --profile ci login --url http://localhost:8080 --api-key "$TENARIUM_API_KEY"

tenariumctl config list                 # * marks the current profile
tenariumctl config use-profile default
tenariumctl config path
tenariumctl logout                      # revokes the session and forgets the tokens
```

Profiles are stored in `<user config dir>/tenarium/config.json` with mode
0600. The user config dir is `$XDG_CONFIG_HOME` or `~/.config` on Linux,
`%APPDATA%` on Windows, and `~/Library/Application Support` on macOS.
`TENARIUM_CONFIG` overrides the path.

On a terminal, `login` prompts for the password and turns off echo through
`stty` where that is available. Otherwise the input is visible. Use
`--password-stdin` in scripts.

Settings are resolved in this order:

1. Flags: `--url`, `--api-key`, `--token`, `--profile`.
2. Environment: `TENARIUM_URL`, `TENARIUM_API_KEY`, `TENARIUM_TOKEN`, `TENARIUM_PROFILE`.
3. The active profile.

## Global flags

`--url`, `--api-key`, `--token`, `-o/--output table|json`, `--profile`, and
`--version`. They work before the command and after the verb, for example
`tenariumctl tenants list -o json`.

## Commands

| Command | Verbs |
|---|---|
| `tenants` | `list get create update delete suspend resume retry-provisioning children entitlements move clone pin-revision maintenance health` |
| `members` | `list add remove set-role` (members can be given by ID or email) |
| `usage` | `get record` |
| `plans` | `list get create update delete revisions` |
| `rollouts` | `list set delete` |
| `templates` | `list get put delete` |
| `users` | `list get create disable enable delete set-password invite` |
| `events` | `list tail` |
| `dead-letters` | `list get replay discard` |
| `plugins` | `list` |
| `me`, `login`, `logout`, `config` | |

Run `tenariumctl <command> --help` or `tenariumctl <command> <verb> --help`
for the flags of each command.

## Examples

```sh
tenariumctl tenants create --slug acme --name "Acme Inc" --plan pro --label region=eu
tenariumctl tenants list --status active --label region=eu
tenariumctl tenants update acme --name "Acme Corp" --if-match 3   # fails with version_conflict if stale
tenariumctl tenants suspend acme --reason "unpaid invoice"
tenariumctl -o json tenants get acme | jq .version

tenariumctl tenants create --slug globex --name Globex --template agency --region eu --add-on extra-seats
tenariumctl tenants move acme --region eu --reprovision     # maintenance window until provisioned there
tenariumctl tenants maintenance acme start --message "Upgrading" --for 30m
tenariumctl tenants clone acme --slug acme-staging --name "Acme staging"
tenariumctl tenants health acme
tenariumctl plans update pro --quota seats=10 --grandfather      # existing tenants keep the old limits
tenariumctl rollouts set new-editor --percent 20 --plan pro
tenariumctl templates put agency --file agency.json

tenariumctl plans create --id pro --name Pro --feature sso --quota members=50
tenariumctl members add acme --email ada@example.com --role admin
tenariumctl members set-role acme ada@example.com viewer
tenariumctl usage record acme api_calls 10
tenariumctl usage get acme

echo "$PW" | tenariumctl users create --email bot@example.com --password-stdin
tenariumctl users invite new.hire@example.com --name "New Hire"

tenariumctl events list --tenant acme --type 'tenant.*'
tenariumctl events tail --type 'tenant.*'          # follow new events; Ctrl-C to stop
tenariumctl events tail --from-start --max 10 -o json

tenariumctl dead-letters list
tenariumctl dead-letters replay <id> [<id>...]
```

## Output and exit codes

`table` is the default output and is written with `text/tabwriter`. `json`
pretty-prints the API objects. `events tail -o json` writes one JSON object
per line.

| Code | Meaning |
|---|---|
| 0 | success (including `--help`) |
| 1 | error: API error, network, config |
| 2 | usage error: unknown command, bad flags, missing arguments |

## Development

Command dispatch lives in
`run(args, stdin, stdout, stderr, env) int`. Tests call it in-process
against a real Tenarium server: `go test ./cmd/tenariumctl/`.
