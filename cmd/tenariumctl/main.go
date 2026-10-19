// Command tenariumctl is the command-line client for the Tenarium API.
//
//	tenariumctl [global flags] <resource> <verb> [args] [flags]
//
// Run "tenariumctl help" for the list of commands.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
)

const version = "0.1.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// run executes one tenariumctl invocation and returns its exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, env func(string) string) int {
	return runContext(context.Background(), args, stdin, stdout, stderr, env)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, env func(string) string) int {
	a := &app{ctx: ctx, rawIn: stdin, in: bufio.NewReader(stdin), out: stdout, errOut: stderr, getenv: env}
	err := a.main(args)
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errFlagParse):
		// The flag package already printed the problem and the usage.
		return exitUsage
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "error: %s\n", ue.msg)
		if ue.cmd != "" {
			fmt.Fprintf(stderr, "Run 'tenariumctl %s --help' for usage.\n", ue.cmd)
		}
		return exitUsage
	}
	if e, ok := client.AsError(err); ok {
		fmt.Fprintf(stderr, "error: %s\n", formatAPIError(e))
		return exitError
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return exitError
}

func formatAPIError(e *client.Error) string {
	msg := e.Message
	if e.Code != "" {
		msg = e.Code + ": " + msg
	}
	if e.Field != "" {
		msg += " (field " + e.Field + ")"
	}
	return fmt.Sprintf("%s [HTTP %d]", msg, e.Status)
}

// usageError is a command-line mistake (exit code 2).
type usageError struct {
	cmd string // command path for the --help hint
	msg string
}

func (e *usageError) Error() string { return e.msg }

func usagef(cmd, format string, args ...any) error {
	return &usageError{cmd: cmd, msg: fmt.Sprintf(format, args...)}
}

var errFlagParse = errors.New("invalid flags")

// app is the state of one invocation.
type app struct {
	ctx    context.Context
	rawIn  io.Reader
	in     *bufio.Reader
	out    io.Writer
	errOut io.Writer
	getenv func(string) string
	g      globals

	cfg     *config
	cfgPath string
	cl      *client.Client
}

// globals are flags accepted before the resource and by every command.
type globals struct {
	url, apiKey, token, output, profile string
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.url, "url", g.url, "Tenarium server URL (env TENARIUM_URL)")
	fs.StringVar(&g.apiKey, "api-key", g.apiKey, "API key (env TENARIUM_API_KEY)")
	fs.StringVar(&g.token, "token", g.token, "bearer access token (env TENARIUM_TOKEN)")
	fs.StringVar(&g.output, "output", g.output, "output format: table or json")
	fs.StringVar(&g.output, "o", g.output, "shorthand for --output")
	fs.StringVar(&g.profile, "profile", g.profile, "config profile (env TENARIUM_PROFILE)")
}

var globalFlagNames = map[string]bool{"url": true, "api-key": true, "token": true, "output": true, "o": true, "profile": true}

// command is a leaf command such as "tenants list".
type command struct {
	name    string
	args    string // argument synopsis, e.g. "<tenant>"
	summary string
	run     func(a *app, path string, args []string) error
}

// group is a top-level resource with verbs, or a single command (run set).
type group struct {
	name    string
	summary string
	verbs   []command
	run     func(a *app, path string, args []string) error
}

func groups() []group {
	return []group{
		tenantsGroup(), membersGroup(), usageGroup(), plansGroup(), usersGroup(),
		eventsGroup(), deadLettersGroup(), pluginsGroup(), rolloutsGroup(), templatesGroup(),
		{name: "me", summary: "Show the authenticated caller", run: cmdMe},
		{name: "login", summary: "Sign in and store credentials in a profile", run: cmdLogin},
		{name: "logout", summary: "Revoke the session and remove stored credentials", run: cmdLogout},
		configGroup(),
	}
}

func (a *app) main(args []string) error {
	a.g.output = "table"
	fs := flag.NewFlagSet("tenariumctl", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	a.g.register(fs)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() { a.rootUsage(a.errOut) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errFlagParse
	}
	if *showVersion {
		fmt.Fprintln(a.out, "tenariumctl", version)
		return nil
	}
	rest := fs.Args()
	if len(rest) == 0 {
		a.rootUsage(a.errOut)
		return usagef("", "missing command")
	}
	name, rest := rest[0], rest[1:]
	if name == "help" {
		return a.help(rest)
	}
	for _, g := range groups() {
		if g.name != name {
			continue
		}
		if g.run != nil {
			return g.run(a, g.name, rest)
		}
		if len(rest) == 0 {
			a.groupUsage(a.errOut, g)
			return usagef("", "missing verb for %q", g.name)
		}
		if rest[0] == "-h" || rest[0] == "--help" || rest[0] == "help" {
			a.groupUsage(a.out, g)
			return nil
		}
		for _, v := range g.verbs {
			if v.name == rest[0] {
				return v.run(a, g.name+" "+v.name, rest[1:])
			}
		}
		return usagef(g.name, "unknown verb %q for %q", rest[0], g.name)
	}
	return usagef("", "unknown command %q (run 'tenariumctl help')", name)
}

func (a *app) help(args []string) error {
	if len(args) == 0 {
		a.rootUsage(a.out)
		return nil
	}
	for _, g := range groups() {
		if g.name == args[0] {
			if g.run != nil {
				return g.run(a, g.name, []string{"--help"})
			}
			if len(args) > 1 {
				for _, v := range g.verbs {
					if v.name == args[1] {
						return v.run(a, g.name+" "+v.name, []string{"--help"})
					}
				}
			}
			a.groupUsage(a.out, g)
			return nil
		}
	}
	return usagef("", "unknown command %q", args[0])
}

func (a *app) rootUsage(w io.Writer) {
	fmt.Fprint(w, `tenariumctl manages a Tenarium server.

Usage:
  tenariumctl [global flags] <command> [verb] [args] [flags]

Commands:
`)
	for _, g := range groups() {
		verbs := ""
		if len(g.verbs) > 0 {
			names := make([]string, len(g.verbs))
			for i, v := range g.verbs {
				names[i] = v.name
			}
			verbs = " (" + strings.Join(names, "|") + ")"
		}
		fmt.Fprintf(w, "  %-13s %s%s\n", g.name, g.summary, verbs)
	}
	fmt.Fprint(w, `
Global flags (also accepted after the verb):
  --url URL          server URL (env TENARIUM_URL)
  --api-key KEY      API key (env TENARIUM_API_KEY)
  --token TOKEN      bearer access token (env TENARIUM_TOKEN)
  -o, --output FMT   table (default) or json
  --profile NAME     config profile (env TENARIUM_PROFILE)
  --version          print the version

Credentials and the server URL are taken from flags, then environment
variables, then the active profile in the config file (see 'tenariumctl config').

Run 'tenariumctl <command> --help' for details on a command.
`)
}

func (a *app) groupUsage(w io.Writer, g group) {
	fmt.Fprintf(w, "%s\n\nUsage:\n  tenariumctl %s <verb> [args] [flags]\n\nVerbs:\n", g.summary, g.name)
	for _, v := range g.verbs {
		fmt.Fprintf(w, "  %-36s %s\n", v.name+" "+v.args, v.summary)
	}
	fmt.Fprintf(w, "\nRun 'tenariumctl %s <verb> --help' for the verb's flags.\n", g.name)
}

// --- flag parsing ------------------------------------------------------------------

// newFlags returns a flag set for a command that also accepts global flags.
func (a *app) newFlags(path, synopsis, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(path, flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	a.g.register(fs)
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "%s\n\nUsage:\n  tenariumctl %s %s\n", summary, path, synopsis)
		var local []string
		fs.VisitAll(func(f *flag.Flag) {
			if !globalFlagNames[f.Name] {
				local = append(local, f.Name)
			}
		})
		if len(local) > 0 {
			fmt.Fprintln(w, "\nFlags:")
			sort.Strings(local)
			for _, n := range local {
				f := fs.Lookup(n)
				typ, usage := flag.UnquoteUsage(f)
				line := "  --" + n
				if typ != "" {
					line += " " + typ
				}
				if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
					usage += fmt.Sprintf(" (default %s)", f.DefValue)
				}
				fmt.Fprintf(w, "%-30s %s\n", line, usage)
			}
		}
		fmt.Fprintln(w, "\nGlobal flags: --url, --api-key, --token, -o/--output, --profile (see 'tenariumctl help').")
	}
	return fs
}

// parse parses flags interspersed with positional arguments and checks the
// number of positional arguments (max < 0 means unlimited).
func (a *app) parse(fs *flag.FlagSet, args []string, minArgs, maxArgs int) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fs.SetOutput(a.out)
				fs.Usage()
				return nil, err
			}
			return nil, errFlagParse
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			pos = append(pos, rest...)
			break
		}
		if len(rest) == 0 {
			break
		}
		pos, args = append(pos, rest[0]), rest[1:]
	}
	if a.g.output != "table" && a.g.output != "json" {
		return nil, usagef(fs.Name(), "invalid --output %q: want table or json", a.g.output)
	}
	switch {
	case len(pos) < minArgs:
		return nil, usagef(fs.Name(), "missing arguments")
	case maxArgs >= 0 && len(pos) > maxArgs:
		return nil, usagef(fs.Name(), "unexpected arguments: %s", strings.Join(pos[maxArgs:], " "))
	}
	return pos, nil
}

// flagSet reports whether a flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// --- client --------------------------------------------------------------------------

func (a *app) env(name string) string {
	if a.getenv == nil {
		return ""
	}
	return a.getenv(name)
}

// client builds an API client from flags, environment and the profile.
func (a *app) client() (*client.Client, error) {
	if a.cl != nil {
		return a.cl, nil
	}
	cfg, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	name := a.profileName()
	prof := cfg.Profiles[name]
	if prof == nil {
		prof = &profile{}
	}
	base := firstNonEmpty(a.g.url, a.env("TENARIUM_URL"), prof.URL)
	if base == "" {
		return nil, errors.New("no server URL: pass --url, set TENARIUM_URL or run 'tenariumctl login'")
	}
	opts := []client.Option{
		client.WithUserAgent("tenariumctl/" + version),
		client.WithHTTPClient(&http.Client{Timeout: 60 * time.Second}),
		client.WithRetry(2, 250*time.Millisecond),
	}
	useTokens := false
	switch {
	case a.g.apiKey != "":
		opts = append(opts, client.WithAPIKey(a.g.apiKey))
	case a.g.token != "":
		opts = append(opts, client.WithToken(a.g.token))
	case a.env("TENARIUM_API_KEY") != "":
		opts = append(opts, client.WithAPIKey(a.env("TENARIUM_API_KEY")))
	case a.env("TENARIUM_TOKEN") != "":
		opts = append(opts, client.WithToken(a.env("TENARIUM_TOKEN")))
	case prof.APIKey != "":
		opts = append(opts, client.WithAPIKey(prof.APIKey))
	case prof.Tokens != nil:
		// Built below: the token source needs the client's AuthService.
		useTokens = sameURL(base, prof.URL)
	}
	c, err := client.New(base, opts...)
	if err != nil {
		return nil, err
	}
	if useTokens {
		ts := client.NewTokenSource(c.Auth, *prof.Tokens, client.OnRefresh(func(p client.TokenPair) {
			prof.Tokens = &p
			if err := a.saveConfig(); err != nil {
				fmt.Fprintf(a.errOut, "warning: could not save refreshed tokens: %v\n", err)
			}
		}))
		c = c.With(client.WithTokenSource(ts))
	}
	a.cl = c
	return c, nil
}

func sameURL(a, b string) bool { return strings.TrimRight(a, "/") == strings.TrimRight(b, "/") }

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
