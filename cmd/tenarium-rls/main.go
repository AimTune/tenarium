// Command tenarium-rls prints PostgreSQL row-level security DDL that
// isolates tenants in shared tables (see docs/rls.md). It never connects to
// a database: review the output and apply it with your migration tool or
// psql.
//
//	tenarium-rls -index -default -bypass-role migrator public.orders billing.invoices:account_id | psql "$DSN"
//
// A table argument is "table", "schema.table" or "schema.table:column".
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AimTune/tenarium/pkg/rls"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tenarium-rls:", err)
		os.Exit(2)
	}
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tenarium-rls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o rls.Options
	var roles, bypass listFlag
	fs.StringVar(&o.Column, "column", rls.DefaultColumn, "default tenant column (override per table with table:column)")
	fs.StringVar(&o.ColumnType, "type", rls.DefaultColumnType, "type of the tenant column (uuid, text, bigint, ...)")
	fs.StringVar(&o.Setting, "setting", rls.DefaultSetting, "configuration parameter holding the current tenant")
	fs.StringVar(&o.Policy, "policy", rls.DefaultPolicy, "policy name (the bypass policy is <policy>_bypass)")
	fs.StringVar(&o.Function, "function", "", "create this helper function (e.g. app.current_tenant) and use it in policies")
	fs.Var(&roles, "role", "roles the isolation policy applies to (repeatable or comma separated; default PUBLIC)")
	fs.Var(&bypass, "bypass-role", "roles that see every tenant (repeatable or comma separated)")
	fs.BoolVar(&o.NoForce, "no-force", false, "do not FORCE row level security (the table owner then bypasses it)")
	fs.BoolVar(&o.Index, "index", false, "create an index on the tenant column")
	fs.BoolVar(&o.SetDefault, "default", false, "default the tenant column to the current tenant")
	drop := fs.Bool("drop", false, "print DDL that removes the isolation instead")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tenarium-rls [flags] table[:column]...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("no tables given")
	}
	o.Roles, o.BypassRoles = roles, bypass
	tables := make([]rls.Table, 0, fs.NArg())
	for _, a := range fs.Args() {
		name, col, _ := strings.Cut(a, ":")
		tables = append(tables, rls.Table{Name: name, Column: col})
	}
	gen := rls.Script
	if *drop {
		gen = rls.DropScript
	}
	out, err := gen(tables, o)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, out)
	return err
}
