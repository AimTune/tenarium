// Package rls isolates tenants in shared ("pooled") PostgreSQL tables with
// row-level security.
//
// Every tenant-owned table carries a tenant column. A policy compares it
// with a setting (app.tenant_id by default) that the application sets per
// transaction, so a query only sees and writes the current tenant's rows,
// whatever its WHERE clause says:
//
//	ddl, _ := rls.Script([]rls.Table{{Name: "public.orders"}}, rls.Options{Index: true})
//	// ALTER TABLE ... ENABLE/FORCE ROW LEVEL SECURITY; CREATE POLICY tenant_isolation ...
//
//	err := rls.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
//		_, err := tx.Exec(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", id)
//		return err
//	})
//
// The setting is read with current_setting(name, true) and an empty value
// counts as "no tenant", so a connection without a tenant sees no rows
// (fail closed). See docs/rls.md.
package rls

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Defaults.
const (
	DefaultSetting    = "app.tenant_id"
	DefaultColumn     = "tenant_id"
	DefaultColumnType = "uuid"
	DefaultPolicy     = "tenant_isolation"
)

// Options configure the generated DDL. The zero value isolates on a uuid
// tenant_id column with the app.tenant_id setting, for every role.
type Options struct {
	// Setting is the configuration parameter holding the current tenant
	// (default "app.tenant_id"). It needs a dot, as custom settings do.
	Setting string
	// Column is the default tenant column (default "tenant_id").
	Column string
	// ColumnType is the type the setting is cast to (default "uuid"); use
	// "text" or "bigint" for other tenant keys.
	ColumnType string
	// Policy names the isolation policy (default "tenant_isolation"); the
	// bypass policy is named "<Policy>_bypass".
	Policy string
	// Roles the isolation policy applies to (default PUBLIC). Roles not
	// covered by any policy see no rows at all.
	Roles []string
	// BypassRoles get a policy that allows every row, e.g. for migrations,
	// support tooling or cross-tenant jobs. Prefer this over BYPASSRLS,
	// which needs a superuser to grant.
	BypassRoles []string
	// NoForce skips FORCE ROW LEVEL SECURITY. Without FORCE the table
	// owner bypasses the policies; keep FORCE unless the application role
	// never owns the tables.
	NoForce bool
	// Function, when set (e.g. "tenarium_current_tenant" or
	// "app.current_tenant"), creates a SQL function returning the current
	// tenant and uses it in the policies.
	Function string
	// Index creates an index on the tenant column (IF NOT EXISTS).
	Index bool
	// SetDefault makes the tenant column default to the current tenant,
	// so INSERTs can leave it out.
	SetDefault bool
}

// Table is a table to protect.
type Table struct {
	// Name is "table" or "schema.table".
	Name string
	// Column overrides Options.Column.
	Column string
}

var (
	settingRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	typeRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?( ?\[\])?$`)
	// Identifiers are quoted; control characters are refused so a name
	// cannot break out of the generated comment lines.
	identRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,63}$`)
)

func (o Options) withDefaults() (Options, error) {
	if o.Setting == "" {
		o.Setting = DefaultSetting
	}
	if o.Column == "" {
		o.Column = DefaultColumn
	}
	if o.ColumnType == "" {
		o.ColumnType = DefaultColumnType
	}
	if o.Policy == "" {
		o.Policy = DefaultPolicy
	}
	var errs []error
	if !settingRE.MatchString(o.Setting) {
		errs = append(errs, fmt.Errorf("rls: invalid setting %q (want e.g. app.tenant_id)", o.Setting))
	}
	if !typeRE.MatchString(o.ColumnType) {
		errs = append(errs, fmt.Errorf("rls: invalid column type %q", o.ColumnType))
	}
	if !identRE.MatchString(o.Column) {
		errs = append(errs, fmt.Errorf("rls: invalid column %q", o.Column))
	}
	if !identRE.MatchString(o.Policy + "_bypass") {
		errs = append(errs, fmt.Errorf("rls: invalid policy name %q", o.Policy))
	}
	for _, r := range append(append([]string{}, o.Roles...), o.BypassRoles...) {
		if !identRE.MatchString(r) {
			errs = append(errs, fmt.Errorf("rls: invalid role %q", r))
		}
	}
	if o.Function != "" {
		if _, err := qualified(o.Function); err != nil {
			errs = append(errs, err)
		}
	}
	return o, errors.Join(errs...)
}

// qualified quotes a possibly schema-qualified name.
func qualified(name string) (string, error) {
	parts := strings.Split(name, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("rls: invalid name %q (want name or schema.name)", name)
	}
	for _, p := range parts {
		if !identRE.MatchString(p) {
			return "", fmt.Errorf("rls: invalid name %q", name)
		}
	}
	return pgx.Identifier(parts).Sanitize(), nil
}

func ident(s string) string { return pgx.Identifier{s}.Sanitize() }

func roleList(roles []string) string {
	if len(roles) == 0 {
		return "PUBLIC"
	}
	out := make([]string, len(roles))
	for i, r := range roles {
		if strings.EqualFold(r, "public") {
			out[i] = "PUBLIC"
		} else {
			out[i] = ident(r)
		}
	}
	return strings.Join(out, ", ")
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// CurrentTenantExpr is the SQL expression for the current tenant: NULL when
// the setting is unset or empty (an ended SET LOCAL leaves it empty).
func (o Options) CurrentTenantExpr() (string, error) {
	o, err := o.withDefaults()
	if err != nil {
		return "", err
	}
	return o.tenantExpr(), nil
}

func (o Options) tenantExpr() string {
	if o.Function != "" {
		fn, _ := qualified(o.Function)
		return fn + "()"
	}
	return o.rawExpr()
}

func (o Options) rawExpr() string {
	return fmt.Sprintf("NULLIF(current_setting(%s, true), '')::%s", quoteLiteral(o.Setting), o.ColumnType)
}

// FunctionDDL returns the CREATE OR REPLACE FUNCTION statement for
// Options.Function, or "" when no function is configured.
func FunctionDDL(o Options) (string, error) {
	o, err := o.withDefaults()
	if err != nil || o.Function == "" {
		return "", err
	}
	fn, _ := qualified(o.Function)
	return fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s() RETURNS %s
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT %s $$;
`, fn, o.ColumnType, o.rawExpr()), nil
}

// TableDDL returns idempotent statements enabling tenant isolation on t:
// ENABLE (and FORCE) ROW LEVEL SECURITY, the isolation policy (dropped and
// recreated so changes apply), the optional bypass policy, index and
// column default.
func TableDDL(t Table, o Options) (string, error) {
	o, err := o.withDefaults()
	if err != nil {
		return "", err
	}
	table, err := qualified(t.Name)
	if err != nil {
		return "", err
	}
	col := t.Column
	if col == "" {
		col = o.Column
	}
	if !identRE.MatchString(col) {
		return "", fmt.Errorf("rls: invalid column %q", col)
	}
	qcol := ident(col)
	cond := fmt.Sprintf("%s = %s", qcol, o.tenantExpr())
	var b strings.Builder
	// Quoted names only: a raw name could end the comment with a newline.
	fmt.Fprintf(&b, "-- %s: tenant isolation on %s\n", table, qcol)
	fmt.Fprintf(&b, "ALTER TABLE %s ENABLE ROW LEVEL SECURITY;\n", table)
	if !o.NoForce {
		fmt.Fprintf(&b, "ALTER TABLE %s FORCE ROW LEVEL SECURITY;\n", table)
	} else {
		fmt.Fprintf(&b, "ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;\n", table)
	}
	fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s;\n", ident(o.Policy), table)
	fmt.Fprintf(&b, "CREATE POLICY %s ON %s\n    AS PERMISSIVE FOR ALL TO %s\n    USING (%s)\n    WITH CHECK (%s);\n",
		ident(o.Policy), table, roleList(o.Roles), cond, cond)
	bypass := ident(o.Policy + "_bypass")
	fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s;\n", bypass, table)
	if len(o.BypassRoles) > 0 {
		fmt.Fprintf(&b, "CREATE POLICY %s ON %s\n    AS PERMISSIVE FOR ALL TO %s\n    USING (true)\n    WITH CHECK (true);\n",
			bypass, table, roleList(o.BypassRoles))
	}
	if o.SetDefault {
		fmt.Fprintf(&b, "ALTER TABLE %s ALTER COLUMN %s SET DEFAULT %s;\n", table, qcol, o.tenantExpr())
	}
	if o.Index {
		fmt.Fprintf(&b, "CREATE INDEX IF NOT EXISTS %s ON %s (%s);\n", ident(indexName(t.Name, col)), table, qcol)
	}
	return b.String(), nil
}

// indexName is "<table>_<column>_idx", truncated to PostgreSQL's 63 bytes.
func indexName(table, col string) string {
	if i := strings.LastIndexByte(table, '.'); i >= 0 {
		table = table[i+1:]
	}
	n := table + "_" + col + "_idx"
	if len(n) > 63 {
		n = n[:63]
	}
	return n
}

// DropDDL returns statements that remove what TableDDL created: policies,
// FORCE, ENABLE and (with SetDefault) the column default. The index is
// kept.
func DropDDL(t Table, o Options) (string, error) {
	o, err := o.withDefaults()
	if err != nil {
		return "", err
	}
	table, err := qualified(t.Name)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "-- %s: remove tenant isolation\n", table)
	fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s;\n", ident(o.Policy+"_bypass"), table)
	fmt.Fprintf(&b, "DROP POLICY IF EXISTS %s ON %s;\n", ident(o.Policy), table)
	fmt.Fprintf(&b, "ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;\n", table)
	fmt.Fprintf(&b, "ALTER TABLE %s DISABLE ROW LEVEL SECURITY;\n", table)
	if o.SetDefault {
		col := t.Column
		if col == "" {
			col = o.Column
		}
		fmt.Fprintf(&b, "ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT;\n", table, ident(col))
	}
	return b.String(), nil
}

// Script returns the full DDL for tables wrapped in one transaction: the
// helper function (when configured) followed by TableDDL for each table.
// Running it again is harmless.
func Script(tables []Table, o Options) (string, error) {
	if len(tables) == 0 {
		return "", errors.New("rls: no tables")
	}
	var b strings.Builder
	b.WriteString("BEGIN;\n\n")
	fn, err := FunctionDDL(o)
	if err != nil {
		return "", err
	}
	if fn != "" {
		b.WriteString(fn + "\n")
	}
	for _, t := range tables {
		ddl, err := TableDDL(t, o)
		if err != nil {
			return "", err
		}
		b.WriteString(ddl + "\n")
	}
	b.WriteString("COMMIT;\n")
	return b.String(), nil
}

// DropScript is Script's inverse; the helper function is dropped last.
func DropScript(tables []Table, o Options) (string, error) {
	if len(tables) == 0 {
		return "", errors.New("rls: no tables")
	}
	var b strings.Builder
	b.WriteString("BEGIN;\n\n")
	for _, t := range tables {
		ddl, err := DropDDL(t, o)
		if err != nil {
			return "", err
		}
		b.WriteString(ddl + "\n")
	}
	if o.Function != "" {
		fn, err := qualified(o.Function)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "DROP FUNCTION IF EXISTS %s();\n\n", fn)
	}
	b.WriteString("COMMIT;\n")
	return b.String(), nil
}
