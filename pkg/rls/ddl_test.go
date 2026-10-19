package rls_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/rls"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden.sql")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./pkg/rls -run Golden -update)", err)
	}
	if w := strings.ReplaceAll(string(want), "\r\n", "\n"); got != w {
		t.Errorf("%s mismatch\n--- got\n%s\n--- want\n%s", name, got, w)
	}
}

func TestGolden(t *testing.T) {
	for name, tc := range map[string]struct {
		tables []rls.Table
		opts   rls.Options
		drop   bool
	}{
		"default": {
			tables: []rls.Table{{Name: "orders"}},
		},
		"full": {
			tables: []rls.Table{{Name: "public.orders"}, {Name: "billing.invoices", Column: "account_id"}},
			opts: rls.Options{
				Function: "app.current_tenant", Roles: []string{"app_user"}, BypassRoles: []string{"migrator", "support"},
				Index: true, SetDefault: true,
			},
		},
		"text_key": {
			tables: []rls.Table{{Name: "Events"}},
			opts:   rls.Options{Setting: "tenarium.tenant", ColumnType: "text", Column: "org", Policy: "org_isolation", NoForce: true, Roles: []string{"public"}},
		},
		"drop": {
			tables: []rls.Table{{Name: "public.orders"}, {Name: "billing.invoices", Column: "account_id"}},
			opts:   rls.Options{Function: "app.current_tenant", SetDefault: true},
			drop:   true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			gen := rls.Script
			if tc.drop {
				gen = rls.DropScript
			}
			got, err := gen(tc.tables, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, name, got)
		})
	}
}

func TestValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		table rls.Table
		opts  rls.Options
		want  string
	}{
		"setting without dot": {rls.Table{Name: "t"}, rls.Options{Setting: "tenant"}, "invalid setting"},
		"setting injection":   {rls.Table{Name: "t"}, rls.Options{Setting: "app.x', true); DROP TABLE t; --"}, "invalid setting"},
		"type injection":      {rls.Table{Name: "t"}, rls.Options{ColumnType: "uuid; DROP TABLE t"}, "invalid column type"},
		"three part name":     {rls.Table{Name: "a.b.c"}, rls.Options{}, "invalid name"},
		"empty name":          {rls.Table{Name: ""}, rls.Options{}, "invalid name"},
		"long column":         {rls.Table{Name: "t", Column: strings.Repeat("c", 64)}, rls.Options{}, "invalid column"},
		"bad function":        {rls.Table{Name: "t"}, rls.Options{Function: "a.b.c"}, "invalid name"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := rls.TableDDL(tc.table, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := rls.Script(nil, rls.Options{}); err == nil {
		t.Error("empty table list accepted")
	}
}

func TestQuoting(t *testing.T) {
	ddl, err := rls.TableDDL(rls.Table{Name: `we"ird.Ta ble`, Column: `Tenant"Id`}, rls.Options{BypassRoles: []string{`ad"min`}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"we""ird"."Ta ble"`, `"Tenant""Id" = NULLIF`, `TO "ad""min"`} {
		if !strings.Contains(ddl, want) {
			t.Errorf("missing %s in\n%s", want, ddl)
		}
	}
	// Control characters (a newline could end the comment line) are refused.
	if _, err := rls.TableDDL(rls.Table{Name: "t\nDROP TABLE x;--"}, rls.Options{}); err == nil {
		t.Fatal("newline in table name accepted")
	}
	expr, err := rls.Options{Setting: "app.org", ColumnType: "bigint"}.CurrentTenantExpr()
	if err != nil || expr != "NULLIF(current_setting('app.org', true), '')::bigint" {
		t.Fatalf("expr %q %v", expr, err)
	}
}
