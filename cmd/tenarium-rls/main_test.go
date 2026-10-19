package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"-index", "-bypass-role", "migrator,support", "-function", "app.current_tenant", "public.orders", "billing.invoices:account_id"}, &out, &errOut)
	if err != nil {
		t.Fatal(err, errOut.String())
	}
	s := out.String()
	for _, want := range []string{
		"BEGIN;", "COMMIT;",
		`CREATE OR REPLACE FUNCTION "app"."current_tenant"()`,
		`ALTER TABLE "public"."orders" FORCE ROW LEVEL SECURITY;`,
		`USING ("account_id" = "app"."current_tenant"())`,
		`TO "migrator", "support"`,
		`CREATE INDEX IF NOT EXISTS "invoices_account_id_idx"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}

	out.Reset()
	if err := run([]string{"-drop", "orders"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "DISABLE ROW LEVEL SECURITY") {
		t.Fatalf("drop: %v %s", err, out.String())
	}
	if err := run(nil, &out, &errOut); err == nil {
		t.Error("no tables accepted")
	}
	if err := run([]string{"-setting", "nodot", "t"}, &out, &errOut); err == nil {
		t.Error("invalid setting accepted")
	}
}
