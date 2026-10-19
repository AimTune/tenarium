package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

func TestTenantTemplateLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	e.createPlan("pro", nil)
	e.create(&tenariumv1.TenantTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "startup-tpl"},
		Spec: tenariumv1.TenantTemplateSpec{
			ID: "startup", Description: "For startups", Plan: "pro", Region: "eu",
			Labels:   map[string]string{"segment": "startup"},
			Settings: raw(`{"theme":"light","limits":{"n":1}}`),
			Features: map[string]bool{"beta": true},
			Limits:   map[string]int64{"seats": 20},
			Branding: &tenariumv1.Branding{PrimaryColor: "#1a2b3c"},
			Roles:    []tenariumv1.TemplateRole{{Name: "billing-admin", Actions: []string{"usage:read", "tenants:read"}}},
		},
	})
	if _, err := e.templates.Reconcile(ctx, req("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	tpl := e.template("startup-tpl")
	if tpl.Status.ID != "startup" || condition(tpl.Status.Conditions, tenariumv1.ConditionReady).Status != metav1.ConditionTrue {
		t.Fatalf("status = %+v", tpl.Status)
	}
	remote, err := e.api.Templates.Get(ctx, "startup")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Name != "startup" || remote.Plan != "pro" || remote.Region != "eu" || remote.Settings["theme"] != "light" ||
		remote.Branding == nil || remote.Branding.PrimaryColor != "#1a2b3c" || len(remote.Roles) != 1 || remote.Limits["seats"] != 20 {
		t.Fatalf("remote = %+v", remote)
	}

	// An idle sync does not rewrite the template.
	if _, err := e.templates.Reconcile(ctx, req("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	if again, _ := e.api.Templates.Get(ctx, "startup"); !again.UpdatedAt.Equal(remote.UpdatedAt) {
		t.Fatal("idle sync rewrote the template")
	}

	// Update.
	tpl = e.template("startup-tpl")
	tpl.Spec.Name = "Startup"
	tpl.Spec.Branding = nil
	tpl.Spec.Settings = raw(`{"theme":"dark"}`)
	if err := e.k8s.Update(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.templates.Reconcile(ctx, req("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	remote, _ = e.api.Templates.Get(ctx, "startup")
	if remote.Name != "Startup" || remote.Branding != nil || remote.Settings["theme"] != "dark" || remote.Settings["limits"] != nil {
		t.Fatalf("remote = %+v", remote)
	}

	// Drift repair.
	remote.Description = "changed"
	if _, err := e.api.Templates.Put(ctx, "startup", remote); err != nil {
		t.Fatal(err)
	}
	if _, err := e.templates.Reconcile(ctx, req("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	if remote, _ = e.api.Templates.Get(ctx, "startup"); remote.Description != "For startups" {
		t.Fatalf("drift not repaired: %+v", remote)
	}

	// Delete.
	if err := e.k8s.Delete(ctx, e.template("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.templates.Reconcile(ctx, req("startup-tpl")); err != nil {
		t.Fatal(err)
	}
	if !e.gone(&tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "startup-tpl", Namespace: "default"}}) {
		t.Fatal("TenantTemplate resource still exists")
	}
	if _, err := e.api.Templates.Get(ctx, "startup"); !client.IsNotFound(err) {
		t.Fatalf("remote template not deleted: %v", err)
	}
}

func TestTenantTemplateAdoption(t *testing.T) {
	e := newEnv(t)
	ctx := e.ctx
	if _, err := e.api.Templates.Put(ctx, "basic", client.TenantTemplate{Name: "Basic"}); err != nil {
		t.Fatal(err)
	}
	e.create(&tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "basic"}, Spec: tenariumv1.TenantTemplateSpec{Name: "Basic v2"}})
	if _, err := e.templates.Reconcile(ctx, req("basic")); err != nil {
		t.Fatal(err)
	}
	if c := condition(e.template("basic").Status.Conditions, tenariumv1.ConditionReady); c.Reason != ReasonAlreadyExists {
		t.Fatalf("Ready = %+v", c)
	}
	tpl := e.template("basic")
	tpl.Annotations = map[string]string{tenariumv1.AnnotationAdopt: "true"}
	if err := e.k8s.Update(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.templates.Reconcile(ctx, req("basic")); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.api.Templates.Get(ctx, "basic"); r.Name != "Basic v2" {
		t.Fatalf("adopted template not updated: %+v", r)
	}
}

func TestTenantTemplateInvalidSettings(t *testing.T) {
	e := newEnv(t)
	e.create(&tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "bad"}, Spec: tenariumv1.TenantTemplateSpec{Settings: raw(`[1]`)}})
	if _, err := e.templates.Reconcile(e.ctx, req("bad")); err == nil {
		t.Fatal("expected an error")
	}
	if c := condition(e.template("bad").Status.Conditions, tenariumv1.ConditionSynced); c.Reason != ReasonInvalidSpec {
		t.Fatalf("Synced = %+v", c)
	}
}

func TestDesiredTemplateAndEqual(t *testing.T) {
	tpl := &tenariumv1.TenantTemplate{ObjectMeta: metav1.ObjectMeta{Name: "x"}, Spec: tenariumv1.TenantTemplateSpec{
		Branding: &tenariumv1.Branding{},
		Roles:    []tenariumv1.TemplateRole{{Name: "r", Actions: []string{"a"}}},
	}}
	d, err := desiredTemplate(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "x" || d.Name != "x" || d.Branding != nil || len(d.Roles) != 1 || d.Settings != nil {
		t.Fatalf("desired = %+v", d)
	}
	same := d
	same.Branding = &sdk.Branding{}
	same.Settings = map[string]any{}
	if !templateEqual(d, same) {
		t.Fatal("empty branding/settings should equal nil")
	}
	for _, mod := range []func(*client.TenantTemplate){
		func(x *client.TenantTemplate) { x.Name = "y" },
		func(x *client.TenantTemplate) { x.Settings = map[string]any{"k": 1.0} },
		func(x *client.TenantTemplate) { x.Branding = &sdk.Branding{AccentColor: "#fff"} },
		func(x *client.TenantTemplate) { x.Roles = []client.TemplateRole{{Name: "r", Actions: []string{"b"}}} },
		func(x *client.TenantTemplate) { x.AddOns = []string{"p"} },
	} {
		c := d
		mod(&c)
		if templateEqual(d, c) {
			t.Fatalf("difference not detected: %+v", c)
		}
	}
}
