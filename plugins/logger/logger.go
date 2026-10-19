// Package logger is a minimal plugin that logs every matching event. It is
// a good starting point for writing your own plugin.
package logger

import (
	"context"
	"log/slog"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("logger", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	// Events are glob patterns on event type; empty means all.
	Events []string `json:"events"`
}

type Plugin struct {
	log *slog.Logger
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "logger",
		Name:        "Event Logger",
		Version:     "0.1.0",
		Description: "Logs tenant events.",
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	var cfg Config
	if err := r.Config(&cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	r.Subscribe("events", sdk.EventFilter{Types: cfg.Events}, p.handle, sdk.WithStartAtEnd())
	return nil
}

func (p *Plugin) handle(_ context.Context, e sdk.Event) error {
	p.log.Info("event", "type", e.Type, "tenant_id", e.TenantID, "seq", e.Seq, "id", e.ID)
	return nil
}
