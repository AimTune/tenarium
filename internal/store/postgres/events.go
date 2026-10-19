package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// likeEscaper escapes LIKE metacharacters (with the default escape "\").
var likeEscaper = strings.NewReplacer(`\`, `\`, `%`, `\%`, `_`, `\_`)

func (s *Store) QueryEvents(ctx context.Context, q store.EventQuery) ([]sdk.Event, error) {
	var (
		where []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if len(q.TenantIDs) > 0 {
		where = append(where, "tenant_id = ANY("+arg(q.TenantIDs)+")")
	}
	if q.Actor != "" {
		where = append(where, "actor = "+arg(q.Actor))
	}
	if len(q.Types) > 0 {
		var exact, prefixes []string
		for _, t := range q.Types {
			if p, ok := strings.CutSuffix(t, "*"); ok {
				prefixes = append(prefixes, likeEscaper.Replace(p)+"%")
			} else {
				exact = append(exact, t)
			}
		}
		where = append(where, "(type = ANY("+arg(exact)+") OR type LIKE ANY("+arg(prefixes)+"))")
	}
	if !q.Since.IsZero() {
		where = append(where, "time >= "+arg(q.Since))
	}
	if !q.Until.IsZero() {
		where = append(where, "time < "+arg(q.Until))
	}
	if q.Before > 0 {
		where = append(where, "seq < "+arg(q.Before))
	}
	sql := `SELECT seq, id::text, type, source, subject, tenant_id, actor, time, data, traceparent, tracestate, dataschema FROM events`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY seq DESC"
	if q.Limit > 0 {
		sql += " LIMIT " + arg(q.Limit)
	}
	rows, err := s.reader().Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sdk.Event
	for rows.Next() {
		var (
			e    sdk.Event
			data []byte
		)
		if err := rows.Scan(&e.Seq, &e.ID, &e.Type, &e.Source, &e.Subject, &e.TenantID, &e.Actor, &e.Time, &data, &e.TraceParent, &e.TraceState, &e.DataSchema); err != nil {
			return nil, err
		}
		e.Time = e.Time.UTC()
		if len(data) > 0 {
			e.Data = json.RawMessage(data)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) PruneEvents(ctx context.Context, before time.Time, maxSeq int64) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM events WHERE time < $1 AND seq <= $2`, before, maxSeq)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
