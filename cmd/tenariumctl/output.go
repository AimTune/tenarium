package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// print writes v as pretty JSON or, in table mode, calls table.
func (a *app) print(v any, table func(w *tabwriter.Writer)) error {
	if a.g.output == "json" {
		return a.writeJSON(v)
	}
	return a.table(table)
}

func (a *app) writeJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "%s\n", b)
	return err
}

func (a *app) table(fn func(w *tabwriter.Writer)) error {
	w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fn(w)
	return w.Flush()
}

// done reports a mutation without a resource body.
func (a *app) done(msg string, obj map[string]any) error {
	if a.g.output == "json" {
		return a.writeJSON(obj)
	}
	_, err := fmt.Fprintln(a.out, msg)
	return err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func fmtStrMap(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

func fmtLimits(m map[string]int64) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, k+"="+strconv.FormatInt(m[k], 10))
	}
	return strings.Join(parts, ",")
}

// fmtFeatures lists enabled features; disabled ones are prefixed with "!".
func fmtFeatures(m map[string]bool) string {
	if len(m) == 0 {
		return "-"
	}
	keys := sortedKeys(m)
	sort.SliceStable(keys, func(i, j int) bool { return m[keys[i]] && !m[keys[j]] })
	parts := make([]string, 0, len(m))
	for _, k := range keys {
		if m[k] {
			parts = append(parts, k)
		} else {
			parts = append(parts, "!"+k)
		}
	}
	return strings.Join(parts, ",")
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// --- repeatable flag values -----------------------------------------------------

// kvFlag collects repeated key=value flags.
type kvFlag map[string]string

func (f kvFlag) String() string { return fmtStrMap(f) }
func (f kvFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return fmt.Errorf("want key=value, got %q", s)
	}
	f[k] = v
	return nil
}

// featureFlag collects repeated name[=true|false] flags.
type featureFlag map[string]bool

func (f featureFlag) String() string { return fmtFeatures(f) }
func (f featureFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if k == "" {
		return fmt.Errorf("want name[=true|false], got %q", s)
	}
	on := true
	if ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("want name[=true|false], got %q", s)
		}
		on = b
	}
	f[k] = on
	return nil
}

// quotaFlag collects repeated metric=N flags.
type quotaFlag map[string]int64

func (f quotaFlag) String() string { return fmtLimits(f) }
func (f quotaFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	n, err := strconv.ParseInt(v, 10, 64)
	if !ok || k == "" || err != nil {
		return fmt.Errorf("want metric=N, got %q", s)
	}
	f[k] = n
	return nil
}

// listFlag collects repeated string flags.
type listFlag []string

func (f *listFlag) String() string { return strings.Join(*f, ",") }
func (f *listFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*f = append(*f, p)
		}
	}
	return nil
}

// jsonObjectFlag parses a JSON object.
type jsonObjectFlag struct{ v map[string]any }

func (f *jsonObjectFlag) String() string {
	if f.v == nil {
		return ""
	}
	b, _ := json.Marshal(f.v)
	return string(b)
}

func (f *jsonObjectFlag) Set(s string) error {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil || m == nil {
		return fmt.Errorf("want a JSON object, got %q", s)
	}
	f.v = m
	return nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
