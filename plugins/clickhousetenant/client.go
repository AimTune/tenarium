package clickhousetenant

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Error is a ClickHouse server error as reported by the HTTP interface.
type Error struct {
	// Code is the ClickHouse error code (X-ClickHouse-Exception-Code), 0 if
	// the server did not send one.
	Code int
	// Status is the HTTP status code.
	Status  int
	Message string
}

func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("clickhouse: code %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("clickhouse: HTTP %d: %s", e.Status, e.Message)
}

// maxErrorBody bounds how much of an error response is kept.
const maxErrorBody = 4 << 10

// client talks to the ClickHouse HTTP interface.
type client struct {
	url      string
	user     string
	password string
	http     *http.Client
}

// exec runs query and returns the response body. params are bound to
// {name:Type} placeholders in the query (sent as param_<name>), so values
// never need to be escaped into the SQL text.
func (c *client) exec(ctx context.Context, query string, params map[string]string) ([]byte, error) {
	u, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	// Buffer the result server-side so errors surface as HTTP errors
	// instead of a 200 response with an exception at the end.
	q.Set("wait_end_of_query", "1")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		e := &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
		if code, err := strconv.Atoi(resp.Header.Get("X-ClickHouse-Exception-Code")); err == nil {
			e.Code = code
		}
		return nil, e
	}
	return io.ReadAll(resp.Body)
}

// queryRows runs a SELECT (without a FORMAT clause) and decodes each
// JSONEachRow line into a T.
func queryRows[T any](ctx context.Context, c *client, query string, params map[string]string) ([]T, error) {
	body, err := c.exec(ctx, query+" FORMAT JSONEachRow", params)
	if err != nil {
		return nil, err
	}
	var out []T
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var row T
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("clickhouse: decode row: %w", err)
		}
		out = append(out, row)
	}
	return out, sc.Err()
}

// quoteIdent quotes a ClickHouse identifier with backticks.
func quoteIdent(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "`", "\\`")
	return "`" + r.Replace(s) + "`"
}

// quoteString quotes a ClickHouse string literal.
func quoteString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`, "\x00", `\0`)
	return "'" + r.Replace(s) + "'"
}
