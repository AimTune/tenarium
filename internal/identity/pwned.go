package identity

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the HIBP range API is keyed by SHA-1; not used for storage
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PwnedPasswords checks passwords against the Have I Been Pwned "Pwned
// Passwords" range API with k-anonymity: only the first five hex digits of
// the password's SHA-1 leave the server, and responses are padded so their
// size reveals nothing either.
type PwnedPasswords struct {
	// BaseURL defaults to https://api.pwnedpasswords.com.
	BaseURL string
	Client  *http.Client
}

// Breached reports whether password appears in a known breach.
func (p PwnedPasswords) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // required by the range API, not used for storage
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := h[:5], h[5:]
	base := p.BaseURL
	if base == "" {
		base = "https://api.pwnedpasswords.com"
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/range/"+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "tenarium")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pwned passwords: status %d", resp.StatusCode)
	}
	// Lines are "SUFFIX:COUNT"; padding entries have count 0.
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 4<<20))
	for sc.Scan() {
		s, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.EqualFold(s, suffix) && count != "0" {
			return true, nil
		}
	}
	return false, sc.Err()
}
