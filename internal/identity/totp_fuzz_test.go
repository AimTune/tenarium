package identity

import (
	"strings"
	"testing"
	"time"
)

// FuzzVerifyTOTP feeds arbitrary secrets, codes, clocks and replay markers
// to the verifier. It must never panic, and an accepted code must be the
// genuine code of a step within the skew window that is newer than
// lastStep.
func FuzzVerifyTOTP(f *testing.F) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Unix()
	f.Add(secret, "123456", now, int64(0))
	f.Add(secret, " 123 456 ", now, int64(-1))
	f.Add("jbswy3dpehpk3pxp====", "000000", int64(0), int64(0))
	f.Add("not base32!", "123456", now, int64(0))
	f.Add("", "", int64(-1), int64(1<<62))
	f.Add(secret, "12345６", now, int64(0))
	f.Fuzz(func(t *testing.T, secret, code string, unix, lastStep int64) {
		// Keep the clock in time.Unix's sane range.
		unix %= 1 << 40
		at := time.Unix(unix, 0)
		step, ok := VerifyTOTP(secret, code, at, lastStep)
		if !ok {
			if step != 0 {
				t.Fatalf("rejected code returned step %d", step)
			}
			// The current code must verify unless replay protection forbids it.
			cur := TOTPStep(at)
			if want, err := TOTPCode(secret, cur); err == nil && lastStep < cur-totpSkew {
				if _, ok := VerifyTOTP(secret, want, at, lastStep); !ok {
					t.Fatalf("genuine code %s for step %d rejected", want, cur)
				}
			}
			return
		}
		cur := TOTPStep(at)
		if step < cur-totpSkew || step > cur+totpSkew {
			t.Fatalf("accepted step %d outside window around %d", step, cur)
		}
		if step <= lastStep {
			t.Fatalf("replayed step %d accepted (lastStep %d)", step, lastStep)
		}
		want, err := TOTPCode(secret, step)
		if err != nil {
			t.Fatalf("accepted code for undecodable secret %q", secret)
		}
		norm := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
		if norm != want {
			t.Fatalf("accepted %q, genuine code is %q", code, want)
		}
		// The same code cannot be used twice.
		if _, again := VerifyTOTP(secret, code, at, step); again {
			t.Fatalf("code %q accepted again after step %d", code, step)
		}
	})
}

// FuzzHashRecoveryCode checks that recovery codes match however the user
// types them (case, dashes, spaces).
func FuzzHashRecoveryCode(f *testing.F) {
	f.Add("abcde-fghij")
	f.Add("ABCDE FGHIJ")
	f.Add("")
	f.Fuzz(func(t *testing.T, code string) {
		h := HashRecoveryCode(code)
		if len(h) != 64 {
			t.Fatalf("hash length %d", len(h))
		}
		// Only codes whose upper-casing round-trips through ToLower are
		// expected to hash identically (some Unicode case mappings are lossy).
		upper, lower := strings.ToUpper(code), strings.ToLower(code)
		if strings.ToLower(upper) == lower && HashRecoveryCode(upper) != HashRecoveryCode(lower) {
			t.Fatalf("case changes hash of %q", code)
		}
		if HashRecoveryCode(" "+code+"-") != h {
			t.Fatalf("separators change hash of %q", code)
		}
	})
}
