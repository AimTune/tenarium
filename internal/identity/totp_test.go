package identity

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, 8 digits there; we compare the last 6).
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for unix, want8 := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		got, err := TOTPCode(secret, unix/30)
		if err != nil || got != want8[2:] {
			t.Errorf("t=%d: got %s want %s (%v)", unix, got, want8[2:], err)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	cur := TOTPStep(now)
	code, _ := TOTPCode(secret, cur)
	step, ok := VerifyTOTP(secret, code[:3]+" "+code[3:], now, 0)
	if !ok || step != cur {
		t.Fatalf("current code: %d %v", step, ok)
	}
	if _, ok := VerifyTOTP(secret, code, now, cur); ok {
		t.Fatal("replayed code accepted")
	}
	prev, _ := TOTPCode(secret, cur-1)
	if _, ok := VerifyTOTP(secret, prev, now, 0); !ok {
		t.Fatal("previous period refused")
	}
	old, _ := TOTPCode(secret, cur-3)
	if _, ok := VerifyTOTP(secret, old, now, 0); ok {
		t.Fatal("stale code accepted")
	}
	if _, ok := VerifyTOTP(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestRecoveryCodesAndURL(t *testing.T) {
	codes, hashes := NewRecoveryCodes(10)
	if len(codes) != 10 || len(codes[0]) != 11 || codes[0][5] != '-' {
		t.Fatalf("codes: %v", codes)
	}
	if HashRecoveryCode(strings.ToUpper(strings.ReplaceAll(codes[3], "-", " "))) != hashes[3] {
		t.Fatal("normalisation")
	}
	u := OTPAuthURL("Tenarium", "ann@example.com", "ABC")
	if !strings.HasPrefix(u, "otpauth://totp/Tenarium:ann@example.com?") || !strings.Contains(u, "secret=ABC") {
		t.Fatalf("url: %s", u)
	}
}
