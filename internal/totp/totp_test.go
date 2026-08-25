package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateAndValidate(t *testing.T) {
	secret, uri, err := Generate("Acme", "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "Acme") {
		t.Errorf("unexpected otpauth URI: %s", uri)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(code, secret) {
		t.Error("freshly generated code should validate")
	}
	if Validate("000000", secret) {
		t.Error("wrong code should not validate")
	}
	if Validate(code, "JBSWY3DPEHPK3PXP") {
		t.Error("code should not validate against another secret")
	}
}
