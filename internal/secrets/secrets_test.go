package secrets

import (
	"strings"
	"testing"
)

const (
	keyA = "key-a-0123456789abcdef0123456789abcdef"
	keyB = "key-b-0123456789abcdef0123456789abcdef"
)

func TestRoundTrip(t *testing.T) {
	c, err := NewCipher([]string{keyA})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Encrypt("otp-secret-material")
	if err != nil {
		t.Fatal(err)
	}
	if !Encrypted(sealed) || strings.Contains(sealed, "otp-secret") {
		t.Fatalf("ciphertext looks wrong: %s", sealed)
	}
	got, err := c.Decrypt(sealed)
	if err != nil || got != "otp-secret-material" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
}

func TestKeyRotation(t *testing.T) {
	old, _ := NewCipher([]string{keyA})
	sealed, _ := old.Encrypt("value")

	rotated, _ := NewCipher([]string{keyB, keyA})
	if got, err := rotated.Decrypt(sealed); err != nil || got != "value" {
		t.Fatalf("rotated cipher should decrypt old values: %q, %v", got, err)
	}

	onlyNew, _ := NewCipher([]string{keyB})
	if _, err := onlyNew.Decrypt(sealed); err == nil {
		t.Fatal("dropping the old key must fail decryption")
	}
}

func TestPassthrough(t *testing.T) {
	c, _ := NewCipher([]string{keyA})
	if got, err := c.Decrypt("legacy-plaintext"); err != nil || got != "legacy-plaintext" {
		t.Fatalf("legacy plaintext must pass through: %q, %v", got, err)
	}
	var nilCipher *Cipher
	if got, err := nilCipher.Encrypt("x"); err != nil || got != "x" {
		t.Fatalf("nil cipher Encrypt: %q, %v", got, err)
	}
	if _, err := nilCipher.Decrypt("enc:v1:AAAA"); err == nil {
		t.Fatal("nil cipher must refuse encrypted values")
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewCipher([]string{"short"}); err == nil {
		t.Fatal("short keys must be rejected")
	}
}
