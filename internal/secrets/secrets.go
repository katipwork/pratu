// Package secrets encrypts stored secrets that would enable impersonation
// if the database leaked: TOTP secrets, second-factor phone numbers, and
// tenant signing keys. (Password hashes, hashed session tokens, and
// bcrypt-hashed client secrets don't need it.)
//
// AES-256-GCM with a configured key list: the first key encrypts, every
// key decrypts, so rotating means prepending a new key and keeping the
// old one until a re-encryption sweep has run. Values carry an "enc:v1:"
// prefix; unprefixed values read back as legacy plaintext, which lets
// deployments turn encryption on against existing data.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const prefix = "enc:v1:"

type Cipher struct {
	aeads []cipher.AEAD
}

// NewCipher derives AES-256 keys from the configured passphrases
// (sha256; each must be at least 32 characters). An empty list returns a
// nil Cipher, whose methods pass values through unchanged.
func NewCipher(passphrases []string) (*Cipher, error) {
	if len(passphrases) == 0 {
		return nil, nil
	}
	c := &Cipher{}
	for i, p := range passphrases {
		if len(p) < 32 {
			return nil, fmt.Errorf("encryption key %d must be at least 32 characters", i+1)
		}
		key := sha256.Sum256([]byte(p))
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		c.aeads = append(c.aeads, aead)
	}
	return c, nil
}

// Encrypt seals a value with the primary key. A nil Cipher returns the
// value unchanged (encryption not configured).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if c == nil {
		return plaintext, nil
	}
	aead := c.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Encrypted reports whether a stored value carries the encryption prefix.
func Encrypted(stored string) bool {
	return strings.HasPrefix(stored, prefix)
}

// Decrypt opens a stored value, trying every configured key. Unprefixed
// values are legacy plaintext and pass through.
func (c *Cipher) Decrypt(stored string) (string, error) {
	raw, ok := strings.CutPrefix(stored, prefix)
	if !ok {
		return stored, nil
	}
	if c == nil {
		return "", errors.New("value is encrypted but no encryption keys are configured")
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("encrypted value: %w", err)
	}
	for _, aead := range c.aeads {
		if len(data) < aead.NonceSize() {
			continue
		}
		plaintext, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
		if err == nil {
			return string(plaintext), nil
		}
	}
	return "", errors.New("no configured encryption key decrypts this value")
}
