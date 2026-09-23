// Package secretbox is authenticated symmetric encryption for secrets the
// auth plugin must store recoverable-but-not-plaintext — today the
// `two_factor` TOTP seed (RFC 6238 needs the raw secret to verify, so it
// can't be one-way hashed like a password). AES-256-GCM with a random
// per-message nonce; the ciphertext blob is base64(nonce || sealed).
//
// The key comes from the plugin env knob `two_factor_secret_key`
// (base64-encoded 32 bytes). A leaked DB without the key yields no usable
// seeds. Self-contained stdlib crypto — the plugin module stays thin.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeySize is the required raw key length (AES-256).
const KeySize = 32

// ErrNoKey is returned by NewFromBase64 for an empty key string — the
// caller (RegisterPlugin / a TOTP handler) surfaces it as a clear
// "two_factor_secret_key not configured" so a misconfigured deployment
// fails loud instead of shipping plaintext seeds.
var ErrNoKey = errors.New("secretbox: empty key")

// Cipher seals/opens secrets with a fixed AES-256-GCM key.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a raw 32-byte key.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// NewFromBase64 builds a Cipher from a base64-std-encoded 32-byte key
// (the `two_factor_secret_key` env value). Empty → ErrNoKey.
func NewFromBase64(s string) (*Cipher, error) {
	if s == "" {
		return nil, ErrNoKey
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("secretbox: decode key: %w", err)
	}
	return New(key)
}

// Seal encrypts plaintext, returning base64(nonce || ciphertext+tag).
func (c *Cipher) Seal(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: read nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. Returns an error on a malformed blob or a failed
// authentication tag (tamper / wrong key).
func (c *Cipher) Open(blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("secretbox: decode blob: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secretbox: blob shorter than nonce")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secretbox: open: %w", err)
	}
	return string(pt), nil
}
