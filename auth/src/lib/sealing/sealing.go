// Package sealing seals a credential to one age X25519 recipient, so that
// only the holder of its identity reads it: a reset token or a mailed code on
// its way to the service that sends it.
//
// The format is standard base64 of age's binary format — what the SDK's
// secret.OpenSealed reads, and `base64 -d | age -d -i key` too. Plain age
// rather than the SDK's helper: a plugin release must not require an SDK newer
// than the project it is installed in.
//
// It lives in lib/, not in handlers/: handlers/ is copied into the consumer's
// bundle, whose go.mod does not require age; lib/ stays in the plugin's
// module and arrives with its requirements.
package sealing

import (
	"bytes"
	"encoding/base64"
	"strings"

	"filippo.io/age"
)

// Seal encrypts plaintext to recipient (age1…).
func Seal(recipient, plaintext string) (string, error) {
	rec, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// CheckRecipient reports whether r is an age X25519 recipient.
func CheckRecipient(r string) error {
	_, err := age.ParseX25519Recipient(strings.TrimSpace(r))
	return err
}
