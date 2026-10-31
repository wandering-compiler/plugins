package handlers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

// The deployment environment, as the SDK reads it (fieldcrypt, ratelimit).
// Here, in a file every activation stages: the delivery check and
// two_factor's scope check both read it.
const (
	envEnvironment = "W17_ENV"
	devEnvironment = "dev"
)

// secretDeliveryFeatures are the staged features whose events carry a
// credential for a person to receive — a reset link's token, a mailed code.
// Each such feature file appends its name from init(), so the boot check below
// asks for a recipient exactly when the activation can emit one.
var secretDeliveryFeatures []string

// deliver is how a credential travels to the mailer on an event. Sealed to
// delivery_recipient (age), it is ciphertext on the event bus, in its
// dead-letter queue and in its backups; only the holder of the recipient's
// identity reads it. Without a recipient — allowed in W17_ENV=dev only
// (checkDeliveryRecipient) — it travels in clear, as it always did.
//
// It answers the pair the events carry: clear (the old field) or sealed
// (sealed_*), never both. An empty credential (a challenge the authenticator
// answers, with no code to send) is neither.
func (h *AuthServiceHandler) deliver(credential string) (clear, sealed string, err error) {
	if credential == "" {
		return "", "", nil
	}
	if strings.TrimSpace(h.DeliveryRecipient) == "" {
		return credential, "", nil
	}
	sealed, err = sealTo(h.DeliveryRecipient, credential)
	if err != nil {
		return "", "", fmt.Errorf("auth plugin: sealing a credential for delivery: %w", err)
	}
	return "", sealed, nil
}

// sealTo encrypts credential to one age X25519 recipient and answers it as
// standard base64 of the age binary format — what the SDK's
// secret.OpenSealed reads, and `base64 -d | age -d -i key` too. Plain age
// rather than the SDK's helper: a plugin release must not require an SDK newer
// than the project it is installed in.
func sealTo(recipient, credential string) (string, error) {
	rec, err := age.ParseX25519Recipient(strings.TrimSpace(recipient))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec)
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]byte(credential)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// checkDeliveryRecipient refuses the boot when a staged feature would put a
// credential on the bus and no recipient is configured, outside W17_ENV=dev;
// and a recipient that is not one, anywhere.
func checkDeliveryRecipient(h *AuthServiceHandler) error {
	r := strings.TrimSpace(h.DeliveryRecipient)
	if r != "" {
		if _, err := age.ParseX25519Recipient(r); err != nil {
			return fmt.Errorf("auth plugin: delivery_recipient %q is not an age recipient (age1…): %w", r, err)
		}
		return nil
	}
	if len(secretDeliveryFeatures) == 0 || os.Getenv(envEnvironment) == devEnvironment {
		return nil
	}
	return fmt.Errorf("auth plugin: delivery_recipient is required: %s put a credential on an event "+
		"(a reset token, a mailed code), and without a recipient it would travel in clear on the event bus. "+
		"Set it to the age public key (age1…) of the service that mails them; that service opens each "+
		"sealed_* field with its identity. In clear is honoured only with %s=%s; this environment is %q",
		strings.Join(secretDeliveryFeatures, ", "), envEnvironment, devEnvironment, os.Getenv(envEnvironment))
}

func init() {
	configChecks = append(configChecks, checkDeliveryRecipient)
}
