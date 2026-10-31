package handlers

import (
	"fmt"
	"os"
	"strings"

	"github.com/wandering-compiler/plugins/auth/lib/sealing"
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
	sealed, err = sealing.Seal(h.DeliveryRecipient, credential)
	if err != nil {
		return "", "", fmt.Errorf("auth plugin: sealing a credential for delivery: %w", err)
	}
	return "", sealed, nil
}

// checkDeliveryRecipient refuses the boot when a staged feature would put a
// credential on the bus and no recipient is configured, outside W17_ENV=dev;
// and a recipient that is not one, anywhere.
func checkDeliveryRecipient(h *AuthServiceHandler) error {
	r := strings.TrimSpace(h.DeliveryRecipient)
	if r != "" {
		if err := sealing.CheckRecipient(r); err != nil {
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
