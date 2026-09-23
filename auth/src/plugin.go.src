// Package auth is the plugin's root package — declares the v4
// plugin entry point `RegisterPlugin(*gen.EnvConfig,
// gen.HandlerRegistry, gen.ClientSet) error` that the bundle's
// main.go invokes once per activation during gRPC server
// bring-up.
//
// The plugin author owns this file. Staging text-rewrites the
// self-imports (`<go_module>/gen`, `<go_module>/handlers`) to
// the per-activation staged paths so the staged copy compiles
// inside the bundle without a shared srcgo dependency.
//
// Bundle main.go imports each activation under an alias =
// RegisteredAs (`import w17auth "<project>/<bundle>/src/plugins/w17auth"`);
// the alias overrides the declared `package auth` so multiple
// activations of the same plugin source coexist as distinct
// import paths.
package auth

import (
	"fmt"

	"github.com/wandering-compiler/platform/plugins/auth/lib/passwordhash"

	"github.com/wandering-compiler/platform/plugins/auth/gen"
	"github.com/wandering-compiler/platform/plugins/auth/handlers"
)

// RegisterPlugin is the v4 plugin entry point. The bundle's
// generated main.go invokes it once per activation during
// server bring-up:
//
//  1. Constructs the AuthServiceHandler with the typed clients
//     resolved from `clients` (in-process adapters wrapping the
//     bundle's storage servers, zero gRPC transport) + the
//     plugin's chosen defaults for the configurable knobs
//     (logger, auth header name, auth scheme, password-hash
//     settings).
//  2. Registers the handler with the bundle's gRPC server via
//     `registry.RegisterAuthServiceServer`.
//  3. Registers the handler's Shutdown method as the bundle's
//     drain hook via `registry.RegisterShutdown`.
//
// `cfg` is the typed env-var bundle (`gen.EnvConfig`) populated
// from `<DOMAIN>_<PLUGIN>_<NAME>` env vars at bundle boot
// (plugin.yaml's `env:` block declares the surface). Today's
// auth plugin exposes `password_hash_algo` only; per-algo
// tunables fall back to the library defaults.
func RegisterPlugin(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if cfg == nil {
		// Nil-safe defaults mirroring the manifest (two_factor_totp default
		// true). The bundle's pluginwire normally populates cfg from env;
		// this covers a direct RegisterPlugin caller (tests, co-host wiring).
		cfg = &gen.EnvConfig{TwoFactorTotp: true}
	}
	pwSettings, err := resolvePasswordHashSettings(cfg)
	if err != nil {
		return err
	}
	h := &handlers.AuthServiceHandler{
		Query:        clients.AuthQuery(),
		Mutation:     clients.AuthMutation(),
		Lock:         clients.AclLock(),
		DistTx:       clients.DistributedTransaction(),
		Connection:   clients.Connection(),
		HeaderName:   "Authorization",
		Scheme:       "Bearer",
		PasswordHash: pwSettings,

		// two_factor knobs (zero/empty when the feature is off — handlers/
		// mfa.go is the only reader, and it isn't staged then). pluginwire
		// sets TwoFactorTotp from envBool(..., true), so the built-in TOTP
		// verify path defaults ON.
		TwoFactorTOTP:      cfg.TwoFactorTotp,
		TwoFactorScope:     cfg.TwoFactorScope,
		MfaCodeTTLSeconds:  cfg.MfaCodeTtlSeconds,
		TotpIssuer:         cfg.TotpIssuer,
		TwoFactorSecretKey: cfg.TwoFactorSecretKey,

		// Session bearer absolute lifetime (base-tier; <=0 → 30d default
		// applied in sessionTokenExpiry). pluginwire sets this from
		// envInt(session_token_ttl_seconds, 2592000).
		SessionTokenTTLSeconds: cfg.SessionTokenTtlSeconds,

		// oauth knob (ignored unless the `oauth` feature is staged).
		OAuthRedirectBase: cfg.OauthRedirectBase,

		// E1 token lifetimes (<=0 → the handler file's default; ignored
		// unless the matching feature is staged).
		PasswordResetTTLSeconds:     cfg.PasswordResetTtlSeconds,
		EmailVerificationTTLSeconds: cfg.EmailVerificationTtlSeconds,

		InviteOnly:        cfg.InviteOnly,
		OrgInviteTTLHours: cfg.OrgInviteTtlHours,
	}
	if err := handlers.ValidateConfig(h); err != nil {
		return err
	}
	registry.RegisterAuthServiceServer(h)
	registry.RegisterShutdown(h.Shutdown)
	return nil
}

// resolvePasswordHashSettings maps the env-driven algo string
// onto the passwordhash.Settings the handler uses. Empty string
// → DefaultSettings (argon2id + OWASP 2024 params). Unknown
// algo → typed error so misconfigured bundles fail loud at
// startup instead of accepting passwords that can never verify.
func resolvePasswordHashSettings(cfg *gen.EnvConfig) (passwordhash.Settings, error) {
	algo := ""
	if cfg != nil {
		algo = cfg.PasswordHashAlgo
	}
	switch algo {
	case "", "argon2id":
		return passwordhash.Settings{Algo: passwordhash.Argon2id, Params: passwordhash.DefaultParams()}, nil
	case "bcrypt":
		return passwordhash.Settings{Algo: passwordhash.Bcrypt, Params: passwordhash.DefaultParams()}, nil
	case "scrypt":
		return passwordhash.Settings{Algo: passwordhash.Scrypt, Params: passwordhash.DefaultParams()}, nil
	case "pbkdf2", "pbkdf2-sha256":
		return passwordhash.Settings{Algo: passwordhash.PBKDF2_SHA256, Params: passwordhash.DefaultParams()}, nil
	default:
		return passwordhash.Settings{}, fmt.Errorf("auth plugin: unknown password_hash_algo %q (supported: argon2id, bcrypt, scrypt, pbkdf2)", algo)
	}
}
