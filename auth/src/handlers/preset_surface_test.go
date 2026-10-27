package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rc23PresetSurface is what the last release, auth v0.1.0-rc.23, published:
// every REST endpoint (method, full path, method ref), MCP tool, admin page,
// page slot and page action of its presets, and its feature names. Written
// down here because the released manifest is not in this tree; regenerate it
// from `git show auth/v0.1.0-rc.23:auth/plugin.yaml` only when the baseline
// release moves on.
const rc23PresetSurface = `action ServiceAccounts disable
action ServiceAccounts enable
action Users disable
action Users enable
mcp AuthService.WhoAmI
page OrgMemberships
page Organizations
page Roles
page ServiceAccounts
page Sessions
page Users
rest DELETE /auth/clients/{id} AuthService.DeleteClient
rest DELETE /auth/devices/{device_id} AuthService.RevokeDevice
rest DELETE /auth/mfa/totp AuthService.DisableTotp
rest DELETE /auth/orgs/{org}/invites/{invite_id} AuthService.RevokeOrgInvite
rest DELETE /auth/tokens/{token_id} AuthService.RevokeApiToken
rest GET /auth/bots AuthService.ListBots
rest GET /auth/bots/roles AuthService.ListBotRoles
rest GET /auth/clients AuthService.ListClients
rest GET /auth/devices AuthService.ListDevices
rest GET /auth/invites AuthService.ListMyInvites
rest GET /auth/mfa/status AuthService.GetMfaStatus
rest GET /auth/oauth/{provider}/authorize AuthService.OAuthAuthorizeURL
rest GET /auth/oauth/{provider}/callback AuthService.OAuthCallback
rest GET /auth/orgs AuthService.ListMyOrgs
rest GET /auth/orgs/{org}/invites AuthService.ListOrgInvites
rest GET /auth/orgs/{org}/members AuthService.ListOrgMembers
rest GET /auth/orgs/{org}/roles AuthService.ListAssignableRoles
rest GET /auth/tokens AuthService.ListApiTokens
rest GET /auth/whoami AuthService.WhoAmI
rest PATCH /auth/clients/{id} AuthService.SetClientEnabled
rest POST /auth/bots AuthService.CreateBot
rest POST /auth/bots/{user_id}/token AuthService.IssueBotToken
rest POST /auth/cli/authorize AuthService.CliAuthorize
rest POST /auth/cli/token AuthService.CliToken
rest POST /auth/clients AuthService.RegisterClient
rest POST /auth/devices/revoke-all AuthService.RevokeAllDevices
rest POST /auth/devices/revoke-others AuthService.RevokeOtherDevices
rest POST /auth/email/verify AuthService.VerifyEmail
rest POST /auth/email/verify-request AuthService.RequestEmailVerification
rest POST /auth/invites/accept AuthService.AcceptOrgInvite
rest POST /auth/login AuthService.SignIn
rest POST /auth/logout AuthService.Logout
rest POST /auth/mfa/recovery-codes AuthService.GenerateRecoveryCodes
rest POST /auth/mfa/totp AuthService.EnrollTotp
rest POST /auth/mfa/totp/confirm AuthService.ConfirmTotp
rest POST /auth/mfa/verify AuthService.VerifyMfa
rest POST /auth/orgs/{org}/invites AuthService.InviteToOrg
rest POST /auth/password/change AuthService.ChangePassword
rest POST /auth/password/reset AuthService.ResetPassword
rest POST /auth/password/reset-request AuthService.RequestPasswordReset
rest POST /auth/register AuthService.SignUp
rest POST /auth/register/confirm AuthService.ConfirmSignUp
rest POST /auth/tokens AuthService.CreateApiToken
slot OrgMemberships detail.delete
slot OrgMemberships detail.read
slot OrgMemberships detail.update
slot OrgMemberships list.source
slot Organizations detail.delete
slot Organizations detail.read
slot Organizations detail.update
slot Organizations list.source
slot Roles detail.delete
slot Roles detail.read
slot Roles detail.update
slot Roles list.source
slot ServiceAccounts detail.delete
slot ServiceAccounts detail.read
slot ServiceAccounts list.source
slot Sessions detail.delete
slot Sessions detail.read
slot Sessions list.source
slot Users detail.delete
slot Users detail.read
slot Users detail.update
slot Users list.source
feature rbac
feature authenticate_turnkey
feature sign_up_turnkey
feature sign_up_confirmation
feature sign_in_turnkey
feature tenant_scope
feature api_token
feature devices
feature oauth
feature two_factor
feature password_reset
feature email_verification
feature cli_login
feature org_membership
feature org_invite
feature password_change
feature service_account
feature user_admin`

// requiredAdditions are published additions that cannot be opt-in, each named
// in the upgrade guide (changes/00-upgrading-to-device-identity.md): the OAuth
// callback hands the browser a login code instead of a session, and the
// exchange is the only way to redeem it.
var requiredAdditions = map[string]bool{
	"rest POST /auth/oauth/exchange AuthService.OAuthExchange": true,
}

// presetSurface reads plugin.yaml's presets the way rc23PresetSurface is
// written, each entry mapped to the feature that gates it ("" for none); a
// page's slots and actions are gated by the page's feature.
func presetSurface(t *testing.T, manifest string) map[string]string {
	t.Helper()
	i := strings.Index(manifest, "\npresets:\n")
	j := strings.Index(manifest, "\nsandboxes:")
	if i < 0 || j < i {
		t.Fatal("plugin.yaml has no presets block")
	}
	var (
		out                   = map[string]string{}
		ofPage                = map[string]string{} // entry → its page
		pageFeature           = map[string]string{}
		section, prefix, page string
		slotParent            string
		inActions             bool
		endpoint              = regexp.MustCompile(`^\s+- \{ ref: ([\w.]+),\s+method: (\w+),\s+path: ("[^"]*"|[^,\s]*),.*?feature: (\w+)`)
		tool                  = regexp.MustCompile(`^\s+- \{ ref: ([\w.]+),\s+feature: (\w+) \}`)
		slot                  = regexp.MustCompile(`^          (source|read|update|delete|create): [\w.]+`)
	)
	for _, line := range strings.Split(manifest[i:j], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if line == "  rest:" || line == "  mcp:" || line == "  admin:" || line == "  rpc:" {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		// The rpc preset publishes nothing by itself: a private surface serves
		// a method only once it confirms it by name (born opt-in), so an
		// upgrade that offers one adds nothing to any activation.
		if section == "rpc" {
			continue
		}
		switch section {
		case "rest":
			if strings.HasPrefix(line, "      - prefix: ") {
				prefix = strings.Trim(strings.TrimPrefix(line, "      - prefix: "), `"`)
			} else if m := endpoint.FindStringSubmatch(line); m != nil {
				out["rest "+m[2]+" "+prefix+strings.Trim(m[3], `"`)+" "+m[1]] = m[4]
			}
		case "mcp":
			if m := tool.FindStringSubmatch(line); m != nil {
				out["mcp "+m[1]] = m[2]
			}
		case "admin":
			switch {
			case strings.HasPrefix(line, "      - name: "):
				page, inActions = strings.TrimPrefix(line, "      - name: "), false
				ofPage["page "+page] = page
			case page == "":
			case strings.HasPrefix(line, "        feature: "):
				pageFeature[page] = strings.TrimPrefix(line, "        feature: ")
			case line == "        list:" || line == "        detail:":
				slotParent, inActions = strings.TrimSuffix(trimmed, ":"), false
			case line == "        actions:":
				inActions = true
			case inActions && strings.HasPrefix(line, "          - name: "):
				ofPage["action "+page+" "+strings.TrimPrefix(line, "          - name: ")] = page
			case !inActions && slot.MatchString(line):
				ofPage["slot "+page+" "+slotParent+"."+slot.FindStringSubmatch(line)[1]] = page
			}
		}
	}
	for k, p := range ofPage {
		out[k] = pageFeature[p]
	}
	return out
}

// features maps each feature plugin.yaml declares to whether it is on by
// default.
func manifestFeatures(manifest string) map[string]bool {
	block := manifest[strings.Index(manifest, "\nfeatures:\n"):]
	block = block[:strings.Index(block, "\ngo_files_combined:")]
	out := map[string]bool{}
	for _, f := range regexp.MustCompile(`(?m)^  - name: `).Split(block, -1)[1:] {
		name := strings.TrimSpace(f[:strings.Index(f, "\n")])
		out[name] = strings.Contains(f, "\n    default: true\n")
	}
	return out
}

// surface/upgrade-adds-nothing: upgrading the plugin must not break an
// existing activation's code generation or e2e suite. A page, slot, action or
// endpoint that disappears breaks the tests and the admins that name it; one
// that appears in an activation that did not ask for it adds a page an admin
// with nav groups must list, a permission, and a scaffolded e2e test that
// fails until someone writes it. So against the last release nothing may be
// removed, and every addition is gated by a NEW feature that is off by
// default. A slot may be rebound (the key carries no method ref): the Users
// page's delete erases now, under the same name and permission.
func TestPresetSurface_AnUpgradeRemovesNothingAndAddsOnlyOptIn(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(raw)
	current := presetSurface(t, manifest)
	features := manifestFeatures(manifest)

	released, releasedFeatures := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(rc23PresetSurface, "\n") {
		if name, ok := strings.CutPrefix(line, "feature "); ok {
			releasedFeatures[name] = true
			continue
		}
		released[line] = true
	}
	if len(released) < 70 || len(current) < len(released) {
		t.Fatalf("the parser read %d entries (released %d): it no longer understands plugin.yaml", len(current), len(released))
	}
	for k := range released {
		if _, ok := current[k]; !ok {
			t.Errorf("%s was published by rc.23 and is gone: an adopter's admin, client or e2e test that names it breaks on upgrade", k)
		}
	}
	for name := range releasedFeatures {
		if _, ok := features[name]; !ok {
			t.Errorf("feature %s was in rc.23 and is gone: an activation that names it fails code generation", name)
		}
	}
	for k, gate := range current {
		if released[k] || requiredAdditions[k] {
			continue
		}
		switch {
		case gate == "":
			t.Errorf("%s is new and ungated: every existing activation gets it on upgrade", k)
		case releasedFeatures[gate]:
			t.Errorf("%s is new and gated by %s, which rc.23 already had: every activation with %s gets it on upgrade; gate it by a new opt-in feature", k, gate, gate)
		case features[gate]:
			t.Errorf("%s is gated by %s, which is on by default", k, gate)
		}
	}
	for k := range requiredAdditions {
		if _, ok := current[k]; !ok {
			t.Errorf("required addition %s is no longer published; drop it from requiredAdditions and the upgrade guide", k)
		}
	}
}
