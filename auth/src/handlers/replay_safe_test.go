package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/core/grpcerr"
)

// An outage Authenticate reports — on every request, before anything is
// written — is replay-safe: a w17 client sends it again instead of failing
// the person's request on one dropped statement. Authenticate writes only
// after every check passed (the token's last use, a legacy token's upgrade),
// and those writes return no error.
func TestAuthenticate_AnOutageIsReplaySafe(t *testing.T) {
	q := &expiryLookupQuery{liveErr: status.Error(codes.Unavailable, "db down")}
	_, err := bareAuthenticate(t, &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}}, "tok")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if !grpcerr.IsReplaySafe(err) {
		t.Error("Authenticate's outage is not replay-safe: a w17 client gives up after one attempt")
	}
	// Still the plugin's own answer underneath: the status and its detail.
	if st := status.Convert(err); st.Message() != "the authentication service is temporarily unavailable" {
		t.Errorf("the mark changed the status: %q", st.Message())
	}
}

// A method that writes is NOT marked: SignIn records the attempt whatever it
// answers, so replaying it would count a guess twice. Its outage stays
// answered, and the client does not send it again by itself.
func TestSignIn_AnOutageIsNotReplaySafe(t *testing.T) {
	s, h := newSignInStore(t, "u1")
	h.Query = lookupOutage{s}
	_, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if grpcerr.IsReplaySafe(err) {
		t.Error("SignIn's outage is marked replay-safe, but SignIn writes")
	}
}

// markReplaySafe marks an UNAVAILABLE only, once; nothing else changes.
func TestMarkReplaySafe(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"nil":                  {nil, false},
		"unavailable":          {status.Error(codes.Unavailable, "down"), true},
		"an outage as refusal": {Unauthenticated(status.Error(codes.DeadlineExceeded, "slow")), true},
		"a refusal":            {Unauthenticated(errAuthnPasswordMismatch), false},
		"not found":            {status.Error(codes.NotFound, "no rows"), false},
	} {
		err := tc.err
		markReplaySafe(&err)
		if got := grpcerr.IsReplaySafe(err); got != tc.want {
			t.Errorf("%s: replay-safe = %v, want %v", name, got, tc.want)
		}
		if status.Code(err) != status.Code(tc.err) {
			t.Errorf("%s: code %v became %v", name, status.Code(tc.err), status.Code(err))
		}
	}
}

// replaySafeMethods are the service methods that change nothing — no
// statement that writes, no transaction — so an UNAVAILABLE they answer is
// marked replay-safe. Authenticate and AuthenticateAdmin write only after
// their last error return (the token's last use), with no error of their own.
// A method added here must not write; a method that defers markReplaySafe
// must be here.
var replaySafeMethods = []string{
	"Authenticate",
	"AuthenticateAdmin",
	"GetBotGuard",
	"GetHostOrg",
	"GetMarketingConsent",
	"GetMfaStatus",
	"GetMyOrgEmailProof",
	"GetOAuthAuthorization",
	"GetOrgEmailProof",
	"ListApiTokens",
	"ListAssignableRoles",
	"ListBotRoles",
	"ListBots",
	"ListClients",
	"ListDevices",
	"ListMyInvites",
	"ListMyOAuthGrants",
	"ListMyOrgPackages",
	"ListMyOrgProductPlan",
	"ListMyOrgTwoFactorPolicies",
	"ListMyOrgs",
	"ListMySignInEvents",
	"ListOrgHosts",
	"ListOrgInvites",
	"ListOrgMembers",
	"ListOrgProductPlan",
	"ListOrgProductRoleGrants",
	"ListOrgRoles",
	"ListOrgSignUpPolicies",
	"ListOrgTeams",
	"ListOrgTwoFactorPolicies",
	"ListPackagesOfOrg",
	"ListProductPermissions",
	"ListProductPlans",
	"ListProductRoleGrants",
	"ListProductRoles",
	"ResolveUser",
	"WhoAmI",
}

func TestReplaySafeMethods_DeferTheMarkAndWriteNothing(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	marked := map[string]*ast.FuncDecl{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			for _, st := range fn.Body.List {
				if def, ok := st.(*ast.DeferStmt); ok {
					if id, ok := def.Call.Fun.(*ast.Ident); ok && id.Name == "markReplaySafe" {
						marked[fn.Name.Name] = fn
					}
				}
			}
		}
	}
	want := map[string]bool{}
	for _, m := range replaySafeMethods {
		want[m] = true
		fn := marked[m]
		if fn == nil {
			t.Errorf("%s changes nothing but does not defer markReplaySafe", m)
			continue
		}
		if def, ok := fn.Body.List[0].(*ast.DeferStmt); !ok || def.Call.Fun.(*ast.Ident).Name != "markReplaySafe" {
			t.Errorf("%s: markReplaySafe is not deferred first", m)
		}
		if strings.HasPrefix(m, "Authenticate") {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "Mutation" {
					t.Errorf("%s defers markReplaySafe but writes (Mutation.%s)", m, sel.Sel.Name)
				}
				if sel.Sel.Name == "inTx" || sel.Sel.Name == "withOrgLock" {
					t.Errorf("%s defers markReplaySafe but opens a transaction (%s)", m, sel.Sel.Name)
				}
			}
			return true
		})
	}
	var extra []string
	for m := range marked {
		if !want[m] {
			extra = append(extra, m)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("defer markReplaySafe outside replaySafeMethods (add them only if they write nothing): %v", extra)
	}
}
