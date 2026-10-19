# Every check CI runs, runnable locally. Needs Go, docker, and a w17ctl login
# (or W17_TOKEN): `make gen` asks the console.
#
#   make check                 everything, every plugin
#   make check PLUGIN=auth     everything, one plugin
#   make test  PLUGIN=auth     just the Go tests
#   make gen   PLUGIN=auth     generate a plugin's src/gen (never committed)
#   make release-pr PLUGIN=auth               open a plugin's release pull request (RELEASING.md)
#   make release RELEASE=auth@v0.1.0-rc.17   cut a signed release (RELEASING.md)

ALL_PLUGINS := $(patsubst %/plugin.yaml,%,$(wildcard */plugin.yaml))
PLUGINS     := $(if $(PLUGIN),$(PLUGIN),$(ALL_PLUGINS))
BUF_IMAGE   ?= w17-plugins-buf:local
GO          ?= go
# The w17ctl the checks use — to generate src/gen and to render the release
# form — at the version pinned in tools/w17ctl-version (tools/w17ctl.sh
# installs it); never whatever is on PATH.
W17CTL = $$(tools/w17ctl.sh)
# golangci-lint at the version pinned in tools/golangci-version, with this
# repository's config. `go run` builds it once into the Go build cache.
GOLANGCI = $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(shell tr -d ' \n' < $(CURDIR)/tools/golangci-version) run --config $(CURDIR)/tools/golangci.yml

# gen is a prerequisite of every target that compiles a plugin's Go.
.PHONY: check plugins-exist gen test vet fmt check-committed-pb check-render check-published-tests check-modules check-stage check-plugin-msgids plugin-msgids-sync lint check-refs check-names check-tools buf-image release release-pr

check: fmt vet lint test check-modules check-stage check-plugin-msgids check-committed-pb check-render check-published-tests check-refs check-names check-tools check-versions check-layout

# A typo in PLUGIN must not make every check pass over nothing.
plugins-exist:
	@[ -n "$(strip $(PLUGINS))" ] || { echo "!! no plugin found"; exit 1; }
	@for p in $(PLUGINS); do [ -f "$$p/plugin.yaml" ] || { echo "!! no plugin $$p (no $$p/plugin.yaml)"; exit 1; }; done

# A plugin's src/gen — pb, the contract (EnvConfig, ClientSet, HandlerRegistry)
# and the feature constants — is generated from plugin.yaml and proto/ by the
# pinned w17ctl, the way a consumer's staging generates it for an activation.
# Nobody edits it and it is never committed (.gitignore), so every target that
# compiles a plugin's Go generates it first. It asks the console: a w17ctl
# login, or W17_TOKEN.
#
# SKIP_GEN=1 uses the src/gen already there instead: CI generates once, then
# runs the checks, rather than asking the console again for each of them.
gen: plugins-exist
	@for p in $(PLUGINS); do $(W17CTL) plugin gen "$$p" || exit 1; done

GEN_FIRST = $(if $(SKIP_GEN),plugins-exist,gen)

# gofmt over the hand-written Go; generated code is the generator's business. A
# file gofmt cannot parse is a failure too, not a line on stderr.
fmt: plugins-exist
	@out="$$(for p in $(PLUGINS); do find $$p -name '*.go' ! -path '*/src/gen/*' ! -path '*/workerpb/*' -print0 | xargs -0 gofmt -l || echo '!! gofmt could not parse a file (above)'; done)"; \
	if [ -n "$$out" ]; then echo "!! not gofmt-clean:"; echo "$$out"; exit 1; fi

vet: $(GEN_FIRST)
	@for p in $(PLUGINS); do echo ">> vet $$p"; (cd $$p/src && $(GO) vet ./...) || exit 1; done

# golangci-lint (tools/golangci.yml): what gofmt and vet do not catch —
# unchecked errors, `==` on errors that may be wrapped, dead code, unnecessary
# conversions, staticcheck.
lint: $(GEN_FIRST)
	@for p in $(PLUGINS); do echo ">> lint $$p"; (cd $$p/src && $(GOLANGCI) ./...) || exit 1; done

test: $(GEN_FIRST)
	@for p in $(PLUGINS); do echo ">> test $$p"; (cd $$p/src && $(GO) test -count=1 -cover ./...) || exit 1; done

# go.mod hygiene: tidy as committed, and no replace onto a path in this repo —
# a plugin is staged into a consumer's bundle, where `../other` is nothing.
check-modules: $(GEN_FIRST)
	@for p in $(PLUGINS); do \
		if grep -qE '^replace[[:space:]]+[^[:space:]]+[[:space:]]+=>[[:space:]]+\.' "$$p/src/go.mod"; then \
			echo "!! $$p/src/go.mod replaces a module with a local path — it will not exist in a consumer's build"; exit 1; \
		fi; \
		(cd $$p/src && $(GO) mod tidy -diff) || { echo "!! $$p/src/go.mod is not tidy — run \`go mod tidy\` there"; exit 1; }; \
	done

# A plugin's features stage INDEPENDENTLY: an activation that leaves a feature
# off gets a tree without that feature's go_files. `go build` here sees every
# file at once, so a reference across a feature boundary compiles here and
# breaks the consumer that enabled one feature without the other.
check-stage: plugins-exist
	@cd tools/pluginstage && $(GO) run . $(addprefix $(CURDIR)/,$(PLUGINS))

# The `//w17:msgid` sentences in a plugin's Go and the `msgids:` block of its
# plugin.yaml are one list written twice; this compares them. The Go is the
# source of truth: `make plugin-msgids-sync` rewrites the manifest block.
check-plugin-msgids: plugins-exist
	@cd tools/pluginmsgid && $(GO) run . $(addprefix $(CURDIR)/,$(PLUGINS))

plugin-msgids-sync: plugins-exist
	@cd tools/pluginmsgid && $(GO) run . -write $(addprefix $(CURDIR)/,$(PLUGINS))

buf-image:
	docker build -q -t $(BUF_IMAGE) -f tools/buf.Dockerfile tools >/dev/null

# Committed generated Go outside src/gen must be what its proto generates: a
# directory with its own buf.gen.yaml (cluster's workerpb, the relay's wire
# protocol, which no consumer's staging generates). Regenerated into a COPY,
# so the committed files cannot be what makes this pass, then compared —
# extra and missing files included.
check-committed-pb: plugins-exist buf-image
	@for p in $(PLUGINS); do \
		for cfg in $$(cd "$$p" && find . -name buf.gen.yaml ! -path './src/gen/*'); do \
			d="$$(dirname "$$cfg")"; \
			work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; mkdir -p "$$work/$$d"; cp -R "$$p/$$d/." "$$work/$$d/"; \
			find "$$work/$$d" -maxdepth 1 -name '*.pb.go' -delete; \
			docker run --rm -u "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$$work/$$d":/workspace -w /workspace $(BUF_IMAGE) generate >/dev/null || exit 1; \
			if ! diff -r "$$p/$$d" "$$work/$$d" >/dev/null; then \
				echo "!! $$p/$$d: the committed pb is not what its buf.gen.yaml generates"; \
				diff -r "$$p/$$d" "$$work/$$d" | head -40; rm -rf "$$work"; exit 1; \
			fi; \
			rm -rf "$$work"; echo ">> $$p/$${d#./}: committed pb matches"; \
		done; \
	done

# The installable form a consumer's w17ctl renders a release into, rendered by
# the pinned w17ctl: inert Go (.src), tests carried, no src/gen — not even when
# a generated one sits in the author tree.
check-render: plugins-exist
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; $(W17CTL) plugin render "$$p" --out "$$work/$$p" || exit 1; \
		[ ! -e "$$work/$$p/src/gen" ] || { echo "!! $$p rendered src/gen — it is generated, never published"; exit 1; }; \
		[ "$$(find "$$work" -name '*_test.go.src' | wc -l)" -gt 0 ] || { echo "!! $$p rendered no tests"; exit 1; }; \
		live="$$(find "$$work/$$p/src" -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) 2>/dev/null)"; \
		[ -z "$$live" ] || { echo "!! $$p rendered LIVE Go:"; echo "$$live"; exit 1; }; \
		rm -rf "$$work"; \
	done

# A release's tests must pass from the RELEASED form — rendered, then rehydrated
# the way a reader of a release would (drop .src, generate src/gen from the
# rendered plugin.yaml and proto/) — not only from the author tree. Otherwise
# the render could drop something the tests or the generator need.
check-published-tests: plugins-exist
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; \
		$(W17CTL) plugin render "$$p" --out "$$work/$$p" >/dev/null || exit 1; \
		find "$$work/$$p" -name '*.src' -exec sh -c 'mv "$$1" "$${1%.src}"' _ {} \; ; \
		$(W17CTL) plugin gen "$$work/$$p" >/dev/null || { echo "!! $$p: src/gen does not generate from the released form"; exit 1; }; \
		echo ">> $$p: tests from the released form"; \
		(cd "$$work/$$p/src" && $(GO) test -count=1 ./... >/dev/null) || { echo "!! $$p's tests fail from the released form"; exit 1; }; \
		rm -rf "$$work"; \
	done

# Paths that only mean something inside the w17 platform's private docs point a
# public reader at nothing. Say the reason in place instead. (`git grep` exits 1
# for no match and 2+ for a real failure, which must not read as "clean".)
check-refs:
	@hits="$$(git grep -nE 'docs/(todos|decisions|specs|runbooks|audit|archive)/' -- ':!Makefile')"; rc=$$?; \
	[ $$rc -le 1 ] || { echo "!! git grep failed ($$rc)"; exit 1; }; \
	if [ -n "$$hits" ]; then echo "!! these cite the platform's private docs:"; echo "$$hits"; exit 1; fi

# Names this public repository must not carry. The list is a CI secret; a
# local run without it says so and passes.
check-names:
	@cd tools/checknames && $(GO) run . $(CHECKNAMES_FLAGS) "$(CURDIR)"

# The Go that is not a plugin's src module: the checker itself, and any
# sandbox module a plugin carries: gofmt, vet, lint, tests.
check-tools:
	@for m in $$(ls -d tools/*/ | sed 's:/$$::' | while read d; do [ -f $$d/go.mod ] && echo $$d; done) $$(find . -path ./.git -prune -o -name go.mod -path '*/sandboxes/*' -print | xargs -r -n1 dirname); do \
		echo ">> tools $$m"; \
		out="$$(gofmt -l $$m)"; [ -z "$$out" ] || { echo "!! not gofmt-clean: $$out"; exit 1; }; \
		(cd $$m && $(GO) vet ./... && $(GOLANGCI) ./... && $(GO) test -count=1 ./...) || exit 1; \
	done

# A plugin's protos go in the layers a module is made of — proto/<layer>/,
# the layers the platform reads (types, queries, mutations, business, events).
# Staged into a domain, any other directory under proto/ becomes a module of
# its own inside the plugin's, which a project's codegen refuses ("is a module
# … and also a group above module"), and nothing here builds a project. The
# marketing plugin's first release went out with proto/subscriptions/.
check-layout:
	@bad=0; for f in $$(find $(addsuffix /proto,$(PLUGINS)) -name '*.proto'); do \
		rel=$${f#*/proto/}; layer=$${rel%%/*}; \
		case "$$rel" in */*/*) bad=1; echo "!! $$f: nested below proto/$$layer — a layer holds its protos directly";; esac; \
		case "$$layer" in types|queries|mutations|business|events) ;; \
			*) bad=1; echo "!! $$f: proto/$$layer is not a layer (types, queries, mutations, business, events) — a project's codegen reads it as a module of its own";; esac; \
	done; exit $$bad

# Every plugin is on the one version line the platform uses: 0.1.0-rc.N, the rc
# counter the only thing that moves. A cluster release once went to 0.2.0 — a
# minor bump for a break, which semver allowed and nobody wanted — and every
# adopter had to be moved back by hand. tools/release.sh refuses the same.
check-versions:
	@bad=0; for m in */plugin.yaml; do \
		v=$$(sed -n 's/^version:[[:space:]]*//p' $$m | head -1); \
		echo "$$v" | grep -Eq '^0\.1\.0-rc\.[0-9]+$$' || { echo "!! $$m: version $$v — every plugin is 0.1.0-rc.N"; bad=1; }; \
	done; exit $$bad

release:
	@tools/release.sh $(RELEASE)

# Open the pull request that releases one plugin: its version, and its
# changelog collected from <plugin>/changes/ (tools/release-pr.sh).
release-pr:
	@tools/release-pr.sh $(PLUGIN)
