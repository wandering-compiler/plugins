# Every check CI runs, runnable locally. Needs Go and docker.
#
#   make check                 everything, every plugin
#   make check PLUGIN=auth     everything, one plugin
#   make test  PLUGIN=auth     just the Go tests
#   make gen-pb PLUGIN=auth    regenerate a plugin's committed pb
#   make release RELEASE=auth@v0.1.0-rc.17   cut a signed release (RELEASING.md)

ALL_PLUGINS := $(patsubst %/plugin.yaml,%,$(wildcard */plugin.yaml))
PLUGINS     := $(if $(PLUGIN),$(PLUGIN),$(ALL_PLUGINS))
BUF_IMAGE   ?= w17-plugins-buf:local
GO          ?= go
# The render a release uses is w17ctl's own, at the version pinned in
# tools/w17ctl-version (tools/w17ctl.sh installs it); never whatever is on PATH.
RENDER_W17CTL = $$(tools/w17ctl.sh)

.PHONY: check plugins-exist test vet fmt gen-pb check-gen-pb check-render check-published-tests check-modules check-stage check-plugin-msgids plugin-msgids-sync check-refs check-names check-tools buf-image release

check: fmt vet test check-modules check-stage check-plugin-msgids check-gen-pb check-render check-published-tests check-refs check-names check-tools

# A typo in PLUGIN must not make every check pass over nothing.
plugins-exist:
	@[ -n "$(strip $(PLUGINS))" ] || { echo "!! no plugin found"; exit 1; }
	@for p in $(PLUGINS); do [ -f "$$p/plugin.yaml" ] || { echo "!! no plugin $$p (no $$p/plugin.yaml)"; exit 1; }; done

# gofmt over the hand-written Go; generated pb is the generator's business. A
# file gofmt cannot parse is a failure too, not a line on stderr.
fmt: plugins-exist
	@out="$$(for p in $(PLUGINS); do find $$p -name '*.go' ! -path '*/gen/pb/*' ! -path '*/workerpb/*' -print0 | xargs -0 gofmt -l || echo '!! gofmt could not parse a file (above)'; done)"; \
	if [ -n "$$out" ]; then echo "!! not gofmt-clean:"; echo "$$out"; exit 1; fi

vet: plugins-exist
	@for p in $(PLUGINS); do echo ">> vet $$p"; (cd $$p/src && $(GO) vet ./...) || exit 1; done

test: plugins-exist
	@for p in $(PLUGINS); do echo ">> test $$p"; (cd $$p/src && $(GO) test -count=1 -cover ./...) || exit 1; done

# go.mod hygiene: tidy as committed, and no replace onto a path in this repo —
# a plugin is staged into a consumer's bundle, where `../other` is nothing.
check-modules: plugins-exist
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

gen-pb: plugins-exist buf-image
	@for p in $(PLUGINS); do BUF_IMAGE=$(BUF_IMAGE) tools/gen-pb.sh $$p "$$(tools/vocabulary.sh $$p)" || exit 1; done

# Committed generated Go must be what its proto generates. Regenerated into a
# COPY, so the committed files cannot be what makes this pass, then compared —
# extra and missing files included. Two kinds: the plugin's src/gen/pb
# (tools/gen-pb.sh), and any directory with its own buf.gen.yaml.
check-gen-pb: plugins-exist buf-image
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; cp -R "$$p" "$$work/"; \
		BUF_IMAGE=$(BUF_IMAGE) tools/gen-pb.sh "$$work/$$p" "$$(tools/vocabulary.sh $$p)" >/dev/null || exit 1; \
		if ! diff -r "$$p/src/gen/pb" "$$work/$$p/src/gen/pb" >/dev/null; then \
			echo "!! $$p: the committed src/gen/pb is not what its proto generates — run \`make gen-pb PLUGIN=$$p\`"; \
			diff -r "$$p/src/gen/pb" "$$work/$$p/src/gen/pb" | head -40; rm -rf "$$work"; exit 1; \
		fi; \
		for cfg in $$(cd "$$p" && find . -name buf.gen.yaml ! -path './src/gen/*'); do \
			d="$$(dirname "$$cfg")"; \
			find "$$work/$$p/$$d" -maxdepth 1 -name '*.pb.go' -delete; \
			docker run --rm -u "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$$work/$$p/$$d":/workspace -w /workspace $(BUF_IMAGE) generate >/dev/null || exit 1; \
			if ! diff -r "$$p/$$d" "$$work/$$p/$$d" >/dev/null; then \
				echo "!! $$p/$$d: the committed pb is not what its buf.gen.yaml generates"; \
				diff -r "$$p/$$d" "$$work/$$p/$$d" | head -40; rm -rf "$$work"; exit 1; \
			fi; \
			echo ">> gen-pb $$p/$${d#./}: committed pb matches"; \
		done; \
		rm -rf "$$work"; echo ">> gen-pb $$p: committed pb matches"; \
	done

# The installable form a release carries, rendered by the pinned w17ctl: inert
# Go (.src), tests carried, no pb.
check-render: plugins-exist
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; $(RENDER_W17CTL) plugin render "$$p" --out "$$work/$$p" || exit 1; \
		[ "$$(find "$$work" -name '*_test.go.src' | wc -l)" -gt 0 ] || { echo "!! $$p rendered no tests"; exit 1; }; \
		live="$$(find "$$work/$$p/src" -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) 2>/dev/null)"; \
		[ -z "$$live" ] || { echo "!! $$p rendered LIVE Go:"; echo "$$live"; exit 1; }; \
		rm -rf "$$work"; \
	done

# A release's tests must pass from the RELEASED form — rendered, then rehydrated
# the way a reader of a release would (drop .src, add the pb) — not only from
# the author tree. Otherwise the render could drop something the tests need.
check-published-tests: plugins-exist
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT; \
		$(RENDER_W17CTL) plugin render "$$p" --out "$$work/$$p" >/dev/null || exit 1; \
		find "$$work/$$p" -name '*.src' -exec sh -c 'mv "$$1" "$${1%.src}"' _ {} \; ; \
		[ ! -d "$$p/src/gen/pb" ] || { mkdir -p "$$work/$$p/src/gen" && cp -R "$$p/src/gen/pb" "$$work/$$p/src/gen/pb"; }; \
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
# sandbox module a plugin carries.
check-tools:
	@for m in $$(ls -d tools/*/ | sed 's:/$$::' | while read d; do [ -f $$d/go.mod ] && echo $$d; done) $$(find . -path ./.git -prune -o -name go.mod -path '*/sandboxes/*' -print | xargs -r -n1 dirname); do \
		echo ">> tools $$m"; \
		out="$$(gofmt -l $$m)"; [ -z "$$out" ] || { echo "!! not gofmt-clean: $$out"; exit 1; }; \
		(cd $$m && $(GO) vet ./... && $(GO) test -count=1 ./...) || exit 1; \
	done

release:
	@tools/release.sh $(RELEASE)
