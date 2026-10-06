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
# The render a release and a commit install both use is w17ctl's own; pinned.
W17CTL      ?= w17ctl

.PHONY: check plugins-exist test vet fmt gen-pb check-gen-pb check-render check-refs check-names check-tools buf-image release

check: fmt vet test check-gen-pb check-render check-refs check-names check-tools

# A typo in PLUGIN must not make every check pass over nothing.
plugins-exist:
	@[ -n "$(strip $(PLUGINS))" ] || { echo "!! no plugin found"; exit 1; }
	@for p in $(PLUGINS); do [ -f "$$p/plugin.yaml" ] || { echo "!! no plugin $$p (no $$p/plugin.yaml)"; exit 1; }; done

# gofmt over the hand-written Go; generated pb is the generator's business.
fmt: plugins-exist
	@out="$$(for p in $(PLUGINS); do find $$p -name '*.go' ! -path '*/gen/pb/*' ! -path '*/workerpb/*' -print0 | xargs -0 gofmt -l; done)"; \
	if [ -n "$$out" ]; then echo "!! not gofmt-clean:"; echo "$$out"; exit 1; fi

vet: plugins-exist
	@for p in $(PLUGINS); do echo ">> vet $$p"; (cd $$p/src && $(GO) vet ./...) || exit 1; done

test: plugins-exist
	@for p in $(PLUGINS); do echo ">> test $$p"; (cd $$p/src && $(GO) test -count=1 -cover ./...) || exit 1; done

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
		work="$$(mktemp -d)"; cp -R "$$p" "$$work/"; \
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

# The installable form a release carries, rendered by the pinned w17ctl — the
# same code a commit install runs: inert Go (.src), tests carried, no pb.
check-render: plugins-exist
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; $(W17CTL) plugin render "$$p" --out "$$work/$$p" || exit 1; \
		[ "$$(find "$$work" -name '*_test.go.src' | wc -l)" -gt 0 ] || { echo "!! $$p rendered no tests"; exit 1; }; \
		live="$$(find "$$work/$$p/src" -type f \( -name '*.go' -o -name go.mod -o -name go.sum \) 2>/dev/null)"; \
		[ -z "$$live" ] || { echo "!! $$p rendered LIVE Go:"; echo "$$live"; exit 1; }; \
		rm -rf "$$work"; \
	done

# Paths that only mean something inside the w17 platform's private docs point a
# public reader at nothing. Say the reason in place instead.
check-refs:
	@hits="$$(git grep -nE 'docs/(todos|decisions|specs|runbooks|audit|archive)/' -- ':!Makefile' || true)"; \
	if [ -n "$$hits" ]; then echo "!! these cite the platform's private docs:"; echo "$$hits"; exit 1; fi

# Names this public repository must not carry. The list is a CI secret; a
# local run without it says so and passes.
check-names:
	@cd tools/checknames && $(GO) run . $(CHECKNAMES_FLAGS) "$(CURDIR)"

# The Go that is not a plugin's src module: the checker itself, and any
# sandbox module a plugin carries.
check-tools:
	@for m in tools/checknames $$(find . -path ./.git -prune -o -name go.mod -path '*/sandboxes/*' -print | xargs -r -n1 dirname); do \
		echo ">> tools $$m"; \
		out="$$(gofmt -l $$m)"; [ -z "$$out" ] || { echo "!! not gofmt-clean: $$out"; exit 1; }; \
		(cd $$m && $(GO) vet ./... && $(GO) test -count=1 ./...) || exit 1; \
	done

release:
	@tools/release.sh $(RELEASE)
