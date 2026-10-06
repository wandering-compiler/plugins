# Every check CI runs, runnable locally. Needs Go and docker.
#
#   make check                 everything, every plugin
#   make check PLUGIN=auth     everything, one plugin
#   make test  PLUGIN=auth     just the Go tests
#   make gen-pb PLUGIN=auth    regenerate a plugin's committed pb
#   make release RELEASE=auth@v0.1.0-rc.17   cut a signed release (RELEASING.md)

PLUGINS   := $(if $(PLUGIN),$(PLUGIN),$(patsubst %/plugin.yaml,%,$(wildcard */plugin.yaml)))
BUF_IMAGE ?= w17-plugins-buf:local
GO        ?= go

.PHONY: check test vet fmt gen-pb check-gen-pb check-render check-names buf-image release

check: fmt vet test check-gen-pb check-render check-names

# gofmt over the hand-written Go; generated pb is the generator's business.
fmt:
	@out="$$(for p in $(PLUGINS); do find $$p/src -name '*.go' ! -path '*/gen/pb/*' -print0 | xargs -0 gofmt -l; done)"; \
	if [ -n "$$out" ]; then echo "!! not gofmt-clean:"; echo "$$out"; exit 1; fi

vet:
	@for p in $(PLUGINS); do echo ">> vet $$p"; (cd $$p/src && $(GO) vet ./...) || exit 1; done

test:
	@for p in $(PLUGINS); do echo ">> test $$p"; (cd $$p/src && $(GO) test -count=1 -cover ./...) || exit 1; done

buf-image:
	docker build -q -t $(BUF_IMAGE) -f tools/buf.Dockerfile tools >/dev/null

gen-pb: buf-image
	@vocab="$$(tools/vocabulary.sh)"; \
	for p in $(PLUGINS); do BUF_IMAGE=$(BUF_IMAGE) tools/gen-pb.sh $$p "$$vocab" || exit 1; done

# The committed pb must be what the generator produces from the committed proto.
# Regenerated into a COPY of the plugin, so the committed files cannot be what
# makes this pass, then compared.
check-gen-pb: buf-image
	@vocab="$$(tools/vocabulary.sh)"; \
	for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; cp -R "$$p" "$$work/"; \
		BUF_IMAGE=$(BUF_IMAGE) tools/gen-pb.sh "$$work/$$p" "$$vocab" >/dev/null || exit 1; \
		if ! diff -r "$$p/src/gen/pb" "$$work/$$p/src/gen/pb" >/dev/null; then \
			echo "!! $$p: the committed src/gen/pb is not what its proto generates — run \`make gen-pb PLUGIN=$$p\`"; \
			diff -r "$$p/src/gen/pb" "$$work/$$p/src/gen/pb" | head -40; rm -rf "$$work"; exit 1; \
		fi; \
		rm -rf "$$work"; echo ">> gen-pb $$p: committed pb matches"; \
	done

# The installable form a release carries: inert Go (.src), tests included,
# no pb. render.sh asserts the inertness itself.
check-render:
	@for p in $(PLUGINS); do \
		work="$$(mktemp -d)"; tools/render.sh "$$p" "$$work" || exit 1; \
		[ "$$(find "$$work" -name '*_test.go.src' | wc -l)" -gt 0 ] || { echo "!! $$p rendered no tests"; exit 1; }; \
		rm -rf "$$work"; \
	done

# Names this public repository must not carry. The list is a CI secret; a
# local run without it says so and passes.
check-names:
	@cd tools/checknames && $(GO) run . $(CHECKNAMES_FLAGS) "$(CURDIR)"

release:
	@tools/release.sh $(RELEASE)
