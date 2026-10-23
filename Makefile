# mist-protocol Makefile
#
# Build tag policy (safety gate for the Phase 1 test-only Initial codec):
#
#   - `mist_unsafe_initial` tag ENABLED  = lab/internal builds & full tests.
#     The real RandomCiphertextCodec (initial_codec_unsafe.go) is compiled in.
#     This codec emits random ciphertext in a QUIC long header — a DPI
#     fingerprint that must NEVER run on a public network. Lab use only.
#
#   - tag ABSENT (default) = release builds. The codec is an inert stub
#     (initial_codec_disabled.go): every method returns an error, so a
#     release binary is physically incapable of emitting the fingerprint.
#
# Running `go test ./...` WITHOUT the tag makes TestInitialCodec FAIL loudly
# (not skip) — that is intentional. Always use `make test` for the full suite.

GO      := go
GOTAGS  := mist_unsafe_initial
MODULES := ./...

.PHONY: all build build-lab test test-release vet fmt clean nm-check nm-check-lab

all: build

## Build the release binary (no unsafe tag) — safe for public networks.
build:
	$(GO) build -o build/mist-server ./cmd/mist-server

## Build the lab binary (WITH unsafe tag) — internal testing only, never public.
build-lab:
	$(GO) build -tags $(GOTAGS) -o build/mist-server-lab ./cmd/mist-server

## Full test suite — MUST use the lab tag (pinned here so it can't be forgotten).
test:
	$(GO) test -tags $(GOTAGS) $(MODULES)

## Release-config tests: safety gate + symbol check, no tag.
## Verifies the gate itself behaves correctly in the release configuration.
test-release: nm-check
	$(GO) test ./mistcore/ -run 'TestCheckInitialCodecSafeForAddr|TestCodecProductionSafeFailClosed' -v

## Assert the release binary contains NO unsafe codec symbols.
nm-check: build
	@if $(GO) tool nm build/mist-server | grep -q "RandomCiphertextCodec.*buildInitial\|RandomCiphertextCodec.*parseInitialPacket"; then \
		echo "ERROR: release binary contains random-ciphertext codec symbols"; \
		$(GO) tool nm build/mist-server | grep "RandomCiphertextCodec" | head; \
		exit 1; \
	fi
	@echo "OK: no unsafe codec symbols in release binary"

## Sanity check: the lab binary MUST contain the codec symbols
## (proves the nm-check above is actually effective, not vacuous).
nm-check-lab: build-lab
	@if ! $(GO) tool nm build/mist-server-lab | grep -q "RandomCiphertextCodec.*buildInitial"; then \
		echo "ERROR: lab binary is missing codec symbols — the nm check may be broken"; \
		exit 1; \
	fi
	@echo "OK: lab binary contains codec symbols (nm check is effective)"

vet:
	$(GO) vet -tags $(GOTAGS) $(MODULES)

fmt:
	gofmt -l -w .

clean:
	rm -rf build/
