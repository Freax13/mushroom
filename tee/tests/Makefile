include ../../config.mk

RUNNER = $(CLI) run --init ../../$(TEST_RUNNER_INIT) --output /dev/null --tee $(TEE) --attestation-report /dev/null --input

CARGO_TARGET_amd64 = x86_64-unknown-linux-gnu
CARGO_TARGET_i386  = i686-unknown-linux-gnu
CARGO_TARGET = $(CARGO_TARGET_$(TEST_TARGET))

export RUSTFLAGS = -C target-feature=+crt-static

test:
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="$(RUNNER)" \
	CARGO_TARGET_I686_UNKNOWN_LINUX_GNU_RUNNER="$(RUNNER)"   \
	cargo test -Zpanic-abort-tests --target $(CARGO_TARGET)

test-on-host:
	cargo test -Zpanic-abort-tests --target $(CARGO_TARGET)

.PHONY: test
