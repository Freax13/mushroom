include ../../config.mk

ifeq ($(INSECURE),true)
RUNNER = $(CLI) run --input /dev/null --output /dev/null --insecure --init
else
RUNNER = $(CLI) run --input /dev/null --output /dev/null --attestation-report /dev/null --init
endif

ifeq ($(TEST_TARGET),amd64)
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER = $(RUNNER)
else ifeq ($(TEST_TARGET),i386)
export CARGO_TARGET_I686_UNKNOWN_LINUX_MUSL_RUNNER = $(RUNNER)
endif

CARGO_TARGET_amd64 = x86_64-unknown-linux-musl
CARGO_TARGET_i386  = i686-unknown-linux-musl
CARGO_TARGET = $(CARGO_TARGET_$(TEST_TARGET))

test:
	cargo test --target $(CARGO_TARGET)

.PHONY: test
