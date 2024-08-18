include ../../config.mk

CARGO_PROFILE_development = kernel
CARGO_PROFILE_release     = kernel
CARGO_PROFILE_kasan       = $(CARGO_PROFILE_development)
CARGO_PROFILE_profiling   = kernel-profiling
CARGO_PROFILE = $(CARGO_PROFILE_$(PROFILE))

CARGO_EXTRA_FLAGS_release   = --features harden
CARGO_EXTRA_FLAGS_profiling = --features profiling
CARGO_EXTRA_FLAGS = $(CARGO_EXTRA_FLAGS_$(PROFILE))

CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS_kasan     = --cfg kasan
CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS_profiling = -Z instrument-mcount -C passes=ee-instrument<post-inline>
export CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS = $(CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS_$(PROFILE))

kernel:
	cargo build \
		--target x86_64-unknown-none \
		-Z build-std=core,alloc \
		--profile $(CARGO_PROFILE) \
		$(CARGO_EXTRA_FLAGS)

.PHONY: kernel
