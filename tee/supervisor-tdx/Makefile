include ../../config.mk

# The supervisor only has development and release profiles.
# If the user requested kasan or profiling use development instead.
ifeq ($(PROFILE),kasan)
PROFILE = development
else ifeq ($(PROFILE),profiling)
PROFILE = development
endif

CARGO_PROFILE_development = supervisor
CARGO_PROFILE_release     = supervisor-release
CARGO_PROFILE = $(CARGO_PROFILE_$(PROFILE))

CARGO_BUILD_STD_FEATURES_development = compiler-builtins-mem
CARGO_BUILD_STD_FEATURES_release     = compiler-builtins-mem,panic_immediate_abort
CARGO_BUILD_STD_FEATURES = $(CARGO_BUILD_STD_FEATURES_$(PROFILE))

CARGO_EXTRA_FLAGS_release = --features harden
CARGO_EXTRA_FLAGS = $(CARGO_EXTRA_FLAGS_$(PROFILE))

export RUSTFLAGS = -Z cf-protection=full

supervisor:
	cargo build \
		--target supervisor.json \
		-Z build-std=core,alloc \
		-Z build-std-features=$(CARGO_BUILD_STD_FEATURES) \
		--profile $(CARGO_PROFILE) \
		$(CARGO_EXTRA_FLAGS)

.PHONY: supervisor
