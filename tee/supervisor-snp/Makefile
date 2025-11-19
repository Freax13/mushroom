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

CARGO_EXTRA_FLAGS_release = --features harden
CARGO_EXTRA_FLAGS = $(CARGO_EXTRA_FLAGS_$(PROFILE))

export RUSTFLAGS = -Z cf-protection=return

supervisor:
	cargo build \
		--target supervisor.json \
		-Z build-std=core,alloc \
		-Z build-std-features=compiler-builtins-mem \
		--profile $(CARGO_PROFILE) \
		$(CARGO_EXTRA_FLAGS)

.PHONY: supervisor
