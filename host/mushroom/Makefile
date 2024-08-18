include ../../config.mk

# The mushroom cli only has development and release profiles.
ifeq ($(PROFILE),kasan)
PROFILE = development
else ifeq ($(PROFILE),profiling)
PROFILE = release
endif

CARGO_EXTRA_FLAGS_release = --release
CARGO_EXTRA_FLAGS = $(CARGO_EXTRA_FLAGS_$(PROFILE))

cli:
	cargo build \
		--features bin \
		$(CARGO_EXTRA_FLAGS)

.PHONY: cli
