include ../../config.mk

# The mushroom cli only has development and release profiles.
ifeq ($(PROFILE),kasan)
PROFILE = development
else ifeq ($(PROFILE),profiling)
PROFILE = release
endif

CARGO_FEATURE_SNP_FLAGS_true = --features snp
CARGO_FEATURE_SNP_FLAGS = $(CARGO_FEATURE_SNP_FLAGS_$(TEE_SNP))

CARGO_FEATURE_TDX_FLAGS_true = --features tdx
CARGO_FEATURE_TDX_FLAGS = $(CARGO_FEATURE_TDX_FLAGS_$(TEE_TDX))

CARGO_FEATURE_INSECURE_FLAGS_true = --features insecure
CARGO_FEATURE_INSECURE_FLAGS = $(CARGO_FEATURE_INSECURE_FLAGS_$(TEE_INSECURE))

CARGO_EXTRA_FLAGS_release = --release
CARGO_EXTRA_FLAGS = $(CARGO_EXTRA_FLAGS_$(PROFILE))

cli:
	cargo build \
		--no-default-features \
		--features bin \
		$(CARGO_FEATURE_SNP_FLAGS) \
		$(CARGO_FEATURE_TDX_FLAGS) \
		$(CARGO_FEATURE_INSECURE_FLAGS) \
		$(CARGO_EXTRA_FLAGS)

.PHONY: cli
