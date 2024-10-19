PROFILE ?= development

# Make sure that the requested profile is supported.
KNOWN_PROFILE_development = 1
KNOWN_PROFILE_release     = 1
KNOWN_PROFILE_kasan       = 1
KNOWN_PROFILE_profiling   = 1
KNOWN_PROFILE = $(KNOWN_PROFILE_$(PROFILE))
ifneq ($(KNOWN_PROFILE),1)
$(error unknown profile $(PROFILE))
endif

ifeq ($(PROFILE),kasan)
export KASAN = true
endif

# Determine file locations for binaries.

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

KERNEL_development = tee/target/x86_64-unknown-none/kernel/kernel
KERNEL_release     = $(KERNEL_development)
KERNEL_kasan       = $(KERNEL_development)
KERNEL_profiling   = tee/target/x86_64-unknown-none/kernel-profiling/kernel
export KERNEL ?= $(mkfile_dir)/$(KERNEL_$(PROFILE))

SUPERVISOR_SNP_development = tee/target/supervisor/supervisor/supervisor-snp
SUPERVISOR_SNP_release     = tee/target/supervisor/supervisor-release/supervisor-snp
SUPERVISOR_SNP_kasan       = $(SUPERVISOR_SNP_development)
SUPERVISOR_SNP_profiling   = $(SUPERVISOR_SNP_development)
export SUPERVISOR_SNP ?= $(mkfile_dir)/$(SUPERVISOR_SNP_$(PROFILE))

SUPERVISOR_TDX_development = tee/target/supervisor/supervisor/supervisor-tdx
SUPERVISOR_TDX_release     = tee/target/supervisor/supervisor-release/supervisor-tdx
SUPERVISOR_TDX_kasan       = $(SUPERVISOR_TDX_development)
SUPERVISOR_TDX_profiling   = $(SUPERVISOR_TDX_development)
export SUPERVISOR_TDX ?= $(mkfile_dir)/$(SUPERVISOR_TDX_$(PROFILE))

CLI_development = host/target/debug/mushroom
CLI_release     = host/target/release/mushroom
CLI_kasan       = $(CLI_development)
CLI_profiling   = $(CLI_release)
CLI = $(mkfile_dir)/$(CLI_$(PROFILE))

TIME_BACKEND ?= fake

# Make sure that the requested time backend is supported.
KNOWN_TIME_BACKEND_fake = 1
KNOWN_TIME_BACKEND_real = 1
KNOWN_TIME_BACKEND = $(KNOWN_TIME_BACKEND_$(TIME_BACKEND))
ifneq ($(KNOWN_TIME_BACKEND),1)
$(error unknown time backend $(TIME_BACKEND))
endif

TEST_TARGET ?= amd64

# Make sure that the requested test target is supported.
KNOWN_TEST_TARGET_amd64 = 1
KNOWN_TEST_TARGET_i386  = 1
KNOWN_TEST_TARGET = $(KNOWN_TEST_TARGET_$(TEST_TARGET))
ifneq ($(KNOWN_TEST_TARGET),1)
$(error unknown test target $(TEST_TARGET))
endif

OUTPUT ?= output.bin
ATTESTATION_REPORT ?= report.bin

TEE_SNP      ?= true
TEE_TDX      ?= true
TEE_INSECURE ?= true

# Make sure that the TEE flags are either true or false.
KNOWN_BOOL_true  = 1
KNOWN_BOOL_false = 1
KNOWN_TEE_SNP = $(KNOWN_BOOL_$(TEE_SNP))
KNOWN_TEE_TDX = $(KNOWN_BOOL_$(TEE_TDX))
KNOWN_TEE_INSECURE = $(KNOWN_BOOL_$(TEE_INSECURE))
ifneq ($(KNOWN_TEE_SNP),1)
$(error unknown value for TEE_SNP $(TEE_SNP))
endif
ifneq ($(KNOWN_TEE_TDX),1)
$(error unknown value for TEE_TDX $(TEE_TDX))
endif
ifneq ($(KNOWN_TEE_INSECURE),1)
$(error unknown value for TEE_INSECURE $(TEE_INSECURE))
endif

TEE ?= auto

# Make sure that the requested TEE value is supported.
KNOWN_TEE_snp      = 1
KNOWN_TEE_tdx      = 1
KNOWN_TEE_insecure = 1
KNOWN_TEE_auto     = 1
KNOWN_TEE = $(KNOWN_TEE_$(TEE))
ifneq ($(KNOWN_TEE),1)
$(error unknown value for TEE $(TEE))
endif
