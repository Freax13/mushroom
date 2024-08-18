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

SUPERVISOR_development = tee/target/supervisor/supervisor/supervisor
SUPERVISOR_release     = tee/target/supervisor/supervisor-release/supervisor
SUPERVISOR_kasan       = $(SUPERVISOR_development)
SUPERVISOR_profiling   = $(SUPERVISOR_development)
export SUPERVISOR ?= $(mkfile_dir)/$(SUPERVISOR_$(PROFILE))

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
