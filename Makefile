include config.mk

all: kernel supervisor-snp supervisor-tdx cli

kernel: vdso
	$(MAKE) -C tee/kernel

vdso:
	$(MAKE) -C tee/vdso

supervisor-snp:
	$(MAKE) -C tee/supervisor-snp

supervisor-tdx:
	$(MAKE) -C tee/supervisor-tdx

cli:
	$(MAKE) -C host/mushroom

test-runner-init: all
	$(MAKE) -C tee/test-runner-init

test: all test-runner-init
	$(MAKE) -C tee/tests

test-on-host: 
	$(MAKE) -C tee/tests test-on-host

run: all
	$(CLI) run --input $(INPUT) --output $(OUTPUT) --tee $(TEE) --attestation-report $(ATTESTATION_REPORT)

verify: all
	$(CLI) verify --input $(INPUT) --output $(OUTPUT) --tee $(TEE) --attestation-report $(ATTESTATION_REPORT)

run-example: all
	$(MAKE) -C tee/example run

run-external-test: all
	$(MAKE) -C tee/external-tests run-external-test

clippy:
	$(MAKE) -C common clippy
	$(MAKE) -C host   clippy
	$(MAKE) -C tee    clippy

clean:
	$(MAKE) -C common clean
	$(MAKE) -C host   clean
	$(MAKE) -C tee    clean

.PHONY: all kernel supervisor-snp supervisor-tdx cli test-runner-init test test-on-host run verify run-example clippy clean
