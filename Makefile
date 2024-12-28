include config.mk

all: kernel supervisor-snp supervisor-tdx cli

kernel:
	$(MAKE) -C tee/kernel

supervisor-snp:
	$(MAKE) -C tee/supervisor-snp

supervisor-tdx:
	$(MAKE) -C tee/supervisor-tdx

cli:
	$(MAKE) -C host/mushroom

test: all
	$(MAKE) -C tee/tests

run: all
ifeq ($(TEE),insecure)
	$(CLI) run --input $(INPUT) --output $(OUTPUT) --tee insecure
else
	$(CLI) run --input $(INPUT) --output $(OUTPUT) --tee $(TEE) --attestation-report $(ATTESTATION_REPORT)
endif

verify: all
ifeq ($(TEE),insecure)
	$(error can't verify attestation report in insecure mode)
endif
	$(CLI) verify --input $(INPUT) --output $(OUTPUT) --tee $(TEE) --attestation-report $(ATTESTATION_REPORT)

run-example: all
	$(MAKE) -C tee/example run

clippy:
	$(MAKE) -C common clippy
	$(MAKE) -C host   clippy
	$(MAKE) -C tee    clippy

clean:
	$(MAKE) -C common clean
	$(MAKE) -C host   clean
	$(MAKE) -C tee    clean

.PHONY: all kernel supervisor-snp supervisor-tdx cli test run verify run-example clippy clean
