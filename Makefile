include config.mk

all: kernel supervisor-snp cli

kernel:
	$(MAKE) -C tee/kernel

supervisor-snp:
	$(MAKE) -C tee/supervisor-snp

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

clean:
	$(MAKE) -C common clean
	$(MAKE) -C host   clean
	$(MAKE) -C tee    clean

.PHONY: all kernel supervisor-snp cli test run verify run-example clean
