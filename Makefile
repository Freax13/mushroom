include config.mk

all: kernel supervisor cli

kernel:
	$(MAKE) -C tee/kernel

supervisor:
	$(MAKE) -C tee/supervisor

cli:
	$(MAKE) -C host/mushroom

test: all
	$(MAKE) -C tee/tests

run: all
ifeq ($(INSECURE),true)
	$(CLI) run --input $(INPUT) --output $(OUTPUT) --insecure
else
	$(CLI) run --input $(INPUT) --output $(OUTPUT) --attestation-report $(ATTESTATION_REPORT)
endif

verify: all
ifeq ($(INSECURE),true)
	$(error can't verify attestation report in insecure mode)
endif
	$(CLI) verify --input $(INPUT) --output $(OUTPUT) --attestation-report $(ATTESTATION_REPORT)

run-example: all
	$(MAKE) -C tee/example run

clean:
	$(MAKE) -C common clean
	$(MAKE) -C host   clean
	$(MAKE) -C tee    clean

.PHONY: all kernel supervisor cli test run verify run-example clean
