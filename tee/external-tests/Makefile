include ../../config.mk

ifndef PACKAGE
$(error missing package, please specify a package in the PACKAGE variable e.g. make run-external-test PACKAGE=coreutils)
endif

export INIT = ../target/x86_64-unknown-linux-musl/release/external-tests-wrapper
init:
	cargo build \
		--target x86_64-unknown-linux-musl \
		--release \
		$(CARGO_EXTRA_FLAGS)

%.tar: Dockerfile
	docker build --build-arg PACKAGE=$* --output type=tar,dest=$@ .

run-external-test: init $(PACKAGE).tar
	$(CLI) run --input $(PACKAGE).tar --output /dev/null --attestation-report /dev/null

clean:
	-rm *.tar

.PHONY: init run clean
