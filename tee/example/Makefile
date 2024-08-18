include ../../config.mk

export INIT = ../target/x86_64-unknown-linux-musl/release/example
init: gcc.tar.gz
	cargo build \
		--target x86_64-unknown-linux-musl \
		--release \
		$(CARGO_EXTRA_FLAGS)

gcc.tar: Dockerfile init.sh
	docker build --output type=tar,dest=gcc.tar .

gcc.tar.gz: gcc.tar
	gzip gcc.tar -fk

run: init
	$(CLI) run --input hello-world.c --output hello-world --attestation-report report.bin
	$(CLI) verify --input hello-world.c --output hello-world --attestation-report report.bin
	chmod +x hello-world
	./hello-world

clean:
	-rm gcc.tar gcc.tar.gz

.PHONY: init run clean
