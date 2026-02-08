include ../../config.mk

CARGO_TARGET_amd64 = x86_64-unknown-linux-gnu
CARGO_TARGET_i386  = i686-unknown-linux-gnu
CARGO_TARGET = $(CARGO_TARGET_$(TEST_TARGET))

export RUSTFLAGS = -C target-feature=+crt-static

test: test-inputs.tar
	$(CLI) run --init ../../$(TEST_RUNNER_INIT) --output /dev/null --tee $(TEE) --attestation-report /dev/null --input $<

test-inputs.tar: cargo-nextest tests.tar.zst ../.config/nextest.toml ../Cargo.toml ../tests/Cargo.toml
	tar -cf $@ $^

cargo-nextest:
	curl -L https://get.nexte.st/0.9/linux-musl -o - | tar xvzf -

tests.tar.zst: cargo-nextest
	./cargo-nextest nextest archive --archive-file $@ --target $(CARGO_TARGET)

test-on-host: cargo-nextest
	./cargo-nextest nextest run --target $(CARGO_TARGET)

clean:
	-rm test-inputs.tar cargo-nextest tests.tar.zst

.PHONY: test tests.tar.zst test-on-host clean
