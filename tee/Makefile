default:

clippy:
	cargo clippy --workspace --exclude example --exclude external-tests-wrapper --exclude test-runner-init --exclude vdso -- -D warnings
	cargo clippy -p example -p external-tests-wrapper -p test-runner-init -p tests --tests -- -D warnings
	$(MAKE) -C vdso clippy

clean:
	cargo clean
	$(MAKE) -C example clean
	-rm external-tests/*.tar
	$(MAKE) -C tests clean

.PHONY: default clippy clean
