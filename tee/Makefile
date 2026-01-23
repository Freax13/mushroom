default:

clippy:
	cargo clippy --workspace --exclude example --exclude external-tests-wrapper --exclude vdso -- -D warnings
	cargo clippy -p example -p external-tests-wrapper -p tests --tests -- -D warnings
	$(MAKE) -C vdso clippy

clean:
	cargo clean
	$(MAKE) -C example clean
	$(MAKE) -C external-tests clean
	$(MAKE) -C vdso clean

.PHONY: default clippy clean
