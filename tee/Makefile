default:

clippy:
	cargo clippy --workspace --exclude example --exclude external-tests-wrapper -- -D warnings
	cargo clippy -p example -p external-tests-wrapper -- -D warnings

clean:
	cargo clean
	$(MAKE) -C example clean
	$(MAKE) -C external-tests clean

.PHONY: default clippy clean
