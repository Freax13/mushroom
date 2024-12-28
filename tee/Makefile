default:

clippy:
	cargo clippy --workspace --exclude example -- -D warnings
	cargo clippy -p example -- -D warnings

clean:
	cargo clean
	$(MAKE) -C example clean

.PHONY: default clippy clean
