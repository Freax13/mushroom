include ../../config.mk

vdso: vdso-i386 vdso-amd64

export RUSTFLAGS = -Z unstable-options -C linker-flavor=gnu-lld -C linker=rust-lld -C link-self-contained=yes -C debuginfo=full -C strip=none -C panic=abort -C link-arg=-soname=linux-vdso.so.1

vdso-i386:
	cargo build --release --target i686-unknown-linux-gnu

vdso-amd64:
	cargo build --release --target x86_64-unknown-linux-gnu

clippy:
	cargo clippy --target x86_64-unknown-linux-gnu

.PHONY: test
