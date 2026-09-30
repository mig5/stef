.PHONY: preflight build test check release deb rpm packages clean

preflight:
	./packaging/check-rust-version.sh

build: preflight
	cargo build

test: preflight
	cargo test

check: preflight
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test

release: preflight
	cargo build --release

deb: release
	cargo deb --no-build

rpm: release
	cargo generate-rpm

packages: deb rpm
	mkdir -p dist
	cp target/debian/*.deb dist/ 2>/dev/null || true
	cp target/generate-rpm/*.rpm dist/ 2>/dev/null || true

clean:
	cargo clean
	rm -rf dist
