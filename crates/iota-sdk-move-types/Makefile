# Set the default target of this Makefile
.PHONY: all
all:: check-features clippy test wasm

# The compiled Move package blobs are not committed; the shape-compare
# tests read them from disk at run time (only `test` needs them — the
# crate compiles without them). `--ensure` fetches them only when they
# are missing or were fetched at a different rev than the pin (the
# `move-binary-format` rev in Cargo.toml), so repeated runs stay offline
# while a pin bump re-fetches automatically.
.PHONY: packages
packages:
	@bash update_compiled_packages.sh --ensure

.PHONY: check-features
check-features:
	cargo hack check --feature-powerset --no-dev-deps

.PHONY: clippy
clippy:
	cargo clippy --all-features --all-targets

.PHONY: test
test: packages
	cargo nextest run --all-features
	cargo test --all-features --doc

.PHONY: wasm
wasm:
	CC=clang wasm-pack test -r --node --all-features

%:
	$(MAKE) -C ../.. $@
