# Set the default target of this Makefile
.PHONY: all
all:: check-features clippy test wasm

# The compiled Move package blobs are not committed; the test targets
# `include_bytes!` them, so fetch them when missing, at the rev pinned by
# the `move-binary-format` dependency in Cargo.toml. `published_api.txt`
# is fetched last by the script, so its presence implies a complete
# download. The no-op recipe (`@:`) keeps the recipe-less target from
# falling through to the `%` catch-all below.
.PHONY: packages
packages: src/packages_compiled/published_api.txt
	@:
src/packages_compiled/published_api.txt:
	bash update_compiled_packages.sh

.PHONY: check-features
check-features:
	cargo hack check --feature-powerset --no-dev-deps

.PHONY: clippy
clippy: packages
	cargo clippy --all-features --all-targets

.PHONY: test
test: packages
	cargo nextest run --all-features
	cargo test --all-features --doc

.PHONY: wasm
wasm: packages
	CC=clang wasm-pack test -r --node --all-features

%:
	$(MAKE) -C ../.. $@
