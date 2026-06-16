# Only the crate-specific rules the root Makefile invokes (via `make -C`)
# live here; everything else (test, clippy, …) falls through to the root.
.PHONY: check-features
check-features:
	cargo hack check --feature-powerset --no-dev-deps

.PHONY: wasm
wasm:
	CC=clang wasm-pack test -r --node --all-features

%:
	$(MAKE) -C ../.. $@
