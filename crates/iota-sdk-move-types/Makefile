# Set the default target of this Makefile
.PHONY: all
all:: wasm

.PHONY: wasm
wasm: ## Run the test suite under wasm32 (node)
	CC=clang wasm-pack test -r --node --all-features

%:
	$(MAKE) -C ../.. $@
