# Set the default target of this Makefile
.PHONY: all
all:: wasm

.PHONY: wasm
wasm:
	CC=clang wasm-pack build

%:
	$(MAKE) -C ../.. $@
