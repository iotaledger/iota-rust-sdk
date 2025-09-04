# Set the default target of this Makefile
.PHONY: all
all:: ci ## Default target, runs the CI process

.PHONY: check-features
check-features: ## Check feature flags for crates
	$(MAKE) -C crates/iota-sdk-types check-features
	$(MAKE) -C crates/iota-crypto check-features

.PHONY: check-fmt
check-fmt: ## Check code formatting
	cargo +nightly fmt -- --check

.PHONY: fmt
fmt: ## Format code
	cargo +nightly fmt

.PHONY: clippy
clippy: ## Run Clippy linter
	cargo clippy --all-features --all-targets

.PHONY: test
test: ## Run unit tests
	cargo nextest run --all-features -p iota-sdk-types -p iota-crypto
	cargo test --all-features --doc

package_%.json: crates/iota-transaction-builder/tests/%/Move.toml crates/iota-transaction-builder/tests/%/sources/*.move ## Generate JSON files for tests
	cd crates/iota-transaction-builder/tests/$(*F) && iota move build --ignore-chain --dump-bytecode-as-base64 > ../../$@

.PHONY: test-with-localnet
test-with-localnet: package_test_example_v1.json package_test_example_v2.json ## Run tests with localnet
	cargo nextest run -p iota-graphql-client -p iota-transaction-builder

.PHONY: wasm
wasm: ## Build WASM modules
	$(MAKE) -C crates/iota-sdk-types wasm
	$(MAKE) -C crates/iota-crypto wasm

.PHONY: doc
doc: ## Generate documentation
	RUSTDOCFLAGS="-Dwarnings --cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --all-features --no-deps

.PHONY: doc-open
doc-open: ## Generate and open documentation
	RUSTDOCFLAGS="--cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --all-features --no-deps --open

.PHONY: is-dirty
is-dirty: ## Checks if repository is dirty
	@(test -z "$$(git diff)" || (git diff && false)) && (test -z "$$(git status --porcelain)" || (git status --porcelain && false))

.PHONY: ci
ci: check-features check-fmt test wasm ## Run the full CI process

.PHONY: ci-full
ci-full: ci doc ## Run the full CI process and generate documentation

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

.PHONY: clean-all
clean-all: clean ## Clean all generated files, including those ignored by Git. Force removal.
	git clean -dXf

.PHONY: bindings
bindings: ## Build all bindings
	@$(MAKE) go
	@$(MAKE) kotlin
	@$(MAKE) python

.PHONY: bindings-examples
bindings-examples: ## Run all bindings examples
	@$(MAKE) go-examples
	@$(MAKE) kotlin-examples
	@$(MAKE) python-examples

.PHONY: bindings-example
bindings-example: ## Run a specific example for all bindings. Usage: make bindings-example example
	@$(MAKE) go-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) kotlin-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) python-example $(word 2,$(MAKECMDGOALS))

# Build ffi crate and detect platform
define build_binding
cargo build -p iota-sdk-ffi --lib --release; \
case "$$(uname -s)" in \
	Darwin)   LIB_EXT=".dylib" ;; \
	Linux)    LIB_EXT=".so" ;; \
	MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;; \
	*)        echo "Unsupported platform"; exit 1 ;; \
esac;
endef

.PHONY: go
go: ## Build Go bindings
	@echo "Building Go bindings..."
	@$(build_binding) \
	uniffi-bindgen-go --library target/release/libiota_sdk_ffi$${LIB_EXT} --out-dir bindings/go --no-format

.PHONY: kotlin
kotlin: ## Build Kotlin bindings
	@echo "Building Kotlin bindings..."
	@$(build_binding) \
	cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language kotlin --out-dir bindings/kotlin/lib --no-format -c bindings/kotlin/uniffi.toml; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/kotlin/lib/

.PHONY: python
python: ## Build Python bindings
	@echo "Building Python bindings..."
	@$(build_binding) \
	cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language python --out-dir bindings/python/lib --no-format; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/python/lib/

.PHONY: go-example
go-example: ## Run a specific Go example. Usage: make go-example example
%:
	@true
go-example:
	@cd bindings/go/examples; \
	LD_LIBRARY_PATH="../../../target/release" CGO_LDFLAGS="-liota_sdk_ffi -L../../../target/release" go run $(word 2,$(MAKECMDGOALS)).go \
	cd -

.PHONY: go-examples
go-examples: ## Run all Go bindings examples
	@for example in $$(find bindings/go/examples -name "*.go" -exec basename {} .go \;); do \
		$(MAKE) go-example "$$example" || exit $$?; \
	done

.PHONY: kotlin-example
kotlin-example: ## Run a specific Kotlin example. Usage: make kotlin-example example
%:
	@true
kotlin-example:
	@cd bindings/kotlin; \
	./gradlew build clean; \
	LD_LIBRARY_PATH=./lib ./gradlew example -Pexample=$(word 2,$(MAKECMDGOALS)) -q; \
	cd -

.PHONY: kotlin-examples
kotlin-examples: ## Run all Kotlin bindings examples
	@for example in $$(find bindings/kotlin/examples -name "*.kt" -exec basename {} .kt \;); do \
		$(MAKE) kotlin-example "$$example" || exit $$?; \
	done

.PHONY: python-example
python-example: ## Run a specific Python example. Usage: make python-example example
%:
	@true
python-example:
	@PYTHONPATH=bindings/python python3 bindings/python/examples/$(word 2,$(MAKECMDGOALS)).py

.PHONY: python-examples
python-examples: ## Run all Python bindings examples
	@for example in $$(find bindings/python/examples -name "*.py" -exec basename {} .py \;); do \
		$(MAKE) python-example "$$example" || exit $$?; \
	done

.PHONY: help
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
