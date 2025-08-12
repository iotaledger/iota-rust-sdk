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

# Build all bindings
.PHONY: bindings
bindings: ## Build all bindings
	$(MAKE) go
	$(MAKE) kotlin
	$(MAKE) python

# Test all bindings
.PHONY: test-bindings
test-bindings: ## Test all bindings
	$(MAKE) test-go
	$(MAKE) test-kotlin
	$(MAKE) test-python

# Build Go bindings
.PHONY: go
go: ## Build Go bindings
	cargo build -p iota-sdk-ffi --lib --release;
	case "$$(uname -s)" in \
	  Darwin)   LIB_EXT=".dylib" ;; \
	  Linux)    LIB_EXT=".so" ;; \
	  MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;; \
	  *)        echo "Unsupported platform"; exit 1 ;; \
	esac; \
	uniffi-bindgen-go --library target/release/libiota_sdk_ffi$${LIB_EXT} --out-dir bindings/go --no-format

# Test Go bindings
.PHONY: test-go
test-go: ## Test Go bindings
	cd bindings/go/; \
	LD_LIBRARY_PATH="../../target/release" CGO_LDFLAGS="-liota_sdk_ffi -L../../target/release" go run test.go \
	cd -

# Build Kotlin bindings
.PHONY: kotlin
kotlin: ## Build Kotlin bindings
	cargo build -p iota-sdk-ffi --lib --release; \
	case "$$(uname -s)" in \
	  Darwin)   LIB_EXT=".dylib" ;; \
	  Linux)    LIB_EXT=".so" ;; \
	  MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;; \
	  *)        echo "Unsupported platform"; exit 1 ;; \
	esac; \
	cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language kotlin --out-dir bindings/kotlin/lib --no-format -c bindings/kotlin/uniffi.toml; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/kotlin/lib/

# Test Kotlin bindings
.PHONY: test-kotlin
test-kotlin: ## Test Kotlin bindings
	cd bindings/kotlin; \
	./gradlew build clean; \
	LD_LIBRARY_PATH=./lib ./gradlew run -q; \
	cd -

# Build Python bindings
.PHONY: python
python: ## Build Python bindings
	cargo build -p iota-sdk-ffi --lib --release; \
	case "$$(uname -s)" in \
	  Darwin)   LIB_EXT=".dylib" ;; \
	  Linux)    LIB_EXT=".so" ;; \
	  MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;; \
	  *)        echo "Unsupported platform"; exit 1 ;; \
	esac; \
	cargo run --bin iota_sdk_bindings -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language python --out-dir bindings/python/lib --no-format; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/python/lib/

# Test Python bindings
.PHONY: test-python
test-python: ## Test Python bindings
	python3 bindings/python/test.py

.PHONY: help
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
