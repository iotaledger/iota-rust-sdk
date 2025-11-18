# Set the default target of this Makefile
.PHONY: all
all:: ci ## Default target, runs the CI process

.PHONY: check-features
check-features: ## Check feature flags for crates
	$(MAKE) -C crates/iota-sdk-types check-features
	$(MAKE) -C crates/iota-sdk-crypto check-features

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
	cargo nextest run --all-features -p iota-sdk-types -p iota-sdk-crypto

.PHONY: test-docs
test-docs: ## Run doc tests
	cargo test --all-features --doc

.PHONY: build-docs
build-docs: ## Build docs
	cargo doc --all-features --workspace --no-deps

package_%.json: crates/iota-sdk-transaction-builder/tests/%/Move.toml crates/iota-sdk-transaction-builder/tests/%/sources/*.move ## Generate JSON files for tests
	cd crates/iota-sdk-transaction-builder/tests/$(*F) && iota move build --ignore-chain --dump-bytecode-as-base64 > ../../$@

.PHONY: test-with-localnet
test-with-localnet: package_test_example_v1.json package_test_example_v2.json ## Run tests with localnet
	cargo nextest run -p iota-sdk-graphql-client -p iota-sdk-transaction-builder

.PHONY: wasm
wasm: ## Build WASM modules
	$(MAKE) -C crates/iota-sdk-crypto wasm
	$(MAKE) -C crates/iota-sdk-graphql-client wasm
	$(MAKE) -C crates/iota-sdk-types wasm
	$(MAKE) -C crates/iota-sdk-transaction-builder wasm

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

.PHONY: bindings-example
bindings-example: ## Run a specific example for all bindings. Usage: make bindings-example example
	@$(MAKE) go-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) kotlin-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) python-example $(word 2,$(MAKECMDGOALS))

.PHONY: bindings-examples
bindings-examples: ## Run all bindings examples
	@$(MAKE) go-examples
	@$(MAKE) kotlin-examples
	@$(MAKE) python-examples

.PHONY: bindings-examples-format-check
bindings-examples-format-check: ## Check format of all bindings examples
	@$(MAKE) go-examples-format-check
	@$(MAKE) kotlin-examples-format-check
	@$(MAKE) python-examples-format-check

.PHONY: bindings-examples-format
bindings-examples-format: ## Format all bindings examples
	@$(MAKE) go-examples-format
	@$(MAKE) kotlin-examples-format
	@$(MAKE) python-examples-format

# Build ffi crate and detect platform
define build_binding
if [ -n "$$TARGET" ]; then \
	cargo build -p iota-sdk-ffi --lib --release --target $$TARGET; \
	ARCH=$$(echo $$TARGET | cut -d'-' -f1); \
	OS=$$(echo $$TARGET | cut -d'-' -f3); \
	case "$$OS" in \
		linux) LIB_PREFIX="lib"; LIB_EXT=".so"; \
			case "$$ARCH" in \
				aarch64) PLATFORM_DIR="linux-aarch64" ;; \
				*) PLATFORM_DIR="linux-x86-64" ;; \
			esac ;; \
		darwin) LIB_PREFIX="lib"; LIB_EXT=".dylib"; \
			case "$$ARCH" in \
				aarch64) PLATFORM_DIR="darwin-aarch64" ;; \
				*) PLATFORM_DIR="darwin-x86-64" ;; \
			esac ;; \
		windows) LIB_PREFIX=""; LIB_EXT=".dll"; \
			case "$$ARCH" in \
				aarch64) PLATFORM_DIR="win32-aarch64" ;; \
				*) PLATFORM_DIR="win32-x86-64" ;; \
			esac ;; \
		*) echo "Unsupported OS in TARGET: $$OS"; exit 1 ;; \
	esac; \
else \
	cargo build -p iota-sdk-ffi --lib --release; \
	MACHINE=$$(uname -m); \
	case "$$(uname -s)" in \
		Darwin)   LIB_PREFIX="lib"; LIB_EXT=".dylib"; \
			case "$$MACHINE" in \
				arm64) PLATFORM_DIR="darwin-aarch64" ;; \
				*) PLATFORM_DIR="darwin-x86-64" ;; \
			esac ;; \
		Linux)    LIB_PREFIX="lib"; LIB_EXT=".so"; \
			case "$$MACHINE" in \
				aarch64) PLATFORM_DIR="linux-aarch64" ;; \
				*) PLATFORM_DIR="linux-x86-64" ;; \
			esac ;; \
		MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_PREFIX=""; LIB_EXT=".dll"; \
			case "$$MACHINE" in \
				aarch64|arm64) PLATFORM_DIR="win32-aarch64" ;; \
				*) PLATFORM_DIR="win32-x86-64" ;; \
			esac ;; \
		*)        echo "Unsupported platform"; exit 1 ;; \
	esac; \
fi;
endef

.PHONY: go
go: ## Build Go bindings
	@printf "Building Go bindings...\n"
	@$(build_binding) \
	if [ -n "$$TARGET" ]; then TARGET_DIR="target/$$TARGET/release"; else TARGET_DIR="target/release"; fi; \
	LIB_NAME="$${LIB_PREFIX}iota_sdk_ffi$${LIB_EXT}"; \
	uniffi-bindgen-go --library $$TARGET_DIR/$${LIB_NAME} --out-dir bindings/go --no-format --config bindings/go/uniffi.toml || exit $$?
	# TODO: For some reason only the .h file is renamed, not the .go file
	@mv bindings/go/iota_sdk/iota_sdk_ffi.go bindings/go/iota_sdk/iota_sdk.go
	@sed -i.bak "s/^package iota_sdk_ffi$$/package iota_sdk/" bindings/go/iota_sdk/iota_sdk.go && rm bindings/go/iota_sdk/iota_sdk.go.bak
	
.PHONY: kotlin
kotlin: ## Build Kotlin bindings
	@printf "Building Kotlin bindings...\n"
	@$(build_binding) \
	if [ -n "$$TARGET" ]; then TARGET_DIR="target/$$TARGET/release"; else TARGET_DIR="target/release"; fi; \
	printf "Built library with LIB_PREFIX=$${LIB_PREFIX}, LIB_EXT=$${LIB_EXT}\n"; \
	LIB_NAME="$${LIB_PREFIX}iota_sdk_ffi$${LIB_EXT}"; \
	printf "Checking if library exists: $$TARGET_DIR/$${LIB_NAME}\n"; \
	test -f "$$TARGET_DIR/$${LIB_NAME}" || (echo "Library not found!" && exit 1); \
	cargo run --bin iota_sdk_bindings -- generate --library "$$TARGET_DIR/$${LIB_NAME}" --language kotlin --out-dir bindings/kotlin/lib --no-format -c bindings/kotlin/uniffi.toml || exit $$?; \
	mkdir -p bindings/kotlin/lib/$${PLATFORM_DIR}; \
	cp $$TARGET_DIR/$${LIB_NAME} bindings/kotlin/lib/$${PLATFORM_DIR}/

.PHONY: python
python: ## Build Python bindings
	@printf "Building Python bindings...\n"
	@$(build_binding) \
	if [ -n "$$TARGET" ]; then TARGET_DIR="target/$$TARGET/release"; else TARGET_DIR="target/release"; fi; \
	LIB_NAME="$${LIB_PREFIX}iota_sdk_ffi$${LIB_EXT}"; \
	cargo run --bin iota_sdk_bindings -- generate --library "$$TARGET_DIR/$${LIB_NAME}" --language python --out-dir bindings/python/lib --no-format || exit $$?; \
	cp $$TARGET_DIR/$${LIB_NAME} bindings/python/lib/

.PHONY: go-example
go-example: ## Run a specific Go example. Usage: make go-example example
%:
	@true
go-example:
	@printf "\nRunning Go example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@cd bindings/go/examples; \
	LD_LIBRARY_PATH="../../../target/release" CGO_LDFLAGS="-liota_sdk_ffi -L../../../target/release" go run $(word 2,$(MAKECMDGOALS))/main.go || exit $$?; \
	cd -

.PHONY: go-examples
go-examples: ## Run all Go bindings examples
	@for example in $$(find bindings/go/examples/* -type d -exec basename {} \;); do \
		$(MAKE) go-example "$$example" || exit $$?; \
	done

.PHONY: go-examples-format-check
go-examples-format-check: ## Check format of all Go bindings examples
	@test -z "$$(gofmt -l bindings/go/examples)"

.PHONY: go-examples-format
go-examples-format: ## Format all Go bindings examples
	@gofmt -w bindings/go/examples

.PHONY: kotlin-example
kotlin-example: ## Run a specific Kotlin example. Usage: make kotlin-example example
%:
	@true
kotlin-example:
	@printf "\nRunning Kotlin example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@cd bindings/kotlin; \
	./gradlew build clean || exit $$?; \
	LD_LIBRARY_PATH=./lib ./gradlew example -Pexample=$(word 2,$(MAKECMDGOALS)) -q || exit $$?; \
	cd -

.PHONY: kotlin-examples
kotlin-examples: ## Run all Kotlin bindings examples
	@for example in $$(find bindings/kotlin/examples -name "*.kt" -exec basename {} .kt \;); do \
		$(MAKE) kotlin-example "$$example" || exit $$?; \
	done

.PHONY: kotlin-examples-format-check
kotlin-examples-format-check: ## Check format of all Kotlin bindings examples
	cd bindings/kotlin; \
	./gradlew KtfmtCheck || exit $$?; \
	cd -

.PHONY: kotlin-examples-format
kotlin-examples-format: ## Format all Kotlin bindings examples
	cd bindings/kotlin; \
	./gradlew KtfmtFormat; \
	cd -

.PHONY: python-example
python-example: ## Run a specific Python example. Usage: make python-example example
%:
	@true
python-example:
	@printf "\nRunning Python example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@PYTHONPATH=bindings/python python3 bindings/python/examples/$(word 2,$(MAKECMDGOALS)).py|| exit $$?;

.PHONY: python-examples
python-examples: ## Run all Python bindings examples
	@for example in $$(find bindings/python/examples -name "*.py" -exec basename {} .py \;); do \
		$(MAKE) python-example "$$example" || exit $$?; \
	done

.PHONY: python-examples-format-check
python-examples-format-check: ## Check format of all Python bindings examples
	@yapf --style google -d bindings/python/examples/*

.PHONY: python-examples-format
python-examples-format: ## Format all Python bindings examples
	@yapf --style google -i bindings/python/examples/*

.PHONY: help
help: ## Show this help
	@printf "Available targets:\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
