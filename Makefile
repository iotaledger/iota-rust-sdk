# Set the default target of this Makefile
.PHONY: all
all:: ci ## Default target, runs the CI process

.PHONY: check-features
check-features: ## Check feature flags for crates
	$(MAKE) -C crates/iota-sdk-types check-features
	$(MAKE) -C crates/iota-sdk-crypto check-features
	$(MAKE) -C crates/iota-sdk-move-types check-features

.PHONY: check-fmt
check-fmt: ## Check code formatting
	cargo +nightly-2026-06-29 fmt -- --check

.PHONY: fmt
fmt: ## Format code
	cargo +nightly-2026-06-29 fmt

.PHONY: fetch-compiled-packages
fetch-compiled-packages: ## Fetch the compiled Move packages if missing or out of date (used by `make test`)
	@bash crates/iota-sdk-move-types/update_compiled_packages.sh --ensure

.PHONY: clippy
clippy: ## Run Clippy linter
	cargo clippy --all-features --all-targets

# Crates left out of `cargo semver-checks`, which needs a crates.io release to
# diff against: these have none yet. `iota-sdk` does have releases, but its
# latest stable one is the unrelated legacy SDK that previously held the name,
# so it stays excluded until 3.0.0 is published.
SEMVER_CHECKS_EXCLUDE = iota-sdk iota-sdk-grpc-client iota-sdk-grpc-types iota-sdk-move-types

.PHONY: semver-checks
semver-checks: ## Check the published crates for breaking API changes
	cargo semver-checks --workspace $(addprefix --exclude ,$(SEMVER_CHECKS_EXCLUDE))

.PHONY: test
test: fetch-compiled-packages ## Run unit tests
	cargo nextest run --all-features -p iota-sdk-types -p iota-sdk-crypto -p iota-sdk-transaction-builder -p iota-sdk-move-types
	cargo nextest run --no-default-features -p iota-sdk-grpc-client

.PHONY: test-docs
test-docs: ## Run doc tests
	cargo test --all-features --doc

.PHONY: build-docs
build-docs: ## Build docs
	cargo doc --all-features --workspace --no-deps

package_%.json: crates/integration-tests/%/Move.toml crates/integration-tests/%/sources/*.move ## Generate JSON files for tests
	cd crates/integration-tests/$(*F) && iota move build --ignore-chain --allow-view-function true --dump-bytecode-as-base64 | grep '^{' > ../../$@

.PHONY: test-with-localnet
test-with-localnet: package_test_example_v1.json package_test_example_v2.json ## Run tests with localnet
	cargo nextest run -p iota-sdk-graphql-client -p integration-tests

# Verify that individual SDK crates compile to wasm32-unknown-unknown.
# This is a quick compatibility check, not the full WASM bindings build.
.PHONY: wasm32
wasm32: ## Check that SDK crates compile to wasm32
	$(MAKE) -C crates/iota-sdk wasm
	$(MAKE) -C crates/iota-sdk-crypto wasm
	$(MAKE) -C crates/iota-sdk-graphql-client wasm
	$(MAKE) -C crates/iota-sdk-move-types wasm
	$(MAKE) -C crates/iota-sdk-transaction-builder wasm
	$(MAKE) -C crates/iota-sdk-types wasm

# Build the full WASM bindings package for browsers.
# Uses ubrn (uniffi-bindgen-react-native) to generate TS bindings, compile
# to wasm32, and run wasm-bindgen. Then esbuild bundles into dist/.
.PHONY: wasm
wasm: ## Build WASM bindings for browsers
	cd bindings/wasm && pnpm install --frozen-lockfile && npx ubrn build web --config ubrn.config.yaml --profile wasm-release
	@# If wasm-opt is installed on PATH, shrink the wasm-bindgen output;
	@# the build works without it (no flag involved).
	@if command -v wasm-opt >/dev/null 2>&1; then \
		printf "Running wasm-opt for size reduction...\n"; \
		wasm-opt -Oz --vacuum --strip-debug \
			--enable-bulk-memory --enable-mutable-globals --enable-sign-ext --enable-nontrapping-float-to-int \
			bindings/wasm/src/ts/wasm-bindgen/index_bg.wasm \
			-o bindings/wasm/src/ts/wasm-bindgen/index_bg.wasm; \
	fi
	cd bindings/wasm && pnpm run build
	@# `ubrn build web` overwrites the tracked placeholders
	@# bindings/wasm/iota-sdk-wasm/{Cargo.toml,src/lib.rs} with generated content (the
	@# generated bridge src/iota_sdk_ffi_module.rs stays and is gitignored).
	@# Restore the placeholders so the tree stays clean (`make is-dirty`) and the
	@# workspace keeps a profile-free member manifest.
	@git checkout -- bindings/wasm/iota-sdk-wasm/Cargo.toml bindings/wasm/iota-sdk-wasm/src/lib.rs
	@printf "WASM bindings built successfully in bindings/wasm/dist/\n"

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
ci: check-features check-fmt check-sort-derives test wasm32 ## Run the full CI process

.PHONY: ci-full
ci-full: ci doc ## Run the full CI process and generate documentation

.PHONY: cargo-sort
cargo-sort: ## Sort, consolidate, and format Cargo.toml dependencies
	cd scripts/cargo_sort && ./run_consolidate.sh

.PHONY: sort-derives
sort-derives: ## Sort `#[derive(...)]` trait lists alphabetically across the workspace
	python3 scripts/sort_derives/sort_derives.py

.PHONY: check-sort-derives
check-sort-derives: ## Check that all `#[derive(...)]` trait lists are sorted alphabetically
	python3 scripts/sort_derives/sort_derives.py --check

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

.PHONY: clean-all
clean-all: clean ## Clean all generated files, including those ignored by Git. Force removal.
	git clean -dXf

.PHONY: install-uniffi-bindgen-go
install-uniffi-bindgen-go: ## Install uniffi-bindgen-go
	cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0

.PHONY: install-uniffi-bindgen-cs
install-uniffi-bindgen-cs: ## Install uniffi-bindgen-cs
	cargo install uniffi-bindgen-cs --git https://github.com/NordSecurity/uniffi-bindgen-cs --tag v0.11.0+v0.31.0

.PHONY: bindings
bindings: ## Build all bindings
	@$(MAKE) go
	@$(MAKE) kotlin
	@$(MAKE) python
	@$(MAKE) csharp
	@$(MAKE) swift
	@$(MAKE) wasm

.PHONY: bindings-example
bindings-example: ## Run a specific example for all bindings. Usage: make bindings-example example
	@$(MAKE) go-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) kotlin-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) python-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) csharp-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) swift-example $(word 2,$(MAKECMDGOALS))
	@$(MAKE) wasm-example $(word 2,$(MAKECMDGOALS))

.PHONY: bindings-examples
bindings-examples: ## Run all bindings examples
	@$(MAKE) go-examples
	@$(MAKE) kotlin-examples
	@$(MAKE) python-examples
	@$(MAKE) csharp-examples
	@$(MAKE) swift-examples
	@$(MAKE) wasm-examples

.PHONY: bindings-examples-format-check
bindings-examples-format-check: ## Check format of all bindings examples
	@$(MAKE) go-examples-format-check
	@$(MAKE) kotlin-examples-format-check
	@$(MAKE) python-examples-format-check
	@$(MAKE) csharp-examples-format-check
	@$(MAKE) swift-examples-format-check
	@$(MAKE) wasm-examples-format-check

.PHONY: bindings-examples-format
bindings-examples-format: ## Format all bindings examples
	@$(MAKE) go-examples-format
	@$(MAKE) kotlin-examples-format
	@$(MAKE) python-examples-format
	@$(MAKE) csharp-examples-format
	@$(MAKE) swift-examples-format
	@$(MAKE) wasm-examples-format

# Build the FFI crate (release) and detect the shared library extension
# (sets LIB_EXT, used to locate libiota_sdk_ffi).
define build_binding
cargo build -p iota-sdk-ffi --lib --release; \
case "$$(uname -s)" in \
	Darwin)   LIB_EXT=".dylib" ;; \
	Linux)    LIB_EXT=".so" ;; \
	MINGW*|MSYS*|CYGWIN*|Windows_NT) LIB_EXT=".dll" ;; \
	*)        echo "Unsupported platform"; exit 1 ;; \
esac;
endef

# Convert a snake_case example name (used by Go/Python, and accepted by Kotlin) to the
# PascalCase form used for C# project and Swift target names. Idempotent for names that
# are already PascalCase, so both `make csharp-example chain_id` and
# `make csharp-example ChainId` resolve to the same example.
snake_to_pascal = $(shell printf '%s' "$(1)" | awk -F_ '{ s=""; for (i=1; i<=NF; i++) s = s toupper(substr($$i,1,1)) substr($$i,2); print s }')

.PHONY: go
go: ## Build Go bindings
	@printf "Building Go bindings...\n"
	@$(build_binding) \
	uniffi-bindgen-go --library target/release/libiota_sdk_ffi$${LIB_EXT} --out-dir bindings/go --no-format --config bindings/go/uniffi.toml || exit $$?
	@# TODO: For some reason only the .h file is renamed, not the .go file
	@mv bindings/go/iota_sdk/iota_sdk_ffi.go bindings/go/iota_sdk/iota_sdk.go
	@sed -i.bak "s/^package iota_sdk_ffi$$/package iota_sdk/" bindings/go/iota_sdk/iota_sdk.go && rm bindings/go/iota_sdk/iota_sdk.go.bak
	
.PHONY: kotlin
kotlin: ## Build Kotlin bindings
	@printf "Building Kotlin bindings...\n"
	@$(build_binding) \
	cargo run --bin uniffi-bindgen -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language kotlin --out-dir bindings/kotlin/lib --no-format -c bindings/kotlin/uniffi.toml || exit $$?; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/kotlin/lib/
	@mv bindings/kotlin/lib/iota_sdk/iota_sdk_ffi.kt bindings/kotlin/lib/iota_sdk/iota_sdk.kt

.PHONY: python
python: ## Build Python bindings
	@printf "Building Python bindings...\n"
	@$(build_binding) \
	cargo run --bin uniffi-bindgen -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language python --out-dir bindings/python/lib --no-format || exit $$?; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/python/lib/
	@mv bindings/python/lib/iota_sdk_ffi.py bindings/python/lib/iota_sdk.py

.PHONY: csharp
csharp: ## Build C# bindings
	@printf "Building C# bindings...\n"
	@$(build_binding) \
	uniffi-bindgen-cs --library target/release/libiota_sdk_ffi$${LIB_EXT} --out-dir bindings/csharp/src/IotaSdk --no-format --config bindings/csharp/uniffi.toml || exit $$?; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/csharp/src/IotaSdk/; \
	mv bindings/csharp/src/IotaSdk/iota_sdk_ffi.cs bindings/csharp/src/IotaSdk/IotaSdk.cs
	@# Fix common compilation issues in generated bindings
	@# byte[][length] -> byte[length][]: NordSecurity/uniffi-bindgen-cs#147
	sed -i.bak 's/new byte\[\]\[(length)\]/new byte[(length)][]/' bindings/csharp/src/IotaSdk/IotaSdk.cs
	sed -i.bak '/class Validator.*: IDisposable/,/^}/ { s/FFIObjectUtil\.DisposeAll(/\/\/ FFIObjectUtil.DisposeAll(/; }' bindings/csharp/src/IotaSdk/IotaSdk.cs
	@# Object? / Object -> object? / object: NordSecurity/uniffi-bindgen-cs#169
	sed -i.bak 's/params Object?\[\]/params object?[]/' bindings/csharp/src/IotaSdk/IotaSdk.cs
	sed -i.bak 's/void Dispose(Object?/void Dispose(object?/' bindings/csharp/src/IotaSdk/IotaSdk.cs
	sed -i.bak 's/Object lock_ = new Object();/object lock_ = new object();/' bindings/csharp/src/IotaSdk/IotaSdk.cs
	@# String.Format -> string.Format: NordSecurity/uniffi-bindgen-cs#170
	sed -i.bak 's/String\.Format/string.Format/g' bindings/csharp/src/IotaSdk/IotaSdk.cs
	sed -i.bak 's/IotaSdkFfiMethods/Iota/g' bindings/csharp/src/IotaSdk/IotaSdk.cs
	rm bindings/csharp/src/IotaSdk/IotaSdk.cs.bak

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
	@for example in $$(find bindings/go/examples/* -type d -not -name release -exec basename {} \;); do \
		$(MAKE) go-example "$$example" || exit $$?; \
	done

.PHONY: go-examples-format-check
go-examples-format-check: ## Check format of all Go bindings examples
	@test -z "$$(find bindings/go/examples -name "*.go" -exec gofmt -l {} \;)"

.PHONY: go-examples-format
go-examples-format: ## Format all Go bindings examples
	@find bindings/go/examples -name "*.go" -exec gofmt -w {} \;

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

.PHONY: kotlin-android
kotlin-android: ## Build Android native libraries for all ABIs
	@printf "Building Android native libraries...\n"
	@for target_abi in "aarch64-linux-android android-aarch64" "armv7-linux-androideabi android-arm" "x86_64-linux-android android-x86-64" "i686-linux-android android-x86"; do \
		set -- $$target_abi; \
		target=$$1; folder=$$2; \
		printf "Building for $$target...\n"; \
		cargo ndk -t $$target -P 21 build -p iota-sdk-ffi --lib --release || exit $$?; \
		mkdir -p bindings/kotlin/lib/$$folder; \
		cp target/$$target/release/libiota_sdk_ffi.so bindings/kotlin/lib/$$folder/ || exit $$?; \
	done
	@printf "Android native libraries built successfully.\n"

.PHONY: kotlin-examples
kotlin-examples: ## Run all Kotlin bindings examples
	@for example in $$(find bindings/kotlin/examples -name "*.kt" -not -path "*/release/*" -not -path "*/android-demo/*" -exec basename {} .kt \;); do \
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
	@for example in $$(find bindings/python/examples -name "*.py" -not -path "*/release/*" -exec basename {} .py \;); do \
		$(MAKE) python-example "$$example" || exit $$?; \
	done

.PHONY: python-examples-format-check
python-examples-format-check: ## Check format of all Python bindings examples
	@yapf --style google -d $$(find bindings/python/examples -name "*.py") --recursive

.PHONY: python-examples-format
python-examples-format: ## Format all Python bindings examples
	@yapf --style google -i $$(find bindings/python/examples -name "*.py") --recursive

.PHONY: csharp-example
csharp-example: ## Run a specific C# example. Usage: make csharp-example ExampleName (e.g. ChainId)
%:
	@true
csharp-example:
	@printf "\nRunning C# example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@cd bindings/csharp/examples; \
	dotnet run --project $(call snake_to_pascal,$(word 2,$(MAKECMDGOALS))) || exit $$?; \
	cd -

.PHONY: csharp-examples
csharp-examples: ## Run all C# bindings examples
	@for example in $$(find bindings/csharp/examples -name "*.csproj" -not -path "*/Release/*" -exec dirname {} \; | xargs -n 1 basename); do \
		$(MAKE) csharp-example "$$example" || exit $$?; \
	done

.PHONY: csharp-examples-format-check
csharp-examples-format-check: ## Check format of all C# bindings examples
	@dotnet restore bindings/csharp/examples/Examples.sln && dotnet format --verify-no-changes bindings/csharp/examples/Examples.sln || exit $$?

.PHONY: csharp-examples-format
csharp-examples-format: ## Format all C# bindings examples
	@dotnet restore bindings/csharp/examples/Examples.sln && dotnet format bindings/csharp/examples/Examples.sln || exit $$?

.PHONY: swift
swift: ## Build Swift bindings
	@printf "Building Swift bindings...\n"
	@$(build_binding) \
	cargo run --bin uniffi-bindgen -- generate --library "target/release/libiota_sdk_ffi$${LIB_EXT}" --language swift --out-dir bindings/swift/Sources/IotaSDK --no-format -c bindings/swift/uniffi.toml || exit $$?; \
	mkdir -p bindings/swift/Sources/CIotaSDK; \
	mv bindings/swift/Sources/IotaSDK/CIotaSDK.h bindings/swift/Sources/CIotaSDK/CIotaSDK.h; \
	mv bindings/swift/Sources/IotaSDK/CIotaSDK.modulemap bindings/swift/Sources/CIotaSDK/module.modulemap; \
	cp target/release/libiota_sdk_ffi$${LIB_EXT} bindings/swift/Sources/CIotaSDK/

.PHONY: swift-example
swift-example: ## Run a specific Swift example. Usage: make swift-example example
%:
	@true
swift-example:
	@printf "\nRunning Swift example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@cd bindings/swift; \
	LD_LIBRARY_PATH="../../target/release" DYLD_LIBRARY_PATH="../../target/release" LIBRARY_PATH="../../target/release" swift run $(call snake_to_pascal,$(word 2,$(MAKECMDGOALS))) || exit $$?; \
	cd -

.PHONY: swift-examples
swift-examples: ## Run all Swift bindings examples
	@for example in $$(find bindings/swift/examples -name "*.swift" -not -path "*/release/*" -exec basename {} .swift \;); do \
		$(MAKE) swift-example "$$example" || exit $$?; \
	done

.PHONY: swift-examples-format-check
swift-examples-format-check: ## Check format of all Swift bindings examples
	@swift-format lint --recursive bindings/swift/examples --strict 2>&1 | grep -v "^$$" && exit 1 || true

.PHONY: swift-examples-format
swift-examples-format: ## Format all Swift bindings examples
	@swift-format format --recursive bindings/swift/examples --in-place

# WASM examples are .mjs scripts executed via Node.js against the same bundle
# that ships to npm. The dev-server / browser story for the HTML examples is
# behind `make wasm-serve` (see below).
.PHONY: wasm-example
wasm-example: ## Run a specific WASM example with Node. Usage: make wasm-example chain_id
%:
	@true
wasm-example:
	@printf "\nRunning WASM example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@node bindings/wasm/examples/$(word 2,$(MAKECMDGOALS)).mjs || exit $$?

.PHONY: wasm-examples
wasm-examples: ## Run all WASM bindings examples
	@for example in $$(find bindings/wasm/examples -name "*.mjs" -not -name "_*" -not -path "*/release/*" -exec basename {} .mjs \;); do \
		$(MAKE) wasm-example "$$example" || exit $$?; \
	done

.PHONY: wasm-examples-format-check
wasm-examples-format-check: ## Check format of all WASM bindings examples
	@cd bindings/wasm && pnpm run examples:format-check

.PHONY: wasm-examples-format
wasm-examples-format: ## Format all WASM bindings examples
	@cd bindings/wasm && pnpm run examples:format

.PHONY: wasm-serve
wasm-serve: ## Serve the WASM browser examples at http://localhost:5173/examples/
	@cd bindings/wasm && pnpm run serve

.PHONY: example
example: ## Run a specific Rust example. Usage: make example example
%:
	@true
example:
	@printf "\nRunning Rust example \"$(word 2,$(MAKECMDGOALS))\"\n"
	@# --all-features so examples gated behind non-default features (e.g.
	@# `move-types`) build and run; extra features are additive.
	@cargo run --all-features --example $(word 2,$(MAKECMDGOALS)) || exit $$?;

.PHONY: examples
examples: ## Run all Rust examples
	@# NOTE: -maxdepth 1 -type f excludes package-based examples like polling-indexer
	@# that require external services (e.g. PostgreSQL). Run those separately.
	@for example in $$(find crates/iota-sdk/examples -maxdepth 1 -type f -name "*.rs" -exec basename {} .rs \;); do \
		$(MAKE) example "$$example" || exit $$?; \
	done

.PHONY: rust-release-example
rust-release-example: ## Run the Rust release example
	@printf "\nRunning Rust release example\n"
	@cd crates/iota-sdk/examples/release && cargo run || exit $$?

.PHONY: go-release-example
go-release-example: ## Run the Go release example
	@printf "\nRunning Go release example\n"
	@cd bindings/go/examples/release && go get github.com/iotaledger/iota-sdk-go && go run main.go || exit $$?

.PHONY: kotlin-release-example
kotlin-release-example: ## Run the Kotlin release example
	@printf "\nRunning Kotlin release example\n"
	@cd bindings/kotlin/examples/release && gradle run || exit $$?

.PHONY: python-release-example
python-release-example: ## Run the Python release example
	@printf "\nRunning Python release example\n"
	@cd bindings/python/examples/release && python3 -m venv .venv && . .venv/bin/activate && pip install --pre --upgrade -r requirements.txt && python example.py || exit $$?;

.PHONY: csharp-release-example
csharp-release-example: ## Run the C# release example
	@printf "\nRunning C# release example\n"
	@cd bindings/csharp/examples/Release && dotnet run

.PHONY: swift-release-example
swift-release-example: ## Run the Swift release example
	@printf "\nRunning Swift release example\n"
	@cd bindings/swift/examples/release && swift run || exit $$?

.PHONY: wasm-release-example
wasm-release-example: ## Run the WASM release example
	@printf "\nRunning WASM release example\n"
	@cd bindings/wasm/examples/release && npm install && node example.mjs || exit $$?

.PHONY: release-examples
release-examples: ## Run all release examples
	@$(MAKE) rust-release-example
	@$(MAKE) go-release-example
	@$(MAKE) kotlin-release-example
	@$(MAKE) python-release-example
	@$(MAKE) csharp-release-example
	@$(MAKE) swift-release-example
	@$(MAKE) wasm-release-example

.PHONY: bcs-schema
bcs-schema: ## Regenerate bcs-schema.abnf
	@printf "Regenerating bcs-schema.abnf...\n"
	@BCS_SCHEMA=1 cargo check -p iota-sdk-types --features bcs-schema,hash || exit $$?
	@BCS_SCHEMA=1 cargo check -p iota-sdk-move-types --features bcs-schema || exit $$?

.PHONY: grpc
grpc: ## Regenerate gRPC protobuf types
	@./crates/iota-sdk-grpc-proto-build/update_grpc_types.sh

.PHONY: update-compiled-packages
update-compiled-packages: ## Force re-fetch the compiled Move packages (REF=branch-or-sha overrides the pinned rev)
	@bash crates/iota-sdk-move-types/update_compiled_packages.sh $(REF)

.PHONY: help
help: ## Show this help
	@printf "Available targets:\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
