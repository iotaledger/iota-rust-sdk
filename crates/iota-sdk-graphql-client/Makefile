# Set the default target of this Makefile
.PHONY: all
all:: check-features clippy test wasm

.PHONY: check-features
check-features:
	cargo hack check --feature-powerset --no-dev-deps

.PHONY: clippy
clippy:
	cargo clippy --all-features --all-targets

.PHONY: test
test:
	cargo nextest run --all-features
	cargo test --all-features --doc

.PHONY: wasm
wasm:
	CC=clang wasm-pack test -r --node --all-features

.PHONY: check-graphql-naming-policy
check-graphql-naming-policy: ## Check GraphQL naming and module-policy guardrails
	bash scripts/check-naming-policy.sh

%:
	$(MAKE) -C ../.. $@
