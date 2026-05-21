SHELL=/bin/bash
.DEFAULT_GOAL=_help

LAKE ?= lake
CARGO ?= cargo

LINT_LOCS_PY = $$(git ls-files '*.py')
LINT_LOCS_SH = $$(git ls-files '*.sh')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Formatting & linting (shared)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: format
format: ##H Format codebase (Rust + Lean + scripts)
	-prettier -w .
	-pre-commit run --all-files
	-black $(LINT_LOCS_PY)
	-isort $(LINT_LOCS_PY)
	-shfmt -w $(LINT_LOCS_SH)
	cargo sort --workspace --grouped

.PHONY: lint
lint: ##H Run all linters
	$(CARGO) clippy --all-targets --all-features

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Lean targets
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: lean/build
lean/build: ##H Build Lean proofs
	$(LAKE) build
	@printf "\n$${STYLE_GREEN}--- Verification Complete ---$${STYLE_RESET}\n"
	@printf "$${STYLE_CYAN}Mapped Theorems & Definitions:$${STYLE_RESET}\n"
	@grep -E '^(theorem|def|class|instance|structure) ' RumaLean/*.lean RumaLean.lean || true
	@printf "$${STYLE_GREEN}--------------------------------$${STYLE_RESET}\n"

.PHONY: lean/clean
lean/clean: ##H Remove Lean build artifacts (preserves packages)
	rm -rf .lake/build/

.PHONY: lean/cache
lean/cache: ##H Fetch Lean/Mathlib oleans from cache
	$(LAKE) exe cache get

.PHONY: lean/docs
lean/docs: ##H Generate Lean docs
	DOCGEN_SKIP_LEAN=1 DOCGEN_SKIP_STD=1 DOCGEN_SKIP_LAKE=1 DOCGEN_SKIP_DEPS=1 $(LAKE) build RumaLean:docs

.PHONY: lean/nuke
lean/nuke: ##H Full Lean reset (removes packages too — will re-clone)
	rm -rf .lake/

# Convenience alias
.PHONY: lean
lean: lean/build ##H Alias for lean/build


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Rust targets
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: rust/build
rust/build: ##H Compile Rust binary (release)
	$(CARGO) build --release --features cli

.PHONY: rust/test
rust/test: fixtures ##H Run Rust tests
	$(CARGO) test --all-targets --all-features

.PHONY: rust/clean
rust/clean: ##H Remove Rust build artifacts
	-$(CARGO) clean

.PHONY: rust/install
rust/install: ##H Install ruma-lean binary to cargo bin
	$(CARGO) install --features cli --path .

.PHONY: rust/coverage
rust/coverage: ##H Run code coverage and generate HTML report
	@echo "Running focused code coverage for ruma-lean..."
	$(CARGO) tarpaulin --out Html \
		--output-dir ../.tmp/coverage-lean \
		--packages ruma-lean \
		--ignore-panics \
		--ignore-tests \
		--skip-clean
	@echo "Coverage report updated in ../.tmp/coverage-lean/tarpaulin-report.html"

.PHONY: rust/e2e
rust/e2e: ##H Run e2e integration test on real JSON
	for f in res/*.json; do \
		$(CARGO) run --release --features cli -- -i "$$f"; \
	done

.PHONY: rust/publish
rust/publish: ##H Preview package and simulate dry-run publish
	@echo "Previewing packaged files..."
	@echo "-----------------------------------"
	$(CARGO) package --list
	@echo ""
	@echo "Simulating publish (--dry-run)"
	@echo "-----------------------------------"
	$(CARGO) publish --dry-run

# Convenience aliases
.PHONY: build test install clean
build:   rust/build   ##H Alias for rust/build
test:    rust/test    ##H Alias for rust/test
install: rust/install ##H Alias for rust/install
clean:   rust/clean lean/clean ##H Remove all build artifacts


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Data generation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: fixtures
fixtures: ##H Generate synthetic data and fetch real DAGs if MATRIX_TOKEN is set
	@mkdir -p res res/expected
	@test -f res/benchmark_1k.json || python3 scripts/generate_benchmark_1k.py
	@test -f res/realistic_large_room.json || python3 scripts/gen_large_room.py
	@if [ -f .env ]; then set -a && source .env; fi; \
	if [ -f ../.env ]; then set -a && source ../.env; fi; \
	if [ -n "$$MATRIX_TOKEN" ]; then \
		test -f res/real_dag_52k_room.json || \
			python3 scripts/export_from_db.py '!da26JtAjE6APGLnX8ncWsvc-skF2KQZ9Nw_MbNpYD2k' \
				--limit 10000 -o res/real_dag_52k_room.json; \
		test -f res/real_dag_nheko.json || \
			python3 scripts/export_from_db.py '!UbCmIlGTHNIgIRZcpt:nheko.im' \
				--limit 6000 -o res/real_dag_nheko.json; \
		test -f res/real_matrix_state_v2_1.json || \
			python3 scripts/fetch_matrix_state.py || echo "Warning: v2.1 fetch failed"; \
		test -f res/real_matrix_state.json || \
			python3 scripts/fetch_matrix_state.py || echo "Warning: state fetch failed"; \
	else \
		echo "No MATRIX_TOKEN found, skipping live fetch."; \
		echo "  Set MATRIX_TOKEN and MATRIX_SERVER in .env to generate real DAG fixtures."; \
	fi


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Help
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# [ENUM] Styling / Colors
STYLE_CYAN := $(shell tput setaf 6 2>/dev/null || echo '\033[36m')
STYLE_GREEN := $(shell tput setaf 2 2>/dev/null || echo '\033[32m')
STYLE_RESET := $(shell tput sgr0 2>/dev/null || echo '\033[0m')
export STYLE_CYAN STYLE_GREEN STYLE_RESET

.PHONY: _help
_help:
	@grep -hE '^[a-zA-Z0-9_\/-]+:[[:space:]]*##H .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":[[:space:]]*##H "}; {printf "$(STYLE_CYAN)%-18s$(STYLE_RESET) %s\n", $$1, $$2}'
