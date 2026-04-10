SHELL=/bin/bash
.DEFAULT_GOAL=_help

LAKE ?= ~/.elan/bin/lake


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Init and format
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: cache
cache: ##H Update Lean cache
	$(LAKE) exe cache get


LINT_LOCS_LEAN = $$(git ls-files '**/*.lean')

.PHONY: format
format: ##H Format codebase
	-prettier -w .
	-pre-commit run --all-files

.PHONY: clean
clean: ##H Remove build artifacts
	-$(LAKE) clean
	-$(CARGO) clean
	# rm -rf res/ .tmp/ .lake/build/



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Main target
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: prove
prove: ##H Run Lean theorem proofs and verification
	$(LAKE) build
	@printf "\n$${STYLE_GREEN}--- Verification Complete ---$${STYLE_RESET}\n"
	@printf "$${STYLE_CYAN}Mapped Theorems & Definitions:$${STYLE_RESET}\n"
	@grep -E '^(theorem|def|class|instance|structure) ' RumaLean/*.lean RumaLean.lean || true
	@printf "$${STYLE_GREEN}--------------------------------$${STYLE_RESET}\n"

.PHONY: docs
docs: ##H Generate Lean documentation via doc-gen4 (skipping core libs and deps)
	DOCGEN_SKIP_LEAN=1 DOCGEN_SKIP_STD=1 DOCGEN_SKIP_LAKE=1 DOCGEN_SKIP_DEPS=1 $(LAKE) build RumaLean:docs

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Rust development
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CARGO ?= cargo

.PHONY: coverage
coverage: ##H Run Rust code coverage and generate HTML report (focused on ruma-lean)
	@echo "Running focused code coverage for ruma-lean (std and no_std)..."
	# Run std coverage
	$(CARGO) tarpaulin --out Html \
		--output-dir ../.tmp/coverage-lean \
		--packages ruma-lean \
		--ignore-panics \
		--ignore-tests \
		--skip-clean
	# Append alloc-only coverage if possible, or just note that 100% requires feature toggling
	@echo "Coverage report updated in ../.tmp/coverage-lean/tarpaulin-report.html"

.PHONY: lint
lint:	##H Run rust and lean linters
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(LAKE) build

.PHONY: test
test: ##H Run Rust unit tests
	$(CARGO) test

.PHONY: publish
publish: ##H Preview package file list and simulate a dry-run publish
	@echo "Previewing packaged files..."
	@echo "-----------------------------------"
	$(CARGO) package --list
	@echo ""
	@echo "Simulating publish (--dry-run)"
	@echo "-----------------------------------"
	$(CARGO) publish --dry-run



# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Data Generation & Benchmarking
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: data
data: ##H Generate synthetic benchmark data and fetch matrix state if credentials exist
	@mkdir -p res
	python3 scripts/generate_benchmark_1k.py
	@if [ -f .env ]; then \
		echo "Found .env, attempting to fetch live matrix state..."; \
		set -a && source .env && python3 scripts/fetch_matrix_state.py || echo "Warning: Fetch failed, continuing..."; \
	else \
		echo "No .env found, skipping live fetch."; \
	fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Help & support commands
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# [ENUM] Styling / Colors
STYLE_CYAN := $(shell tput setaf 6 2>/dev/null || echo '\033[36m')
STYLE_GREEN := $(shell tput setaf 2 2>/dev/null || echo '\033[32m')
STYLE_RESET := $(shell tput sgr0 2>/dev/null || echo '\033[0m')
export STYLE_CYAN STYLE_GREEN STYLE_RESET

.PHONY: _help
_help:
	@grep -hE '^[a-zA-Z0-9_\/-]+:[[:space:]]*##H .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":[[:space:]]*##H "}; {printf "$(STYLE_CYAN)%-15s$(STYLE_RESET) %s\n", $$1, $$2}'
