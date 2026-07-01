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

.PHONY: fix
fix:	##H Clippy auto-fix
	$(CARGO) +nightly clippy --allow-dirty --fix --all-targets --all-features -- -W clippy::perf -W clippy::pedantic
	$(CARGO) fix --all-targets --all-features --allow-dirty

.PHONY: lint
lint: ##H Run all linters
	$(CARGO) +nightly clippy --all-targets --all-features -- -W clippy::perf -W clippy::pedantic

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Lean targets
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#.PHONY: lean/build
#lean/build: ##H Build Lean proofs
#	$(LAKE) build
#	@printf "\n$${STYLE_GREEN}--- Verification Complete ---$${STYLE_RESET}\n"
#	@printf "$${STYLE_CYAN}Mapped Theorems & Definitions:$${STYLE_RESET}\n"
#	@grep -E '^(theorem|def|class|instance|structure) ' RumaLean/*.lean RumaLean.lean || true
#	@printf "$${STYLE_GREEN}--------------------------------$${STYLE_RESET}\n"
#
#.PHONY: lean/clean
#lean/clean: ##H Remove Lean build artifacts (preserves packages)
#	rm -rf .lake/build/
#
#.PHONY: lean/cache
#lean/cache: ##H Fetch Lean/Mathlib oleans from cache
#	$(LAKE) exe cache get
#
#.PHONY: lean/docs
#lean/docs: ##H Generate Lean docs
#	DOCGEN_SKIP_LEAN=1 DOCGEN_SKIP_STD=1 DOCGEN_SKIP_LAKE=1 DOCGEN_SKIP_DEPS=1 $(LAKE) build RumaLean:docs
#
#.PHONY: lean/nuke
#lean/nuke: ##H Full Lean reset (removes packages too — will re-clone)
#	rm -rf .lake/
#
## Convenience alias
#.PHONY: lean
#lean: lean/build ##H Alias for lean/build


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Rust targets
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: rust/build
rust/build: ##H Compile Rust binary (release)
	$(CARGO) build --release --features cli,hashing

.PHONY: rust/doc
rust/doc: ##H Generate rustdoc API documentation
	$(CARGO) doc --no-deps --features hashing
	echo '<meta http-equiv="refresh" content="0;url=rezzy/index.html">' > target/doc/index.html

.PHONY: rust/test
rust/test: fixtures ##H Run Rust tests (p=NAME for specific test, a=ARGS for test binary args)
ifdef p
	$(CARGO) test --test $(p) --all-features $(if $(a),-- $(a))
else
	$(CARGO) test --all-targets --all-features $(if $(a),-- $(a))
endif

.PHONY: rust/coverage
rust/coverage: fixtures ##H Run code coverage and generate HTML report
	# TODO: include `src/bin/` in coverage
	# Run coverage
	$(CARGO) +nightly llvm-cov --all-features --all-targets \
		--html --output-dir ../.tmp/coverage-lean \
		--ignore-filename-regex 'src/bin/.*'
	# Process report to codecov-compatible JSON
	$(CARGO) +nightly llvm-cov report \
		--ignore-filename-regex 'src/bin/.*' \
		--codecov --output-path ../.tmp/coverage-lean/codecov.json

.PHONY: rust/clean
rust/clean: ##H Remove Rust build artifacts
	-$(CARGO) clean

.PHONY: rust/install
rust/install: ##H Install rezzy binary to cargo bin
	$(CARGO) install --features cli,hashing --path . --bin rezzy

.PHONY: rust/uninstall
rust/uninstall: ##H Uninstall rezzy binary from cargo bin
	$(CARGO) uninstall rezzy

.PHONY: rust/e2e
rust/e2e: ##H Run e2e integration test on real JSON
	for f in res/*.json res/*jsonl; do \
		ARGS=""; \
		if [ "$$f" = "res/real_dag_52k_room.json" -o "$$f" = "res/real_dag_nheko.json" ]; then ARGS="--state-res v2"; fi; \
		if [ "$$f" = "res/remote-dag-sM2LwqNHGQOgLf35gqxPMy9D7oYde2q9ADg8HPBM3kE-v12-unredacted.org-PARTIAL.jsonl" ]; then ARGS="--state-res v2-1"; fi; \
		$(CARGO) run --release --features cli,hashing -- $$ARGS -i "$$f" || exit 1; \
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
.PHONY: build test install clean uninstall
build:   rust/build   ##H Alias for rust/build
test:    rust/test    ##H Alias for rust/test
cov:     rust/coverage ##H Alias for rust/coverage
install: rust/install ##H Alias for rust/install
uninstall: rust/uninstall ##H Alias for rust/uninstall

clean:   rust/clean	##H Remove all build artifacts
	find . -name __pycache__ | xargs -r rm -rf


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Data generation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.PHONY: fetch-stateres-vectors
fetch-stateres-vectors: ##H Fetch Ruma state resolution test vectors
	@mkdir -p res/ruma_upstream/MSC4297-problem-A res/ruma_upstream/MSC4297-problem-B
	@echo "Fetching MSC4297-problem-A vectors..."
	@test -f res/ruma_upstream/MSC4297-problem-A/pdus-v11.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-A/pdus-v11.json -o res/ruma_upstream/MSC4297-problem-A/pdus-v11.json
	@test -f res/ruma_upstream/MSC4297-problem-A/pdus-v12.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-A/pdus-v12.json -o res/ruma_upstream/MSC4297-problem-A/pdus-v12.json
	@test -f res/ruma_upstream/MSC4297-problem-A/state-bob.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-A/state-bob.json -o res/ruma_upstream/MSC4297-problem-A/state-bob.json
	@test -f res/ruma_upstream/MSC4297-problem-A/state-charlie.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-A/state-charlie.json -o res/ruma_upstream/MSC4297-problem-A/state-charlie.json
	@echo "Fetching MSC4297-problem-B vectors..."
	@test -f res/ruma_upstream/MSC4297-problem-B/pdus-v11.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-B/pdus-v11.json -o res/ruma_upstream/MSC4297-problem-B/pdus-v11.json
	@test -f res/ruma_upstream/MSC4297-problem-B/pdus-v12.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-B/pdus-v12.json -o res/ruma_upstream/MSC4297-problem-B/pdus-v12.json
	@test -f res/ruma_upstream/MSC4297-problem-B/state-eve.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-B/state-eve.json -o res/ruma_upstream/MSC4297-problem-B/state-eve.json
	@test -f res/ruma_upstream/MSC4297-problem-B/state-zara.json || curl -sL https://raw.githubusercontent.com/ruma/ruma/main/crates/ruma-state-res/tests/it/resolve/fixtures/MSC4297-problem-B/state-zara.json -o res/ruma_upstream/MSC4297-problem-B/state-zara.json

.PHONY: fixtures
fixtures: fetch-stateres-vectors ##H Generate synthetic data and fetch real DAGs if MATRIX_TOKEN is set
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
