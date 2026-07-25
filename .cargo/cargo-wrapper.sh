#!/usr/bin/env bash
set -e

RUSTC="$1"
shift

CMD=("$RUSTC")

# Codex's sandbox cannot connect to the host sccache daemon.
if [[ -z "$NO_SCCACHE" && -z "$CODEX_THREAD_ID" ]] && command -v sccache >/dev/null 2>&1; then
	CMD=(sccache "$RUSTC")
fi

MOLD_ARGS=()
if command -v mold >/dev/null 2>&1; then
	# Do not use mold if cross-compiling to webassembly or riscv (SP1)
	if [[ "$*" == *"wasm32"* ]] || [[ "$*" == *"riscv"* ]]; then
		: # skip mold
	else
		MOLD_ARGS=("-C" "link-arg=-fuse-ld=mold")
	fi
fi

exec "${CMD[@]}" "$@" "${MOLD_ARGS[@]}"
