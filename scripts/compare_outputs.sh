#!/usr/bin/env bash
# Compares the resolved state of two runs and diffs them if they differ.
# Usage: ./scripts/compare_outputs.sh <json1> <json2>

set -e

JSON1=$1
JSON2=$2

if [[ -z "$JSON1" || -z "$JSON2" ]]; then
	echo "Usage: $0 <json1> <json2>"
	exit 1
fi

TMP1=$(mktemp).json
TMP2=$(mktemp).json

# Extract, sort, and filter essential fields for each event in the state array
# Essential fields: event_id, type, state_key, content
cat "$JSON1" | jq -S '.state | map({event_id, type, state_key, content}) | sort_by(.event_id)' >"$TMP1"
cat "$JSON2" | jq -S '.state | map({event_id, type, state_key, content}) | sort_by(.event_id)' >"$TMP2"

if ! diff -u "$TMP1" "$TMP2"; then
	echo "Error: Resolved state differs between $JSON1 and $JSON2"
	rm -f "$TMP1" "$TMP2"
	exit 1
fi

echo "✓ States are identical!"
rm -f "$TMP1" "$TMP2"
exit 0
