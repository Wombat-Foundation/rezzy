#!/bin/bash -x
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
prettier --prose-wrap always --print-width 80 --write .
