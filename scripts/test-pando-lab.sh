#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Optional explicit tool environment; never reuse its database URL.
if [[ -n "${ROOTYARD_TOOLS_ENV:-}" ]]; then source "$ROOTYARD_TOOLS_ENV"; fi
if [[ -n "${ROOTYARD_GIT_ENV:-}" ]]; then source "$ROOTYARD_GIT_ENV"; fi
unset DATABASE_URL TEST_DATABASE_URL ROOTYARD_TEST_DATABASE_URL
if [[ "${PANDO_SKIP_BUILD:-0}" != 1 ]]; then cargo build --locked --features pando-lab --bin rootyard-pando-lab; fi
exec python3 tests/pando_lab.py --binary "${PANDO_BINARY:-${CARGO_TARGET_DIR:-target}/debug/rootyard-pando-lab}" "$@"
