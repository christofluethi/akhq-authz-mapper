#!/usr/bin/env bash
# Run the akhq-authz-mapper.js test suite using Node's built-in test runner.
# Requires Node.js >= 18 (uses node:test, node:assert/strict, node:vm).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: 'node' not found on PATH. Install Node.js >= 18." >&2
    exit 1
fi

exec node --test "${SCRIPT_DIR}/test/akhq-authz-mapper.test.js" "$@"
