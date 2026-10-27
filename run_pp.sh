#!/usr/bin/env bash
# Bash entry point for the Python symbolic profiling pipeline.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if [[ -n "${PYTHON_BIN:-}" ]]; then
    interpreter=$PYTHON_BIN
elif command -v python3 >/dev/null 2>&1; then
    interpreter=python3
elif command -v python >/dev/null 2>&1; then
    interpreter=python
else
    echo 'Profiling requires Python with angr and Z3. Install the dependencies or set PYTHON_BIN.' >&2
    exit 1
fi

exec "$interpreter" -B "$script_dir/src/rvmca/profile_json.py" "$@"
