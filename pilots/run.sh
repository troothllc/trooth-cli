#!/usr/bin/env bash
# pilots/run.sh - runs every Trooth-run guard pilot against the real framework
# packages, with the guard taken from this repository (JavaScript imports
# bin/lib; Python imports sdk/python and calls bin/trooth.mjs).
#
# Needs: Node >= 18; the JavaScript packages installed in pilots/js
# (npm install there); a Python with openai-agents, crewai and langgraph
# installed (PYTHON, default python3); network access to trooth.co and
# api.trooth.co for the live steps. It starts the local fixture server itself.
#
# Each pilot prints PASS or FAIL per step and writes logs/<name>.out and
# logs/<name>.json. The script exits 1 when any step fails or any pilot does
# not finish, 0 otherwise. A skipped pilot counts as a failure.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$here"
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$repo/sdk/python:$here/py" NODE_NO_WARNINGS=1
mkdir -p logs
rm -f logs/*.out logs/*.json

node fixture-server.mjs > logs/fixture-server.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null' EXIT
for _ in $(seq 1 100); do [ -s logs/fixture-info.json ] && break; sleep 0.1; done
if [ ! -s logs/fixture-info.json ]; then echo "the fixture server did not start"; cat logs/fixture-server.log; exit 1; fi

status=0
run() {
  local name="$1"; shift
  if "$@" > "logs/$name.out" 2>&1; then echo "$name: finished"; else echo "$name: exit $? (see logs/$name.out)"; status=1; fi
}
run pilot1-js          bash -c 'cd js && node pilot1-payments-openai-agents.mjs'
run pilot2-js          bash -c 'cd js && node pilot2-procurement-langgraph-langchain.mjs'
run pilot1-py          bash -c "cd py && '$PYTHON' pilot1_payments_openai_agents.py"
run pilot3-crewai      bash -c "cd py && '$PYTHON' pilot3_export_crewai.py"
run check-langgraph-py bash -c "cd py && '$PYTHON' check_langgraph_py_deny_goto.py"
run pilot3-hook        bash -c 'cd hook && node pilot3-claude-code-hook.mjs'

echo
total_pass=0; total_fail=0
for f in logs/*.out; do
  case "$f" in logs/fixture-server*) continue ;; esac
  p=$(grep -c '^PASS' "$f"); x=$(grep -c '^FAIL' "$f")
  total_pass=$((total_pass + p)); total_fail=$((total_fail + x))
  echo "$f: $p pass, $x fail"
  [ "$p" -gt 0 ] || status=1
done
echo "all: $total_pass pass, $total_fail fail"
grep -h '^FAIL' logs/*.out || true
[ "$total_fail" -eq 0 ] || status=1
exit $status
