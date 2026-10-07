#!/usr/bin/env bash
# Runs this repository's trooth CLI (bin/trooth.mjs) against the local fixture
# server (world given by TROOTH_FIXTURE_WORLD, default main), with the
# fixture's log key and witness keys. Used by the Trooth-run pilots only.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
info="$here/logs/fixture-info.json"
world="${TROOTH_FIXTURE_WORLD:-main}"
read -r web api vkey w1 w2 < <(node -e '
const i=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const w=i.worlds[process.argv[2]];
console.log([w.web,w.api,i.vkey,...i.witnesses].join(" "))' "$info" "$world")
export TROOTH_WEB="$web" TROOTH_API="$api"
exec node "$here/../bin/trooth.mjs" "$@" --log-vkey "$vkey" --witness "$w1" --witness "$w2"
