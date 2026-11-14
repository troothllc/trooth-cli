// tests/method-claims.test.mjs - CR27: the open spec describes what a record is and how to check it,
// never how Trooth's unpublished methods work. Part 7 of the consensus record file and of the
// confidence raise file (2026-11-08) list them; the same patterns run in trooth-web
// (tests/cli3-docs.test.mjs) over trooth.co's public pages.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const METHOD_CLAIMS = [
  /supersession passages?/i, /passages? generated from validity intervals?/i, /channel[- ]isolated/i,
  /tracer facts?/i, /propagation map/i, /sealed answer receipts?/i, /map[- ]chosen channel/i,
  /ledger[- ]traced cause/i, /pre-ask prediction/i, /predict\w* (?:the )?(?:answer )?correctness/i,
  /re-?tun\w* (?:of )?(?:the )?citation weights?/i, /citation weight and channel choice/i,
  /conflict-explaining passages?/i, /canonical[- ]form grading/i, /router[- ]combination/i,
];
const walk = (d) => readdirSync(join(ROOT, d)).flatMap((n) => {
  const p = join(d, n);
  return statSync(join(ROOT, p)).isDirectory() ? walk(p) : [p];
});
const surfaces = ['docs', 'spec', 'schemas', 'bin', 'types'].flatMap(walk).concat(['README.md', 'CHANGELOG.md', 'SPECIFICATION-LICENSE.md']);
let n = 0;
assert.ok(METHOD_CLAIMS.some((re) => re.test('Channel-isolated tracer facts build a propagation map.')));
n++;
const found = surfaces.filter((p) => METHOD_CLAIMS.some((re) => re.test(readFileSync(join(ROOT, p), 'utf8'))));
assert.deepEqual(found, [], 'a public file describes an unpublished method');
n++;
console.log(`method-claims: ${n} ok over ${surfaces.length} public files`);
