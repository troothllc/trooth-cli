// tests/effect-figures.test.mjs - CR26, AA30 (and CF21's part in this repository): no public file here
// states a percentage about Semanto's effect before the pre-registered result, or any probability or
// confidence figure about Semanto's prospects. The same patterns run in trooth-web (tests/cli3-docs.test.mjs).
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const EFFECT = [
  /[0-9]+(?:\.[0-9]+)? ?(?:%|percent)[^.\n]{0,60}(?:fewer|less|lower|reduc|improv|more accura|wrong|hallucinat|mistake)/i,
  /(?:fewer|reduc|improv|accura|cut|lower)[^.\n]{0,40}[0-9]+(?:\.[0-9]+)? ?(?:%|percent)/i,
  /(?:probability|confidence|chance|likelihood|odds)[^.\n"]{0,50}\b[0-9]{1,3} ?(?:%|percent)/i,
  /\b(?:80 ?[–-] ?85|65 ?[–-] ?70|60 ?[–-] ?70|40 ?[–-] ?60)\b/,
];
const walk = (d) => readdirSync(join(ROOT, d)).flatMap((n) => {
  const p = join(d, n);
  return statSync(join(ROOT, p)).isDirectory() ? walk(p) : [p];
});
const surfaces = ['docs', 'spec', 'schemas', 'bin', 'types'].flatMap(walk).concat(['README.md', 'CHANGELOG.md']);
assert.ok(EFFECT.some((re) => re.test('Semanto cuts wrong answers by 40%.')));
assert.ok(EFFECT.some((re) => re.test('a 92 percent chance it works')) || EFFECT.some((re) => re.test('confidence of 92%')));
const found = surfaces.filter((p) => EFFECT.some((re) => re.test(readFileSync(join(ROOT, p), 'utf8'))));
assert.deepEqual(found, [], 'a public file states an effect or prospect figure');
console.log(`effect-figures: ok over ${surfaces.length} public files`);
