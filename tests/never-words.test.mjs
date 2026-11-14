// tests/never-words.test.mjs - UX25 (cli7): no never-word in anything the CLI prints. Every string and template
// literal with a space in bin/ is read (help, output lines, errors, problem bodies); the list is the founder's
// banned words plus the UX file's Part 3 kinds (the rating word, the search-marketing acronyms, the generic engine
// label, marketing adjectives, the word for made-up answers, "in development", "coming soon"). The ellipsis and the
// dash are left out here on purpose: CLI usage syntax writes <domain>... and flags as --name.
// Sentences over 25 words are counted and listed, not failed, as the UX file asks ("flagged").
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;
export const NEVER = /\b(verified|verification|certified|scores?|tiers?|instant(ly)?|go live|in flight|handoff|coming soon|in development|hallucinat\w*|SEO|GEO|AEO|seamless(ly)?|revolutionary|cutting-edge|best-in-class|world-class|game-chang\w+|AI search engines?)\b/i;

function files(dir) {
  const out = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) out.push(...files(p));
    else if (/\.mjs$/.test(f)) out.push(p);
  }
  return out;
}
export function printedStrings(src) {
  const out = [];
  const re = /(["`'])((?:\\.|(?!\1)[^\\\n])*)\1/g;
  let m;
  while ((m = re.exec(src))) if (m[2].includes(' ')) out.push({ line: src.slice(0, m.index).split('\n').length, value: m[2] });
  return out;
}
const hits = (src) => printedStrings(src).filter((s) => NEVER.test(s.value));

test('UX25: no never-word in any string the CLI prints', () => {
  const bad = [];
  for (const f of files(join(ROOT, 'bin'))) for (const h of hits(readFileSync(f, 'utf8'))) bad.push(`${f.slice(ROOT.length)}:${h.line}: ${h.value.slice(0, 120)}`);
  assert.deepEqual(bad, []);
});

test('UX25: the check fails on a planted word in each kind of output: help, an output line, an error, a problem body', () => {
  for (const planted of [
    "  trooth status   See your trust score",
    "out(`Record verified for ${domain}`)",
    "fail(EXIT.USAGE, 'This feature is coming soon.')",
    "io.emitJson({ detail: 'Checked by our best-in-class engine' })",
  ]) assert.equal(hits(`const x = ${JSON.stringify(planted)};\n${planted}`).length > 0, true, planted);
});

test('UX25: sentences over 25 words are listed, as a flag', () => {
  let long = 0;
  for (const f of files(join(ROOT, 'bin'))) for (const s of printedStrings(readFileSync(f, 'utf8'))) for (const sentence of s.value.split(/(?<=[.!?])\s+/)) if (sentence.split(/\s+/).filter(Boolean).length > 25) long++;
  console.log(`  ${long} printed sentences run over 25 words (flagged, not failed)`);
  assert.ok(long >= 0);
});
