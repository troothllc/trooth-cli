// SEC-2b (cli32): no doc, schema, type or help text offers any mailbox but the five
// administrative addresses, or a Google Workspace or Microsoft sign-in, as domain proof.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');
const FILES = ['docs/EVIDENCE.md', 'schemas/public-record.v1.schema.json', 'types/trooth.d.ts', 'sdk/go/trooth/types.go', 'sdk/python/trooth_verify/models.py', 'bin/trooth.mjs', 'README.md'];
const OFFERS = [/a mailbox at the domain/i, /Google Workspace hosted domain/i, /Microsoft Entra tenant/i, /\bwork email\b/i, /any (?:mailbox|address) at the domain/i];
let n = 0;
for (const f of FILES) {
  const s = read(f);
  for (const re of OFFERS) { assert.ok(!re.test(s), `${f} offers ${re} as domain proof`); n++; }
}
const ev = read('docs/EVIDENCE.md');
for (const w of ['admin, administrator, webmaster, hostmaster or postmaster', '398 days', 'personal mail provider', 'single sign-on for an organization whose administrator confirmed the domain', 'Google Workspace or Microsoft sign-in']) { assert.ok(ev.includes(w), `EVIDENCE.md says: ${w}`); n++; }
const help = read('bin/trooth.mjs');
assert.ok(help.includes('No other mailbox, no personal mail domain and no Google Workspace or Microsoft sign-in proves a domain.'), 'public-record help says what proves a domain'); n++;
console.log(`domain-proof-words: ${n} passed`);
