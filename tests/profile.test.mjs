// tests/profile.test.mjs - `trooth profile` (0.16.4), held without the network.
// A loopback server serves one live response of /api/network/profile for
// trooth.co, saved unedited on 2026-10-09 (tests/fixtures/profile/), and
// variations of it: every section in page order, each fact with who said it
// and its date only when the record carries one, "not published" for an empty
// section, --section and its names, --json against
// schemas/profile-output.v1.schema.json, --markdown, slugs, an honest absence,
// a withheld record, paging, a body with no profile, and every exit code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { SECTION_NAMES, SECTION_OF_CATEGORY, parseSectionArgs, buildSections } from '../bin/lib/profile.mjs';

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const CLOSED = 'http://127.0.0.1:9';
const SAVED = JSON.parse(readFileSync(new URL('./fixtures/profile/trooth.co-2026-10-09.json', import.meta.url), 'utf8'));
const BODY = SAVED.body;
const OLD = JSON.parse(readFileSync(new URL('./fixtures/projection/record-v2.json', import.meta.url), 'utf8')).body; // no profile member; acme.example
const validate = makeValidator(loadSchemas(new URL('../schemas/', import.meta.url)));
const clone = (v) => JSON.parse(JSON.stringify(v));

function run(args, env = {}) {
  return new Promise((resolve) => {
    const e = { ...process.env, TROOTH_WEB: CLOSED, TROOTH_API: CLOSED, NO_COLOR: '1', ...env };
    for (const [k, v] of Object.entries(e)) if (v === undefined) delete e[k];
    const p = spawn(process.execPath, [cli, ...args], { env: e });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
    p.stdin.end();
  });
}

function stand(handler) {
  return new Promise((resolve) => {
    const seen = [];
    const srv = http.createServer((req, res) => { seen.push(req.url); handler(req, res, new URL(req.url, 'http://x').searchParams); });
    srv.seen = seen;
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
const send = (res, status, body, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
const recordHeaders = Object.fromEntries(Object.entries(SAVED.headers).filter(([k]) => k.startsWith('trooth-')));
const base = (srv) => `http://127.0.0.1:${srv.address().port}`;

/** The saved record for trooth.co (and its slug), a body per test, nothing else. */
async function withRecord(body, fn, extra = () => false) {
  const srv = await stand((req, res, q) => {
    if (extra(req, res, q)) return;
    if (q.get('q') === 'trooth.co' || q.get('q') === 'trooth') return send(res, 200, body, recordHeaders);
    return send(res, 200, { found: false });
  });
  try { return await fn({ TROOTH_WEB: base(srv) }, srv); } finally { srv.close(); }
}

const TYPED_KEYS = BODY.facts.map((f) => f.key);
const allFacts = (doc) => doc.sections.flatMap((s) => s.facts);

test('the saved response is a whole record: twenty sections, every typed fact on one page', () => {
  assert.equal(SAVED.status, 200);
  assert.equal(BODY.found, true);
  assert.equal(BODY.contractVersion, 2);
  assert.deepEqual(BODY.profile.sections.map((s) => s.id), SECTION_NAMES);
  assert.equal(BODY.selection.truncated, false);
  assert.equal(BODY.facts.length, 68);
});

test('text: every section in page order, its state and who said it; the not-signed notice names trooth verify', async () => {
  await withRecord(BODY, async (env) => {
    const r = await run(['profile', 'trooth.co'], env);
    assert.equal(r.code, 0, r.err);
    assert.doesNotMatch(r.out, /\x1b\[/, 'no color when NO_COLOR is set or stdout is not a terminal');
    const heads = [...r.out.matchAll(/^== .* \(([a-z-]+)\) · /gm)].map((m) => m[1]);
    assert.deepEqual(heads, SECTION_NAMES);
    assert.match(r.out, /^Trooth {3}trooth\.co {3}slug trooth$/m);
    assert.match(r.out, /record updated 2026-10-06T01:08:12\.526Z · record version 8 · read /);
    assert.match(r.out, /company's own declared record/);
    assert.match(r.out, /It is not signed: Trooth signs one object, the witness statement/);
    assert.match(r.out, /Check that statement yourself: trooth verify trooth\.co/);
    // The empty section: "not published", never filled in.
    const proof = r.out.slice(r.out.indexOf('== Customer proof'), r.out.indexOf('== People'));
    assert.match(proof, /· not published · named customers/);
    assert.match(proof, /^ {2}not published$/m);
    assert.doesNotMatch(proof, /said by/);
    // Shared on request only: said so, no contents.
    assert.match(r.out, /== Request documents \(documents\) · on request only/);
    // A fact the record dates, and one it does not.
    assert.match(r.out, /Legal name: Trooth, LLC\n {4}said by the company \(declared\) · declared 2026-10-06 · identity\.legal-name/);
    assert.match(r.out, /Name: Trooth\n {4}said by the company \(declared\) · date unknown\n/);
    assert.match(r.out, /Badge ID: scan_mtlolyke_03a9dd2ee0d0960f\n {4}said by Trooth \(observed\) · date unknown/);
    // Groups and items are headed; sub-processors keep their own fields.
    assert.match(r.out, /^ {2}Sub-processors · Cloudflare, Inc\.$/m);
    assert.match(r.out, /^ {2}Recovery$/m);
    // Every typed fact is printed with its key.
    for (const k of TYPED_KEYS) assert.ok(r.out.includes(` · ${k}\n`), k);
    assert.match(r.out, /20 sections; \d+ facts\. Trooth does not grade, rate, rank or certify a company\./);
  });
});

test('--json validates against profile-output.v1, carries every typed fact once, and dates only what the record dates', async () => {
  await withRecord(BODY, async (env, srv) => {
    const r = await run(['profile', 'trooth.co', '--json'], env);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(srv.seen, ['/api/network/profile?q=trooth.co&contract=2']);
    const doc = JSON.parse(r.out);
    assert.deepEqual(validate('profile-output.v1.schema.json', doc), []);
    assert.equal(doc.subject, 'trooth.co');
    assert.equal(doc.contract, 2);
    assert.ok(!Number.isNaN(Date.parse(doc.read_at)));
    assert.equal(doc.found, true);
    assert.equal(doc.signed, false);
    assert.equal(doc.verify_with, 'trooth verify trooth.co');
    assert.equal(doc.record.version, 8);
    assert.equal(doc.record.digest, SAVED.headers['trooth-record-digest']);
    assert.equal(doc.record.updated_at, BODY.updatedAt);
    assert.equal(doc.profile_present, true);
    assert.deepEqual(doc.sections.map((s) => s.name), SECTION_NAMES);
    assert.deepEqual(doc.sections.map((s) => s.state), BODY.profile.sections.map((s) => s.state));
    const proof = doc.sections.find((s) => s.name === 'proof');
    assert.equal(proof.state, 'not_published'); assert.deepEqual(proof.facts, []);
    const facts = allFacts(doc);
    const keyed = facts.filter((f) => f.key);
    assert.deepEqual(keyed.map((f) => f.key).sort(), [...TYPED_KEYS].sort(), 'each typed fact exactly once');
    const byKey = new Map(BODY.facts.map((f) => [f.key, f]));
    for (const f of facts) {
      assert.equal(f.signed, false);
      if (!f.key) { assert.equal(f.date, null, `${f.label} has no typed fact, so no date`); assert.equal(f.date_kind, null); continue; }
      const t = byKey.get(f.key);
      assert.equal(f.value, t.value); assert.equal(f.label, t.label); assert.equal(f.origin, t.origin);
      assert.equal(f.date, t.claim.declaredAt ?? t.claim.observedAt ?? null, f.key);
      assert.equal(f.date_kind, t.claim.declaredAt ? 'declared' : t.claim.observedAt ? 'observed' : null);
      assert.equal(f.source, t.record.sourceReference);
    }
    // No date is ever the record's update time or the reading's time.
    for (const f of facts) assert.notEqual(f.date, BODY.updatedAt, f.label);
    for (const f of facts) assert.notEqual(f.date, BODY.witnessed.lastWitnessed, f.label);
    // registration.* are shown in identity, recovery.* in hosting, ai-practices.* in ai.
    const where = (k) => doc.sections.find((s) => s.facts.some((f) => f.key === k)).name;
    assert.equal(where('registration.registration-identifier'), 'identity');
    assert.equal(where('recovery.declared-rpo-target'), 'hosting');
    assert.equal(where('ai-practices.trains-on-customer-data'), 'ai');
    assert.equal(where('pricing.list-price'), 'pricing');
    // Who said it comes from the group when a group says otherwise.
    const linkCheck = doc.sections.find((s) => s.name === 'procurement').facts.find((f) => f.group === 'Link checks');
    assert.equal(linkCheck.provenance, 'trooth_observation'); assert.equal(linkCheck.said_by, 'Trooth (observed)');
    // An item published by name only is one fact: the group, and the name.
    assert.ok(doc.sections.find((s) => s.name === 'stack').facts.some((f) => f.group === 'Integrations' && f.label === 'Integrations' && f.value === 'Slack'));
    // Notes are kept, with the group and item they belong to.
    assert.ok(doc.sections.find((s) => s.name === 'documents').notes.length >= 1);
    assert.ok(doc.sections.find((s) => s.name === 'identity').notes.some((n) => n.group === 'Legal entities' && n.item === 'Trooth, LLC'));
  });
});

test('--section: comma-separated or repeated names, in page order; the record\'s fact categories name their sections; anything else is exit 2', async () => {
  await withRecord(BODY, async (env) => {
    let r = await run(['profile', 'trooth.co', '--section', 'privacy,security', '--json'], env);
    assert.equal(r.code, 0, r.err);
    let doc = JSON.parse(r.out);
    assert.deepEqual(doc.sections.map((s) => s.name), ['security', 'privacy']);
    assert.deepEqual(doc.requested_sections, ['security', 'privacy']);
    assert.deepEqual(validate('profile-output.v1.schema.json', doc), []);

    r = await run(['profile', 'trooth.co', '--section', 'ai-practices', '--section=registration,recovery,proof', '--json'], env);
    doc = JSON.parse(r.out);
    assert.deepEqual(doc.sections.map((s) => s.name), ['identity', 'ai', 'hosting', 'proof'].sort((a, b) => SECTION_NAMES.indexOf(a) - SECTION_NAMES.indexOf(b)));

    r = await run(['profile', 'trooth.co', '--section', 'proof'], env);
    assert.equal(r.code, 0);
    assert.match(r.out, /Sections asked for: proof/);
    assert.match(r.out, /== Customer proof \(proof\) · not published/);
    assert.doesNotMatch(r.out, /== Security/);

    r = await run(['profile', 'trooth.co', '--section', 'security,ratings'], env);
    assert.equal(r.code, 2);
    assert.match(r.err, /not a section: ratings\. Sections: overview, identity, history/);
    r = await run(['profile', 'trooth.co', '--section', ',', '--json'], env);
    assert.equal(r.code, 2); assert.equal(JSON.parse(r.out).exit, 2);
    r = await run(['profile', 'trooth.co', '--section'], env);
    assert.equal(r.code, 2); assert.match(r.err, /--section needs a value/);
  });
  assert.deepEqual(parseSectionArgs(['AI, Security ']).names, ['security', 'ai']);
  for (const [cat, sec] of Object.entries(SECTION_OF_CATEGORY)) assert.deepEqual(parseSectionArgs([cat]).names, [sec], cat);
});

test('--markdown prints the same profile as Markdown', async () => {
  await withRecord(BODY, async (env) => {
    const r = await run(['profile', 'trooth.co', '--markdown'], env);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^# Trooth \(trooth\.co\): Trust Profile\n/);
    assert.match(r.out, /^> This profile is the company's own declared record.*It is not signed.*`trooth verify trooth\.co`\./m);
    const heads = [...r.out.matchAll(/^## .* \(`([a-z-]+)`\)$/gm)].map((m) => m[1]);
    assert.deepEqual(heads, SECTION_NAMES);
    assert.match(r.out, /## Customer proof \(`proof`\)\n\n\*not published · named customers\*.*\n\nNot published\./);
    assert.match(r.out, /^- \*\*Legal name:\*\* Trooth, LLC \(said by the company \(declared\); declared 2026-10-06; `identity\.legal-name`\)$/m);
    assert.match(r.out, /^- \*\*Name:\*\* Trooth \(said by the company \(declared\); date unknown\)$/m);
    assert.match(r.out, /^### Sub-processors · Cloudflare, Inc\.$/m);
    for (const k of TYPED_KEYS) assert.ok(r.out.includes(`\`${k}\``), k);
    const both = await run(['profile', 'trooth.co', '--markdown', '--json'], env);
    assert.equal(both.code, 2); assert.match(both.err, /pass one/);
  });
});

test('a slug is resolved on the projection, then read by its domain; an unknown slug is exit 2', async () => {
  await withRecord(BODY, async (env, srv) => {
    const r = await run(['profile', 'trooth', '--json'], env);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(srv.seen, ['/api/network/profile?q=trooth&contract=2', '/api/network/profile?q=trooth.co&contract=2']);
    assert.match(r.err, /trooth is a Trooth slug: the record for trooth\.co/);
    const doc = JSON.parse(r.out);
    assert.equal(doc.subject, 'trooth.co'); assert.equal(doc.query, 'trooth');
    const bad = await run(['profile', 'nosuchco'], env);
    assert.equal(bad.code, 2);
    assert.match(bad.err, /no Trooth record has the slug nosuchco\. Pass the company's domain, for example: trooth profile stripe\.com/);
  });
});

test('no published record: exit 1, an honest absence; the claim link only when the API gives one', async () => {
  await withRecord(BODY, async (env) => {
    let r = await run(['profile', 'unknown.example'], env);
    assert.equal(r.code, 1, r.err);
    assert.match(r.out, /unknown\.example \/\/ no published record on the Trooth Network/);
    assert.match(r.out, /says\nnothing about the company/);
    assert.doesNotMatch(r.out, /claim/i);
    r = await run(['profile', 'unknown.example', '--json'], env);
    assert.equal(r.code, 1);
    const doc = JSON.parse(r.out);
    assert.deepEqual(validate('profile-output.v1.schema.json', doc), []);
    assert.equal(doc.found, false); assert.deepEqual(doc.sections, []); assert.equal(doc.claim_url, null);
    r = await run(['profile', 'claimable.example', '--markdown'], env);
    assert.equal(r.code, 1);
    assert.match(r.out, /claimed at <https:\/\/trooth\.co\/claim\?domain=claimable\.example>/);
    r = await run(['profile', 'claimable.example', '--json'], env);
    assert.equal(JSON.parse(r.out).claim_url, 'https://trooth.co/claim?domain=claimable.example');
    r = await run(['profile', 'claimable.example'], env);
    assert.match(r.out, /can be claimed at https:\/\/trooth\.co\/claim\?domain=claimable\.example/);
  }, (req, res, q) => q.get('q') === 'claimable.example' && (send(res, 200, { found: false, claimUrl: 'https://trooth.co/claim?domain=claimable.example' }), true));
});

test('a withheld record is exit 6, with no facts', async () => {
  await withRecord({ found: true, withheld: true, slug: 'trooth', name: 'Trooth', reason: 'A report about this record is being reviewed.', since: '2026-10-01T00:00:00Z' }, async (env) => {
    let r = await run(['profile', 'trooth.co'], env);
    assert.equal(r.code, 6, r.err);
    assert.match(r.out, /withheld while a report about it is reviewed/);
    r = await run(['profile', 'trooth.co', '--json'], env);
    const doc = JSON.parse(r.out);
    assert.equal(r.code, 6);
    assert.deepEqual(validate('profile-output.v1.schema.json', doc), []);
    assert.equal(doc.withheld, true); assert.deepEqual(doc.sections, []);
  });
});

test('network and contract errors are exit 3, never an answer about the company', async () => {
  let r = await run(['profile', 'trooth.co', '--json']);
  assert.equal(r.code, 3);
  assert.equal(JSON.parse(r.out).exit, 3);
  for (const [label, handler] of [
    ['HTTP 500', (req, res) => send(res, 500, { error: 'x' })],
    ['HTTP 404', (req, res) => send(res, 404, { error: 'x' })],
    ['not JSON', (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>'); }],
    ['contract 1', (req, res) => send(res, 200, { ...BODY, contractVersion: 1 })],
    ['another record', (req, res) => send(res, 200, { ...BODY, domain: 'other.example' })],
  ]) {
    const srv = await stand(handler);
    try {
      r = await run(['profile', 'trooth.co'], { TROOTH_WEB: base(srv) });
      assert.equal(r.code, 3, `${label}: ${r.err}`);
      assert.equal(r.out, '', label);
    } finally { srv.close(); }
  }
});

test('usage: one subject, known flags, and --help', async () => {
  for (const args of [['profile'], ['profile', 'a.example', 'b.example'], ['profile', 'a.example', '--bogus'], ['profile', 'not a domain']]) {
    const r = await run(args);
    assert.equal(r.code, 2, args.join(' '));
  }
  const h = await run(['profile', '--help']);
  assert.equal(h.code, 0);
  assert.match(h.out, /^trooth profile v\d/m);
  assert.match(h.out, /trooth profile <domain\|slug> \[--section <name>\[,<name>\.\.\.\]\] \[--json \| --markdown\]/);
  for (const n of SECTION_NAMES) assert.ok(h.out.includes(n), n);
  assert.match(h.out, /not signed/);
  const general = await run(['--help']);
  assert.match(general.out, /trooth profile <domain>/);
});

test('facts that run past one page are read to the end from the same record version; a page from another version is exit 3', async () => {
  const first = clone(BODY), second = clone(BODY);
  first.facts = BODY.facts.slice(0, 40); second.facts = BODY.facts.slice(40);
  first.selection = { ...BODY.selection, limit: 40, returned: 40, truncated: true, next: 'cursor-2' };
  second.selection = { ...BODY.selection, limit: 40, returned: 28, truncated: false, next: null };
  await withRecord(first, async (env, srv) => {
    const r = await run(['profile', 'trooth.co', '--json'], env);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(srv.seen, ['/api/network/profile?q=trooth.co&contract=2', '/api/network/profile?q=trooth.co&contract=2&after=cursor-2']);
    const keys = allFacts(JSON.parse(r.out)).filter((f) => f.key).map((f) => f.key).sort();
    assert.deepEqual(keys, [...TYPED_KEYS].sort());
  }, (req, res, q) => q.get('after') === 'cursor-2' && (send(res, 200, second, recordHeaders), true));
  const stale = { ...second, selection: { ...second.selection, recordVersion: '2026-10-09T00:00:00.000Z' } };
  await withRecord(first, async (env) => {
    const r = await run(['profile', 'trooth.co'], env);
    assert.equal(r.code, 3); assert.match(r.err, /another record version/);
  }, (req, res, q) => q.get('after') && (send(res, 200, stale), true));
});

test('a contested fact lists every account; a fact the record does not date prints "date unknown", not another date', async () => {
  const b = clone(BODY);
  const hq = b.facts.find((f) => f.key === 'identity.headquarters');
  hq.contested = true;
  b.conflicts = [{ key: 'identity.headquarters', category: 'Identity', label: 'Headquarters', accounts: [{ origin: 'company-declared', value: hq.value }, { origin: 'public-source', value: 'Wilmington, Delaware, United States' }] }];
  const size = b.facts.find((f) => f.key === 'identity.company-size');
  size.claim.declaredAt = null; delete size.claim.declaredBy;
  await withRecord(b, async (env) => {
    let r = await run(['profile', 'trooth.co', '--section', 'identity'], env);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /Headquarters: Miami, Florida, United States\n.*identity\.headquarters\n {4}contested: sources disagree, and Trooth does not choose between them\n {6}company-declared: Miami, Florida, United States\n {6}public-source: Wilmington, Delaware, United States/);
    assert.match(r.out, /Company size: 1-10\n {4}said by the company \(declared\) · date unknown · identity\.company-size/);
    r = await run(['profile', 'trooth.co', '--json', '--section', 'identity'], env);
    const facts = allFacts(JSON.parse(r.out));
    const f = facts.find((x) => x.key === 'identity.headquarters');
    assert.equal(f.contested, true); assert.equal(f.accounts.length, 2);
    assert.equal(facts.find((x) => x.key === 'identity.company-size').date, null);
  });
});

test('a body with no profile member: the typed facts in their sections, every other section unavailable, nothing invented', async () => {
  const srv = await stand((req, res) => send(res, 200, OLD));
  try {
    const r = await run(['profile', 'acme.example', '--json'], { TROOTH_WEB: base(srv) });
    assert.equal(r.code, 0, r.err);
    const doc = JSON.parse(r.out);
    assert.deepEqual(validate('profile-output.v1.schema.json', doc), []);
    assert.equal(doc.profile_present, false);
    assert.equal(allFacts(doc).length, OLD.facts.length);
    for (const s of doc.sections) {
      if (s.facts.length) assert.equal(s.state, 'published', s.name);
      else assert.equal(s.state, 'unavailable', s.name);
    }
    const text = await run(['profile', 'acme.example'], { TROOTH_WEB: base(srv) });
    assert.match(text.out, /carries no complete profile, only the typed facts/);
    assert.match(text.out, /== Overview \(overview\) · unavailable on this read \(not empty\)/);
  } finally { srv.close(); }
  // buildSections never drops a typed fact whose category it does not know.
  const b = clone(BODY);
  b.facts.push({ ...clone(BODY.facts[0]), key: 'carbon.scope-1', category: 'Carbon', label: 'Scope 1', value: '0 t' });
  const { sections } = buildSections(b);
  const unsorted = sections.find((s) => s.name === 'unsorted');
  assert.equal(unsorted.facts.length, 1); assert.equal(unsorted.facts[0].key, 'carbon.scope-1');
});
