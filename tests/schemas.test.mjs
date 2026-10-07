// tests/schemas.test.mjs - schemas/ describes what Trooth actually publishes.
// Every vector, every bundle, a real bundle saved from trooth.co and the CLI's
// own --json output validate; every property carries a description; the
// generated types (scripts/gen-types.mjs) are current; ids follow docs/IDS.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { formatId, parseId, statementId } from '../bin/lib/ids.mjs';
import { canonicalize, isCanonical, CanonicalizationError } from '../bin/lib/jcs.mjs';
import { generateDeclarationKey, buildDeclaration } from '../bin/lib/declaration.mjs';

const schemaDir = new URL('../schemas/', import.meta.url);
const schemas = loadSchemas(schemaDir);
const validate = makeValidator(schemas);
const vec = JSON.parse(readFileSync(new URL('./vectors/vectors.json', import.meta.url), 'utf8'));
const bundles = JSON.parse(readFileSync(new URL('./vectors/bundles.json', import.meta.url), 'utf8')).bundles;
const liveUrl = new URL('./fixtures/bundles/trooth.co-2026-10-06.bundle.json', import.meta.url);
const live = JSON.parse(readFileSync(liveUrl, 'utf8'));
const ok = (file, v, label) => assert.deepEqual(validate(file, v), [], `${label} against ${file}`);

test('each schema names itself under https://trooth.co/schemas/ and states its dialect', () => {
  assert.equal(Object.keys(schemas).length, 17);
  // The guard decision keeps the $id the brief published for it (docs/GUARD.md).
  const publishedIds = { 'guard-decision.v1.schema.json': 'https://trooth.co/schemas/guard-decision.v1.json' };
  for (const [f, s] of Object.entries(schemas)) {
    assert.equal(s.$id, publishedIds[f] ?? `https://trooth.co/schemas/${f}`);
    assert.equal(s.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.ok(s.title && s.description, `${f} has a title and a description`);
  }
});

test('every property in every schema carries a description', () => {
  const missing = [];
  const walk = (n, where) => {
    if (!n || typeof n !== 'object') return;
    if (n.properties) for (const [k, v] of Object.entries(n.properties)) { if (!v.description) missing.push(`${where}.${k}`); walk(v, `${where}.${k}`); }
    for (const [k, v] of Object.entries(n)) if (k !== 'properties' && typeof v === 'object') walk(v, `${where}/${k}`);
  };
  for (const [f, s] of Object.entries(schemas)) walk(s, f);
  assert.deepEqual(missing, []);
});

test('the v2 schema lists members in the exact order v2 signs them', () => {
  const live2 = JSON.parse(live.statement.payload);
  assert.deepEqual(Object.keys(live2), schemas['witness-payload.v2.schema.json'].required);
  assert.deepEqual(Object.keys(schemas['witness-payload.v2.schema.json'].properties), schemas['witness-payload.v2.schema.json'].required);
});

test('every well-formed vector validates: envelope, payload, key list, manifest', () => {
  let n = 0;
  for (const v of vec.vectors) {
    let p; try { p = JSON.parse(v.statement.payload); } catch { continue; }
    if (['malformed-signature', 'wrong-alg'].includes(v.name)) continue;
    ok('witness-statement.schema.json', v.statement, v.name);
    ok(`witness-payload.${p.statement.slice(-2)}.schema.json`, p, v.name);
    ok('key-list.schema.json', { keys: v.keys }, v.name);
    if (v.manifest) ok('evidence-manifest.schema.json', v.manifest, v.name);
    n++;
  }
  assert.ok(n >= 25, `${n} vectors validated`);
});

test('a reason-less v2 check, a v3 payload without subject_id and a manifest entry with both fields are refused', () => {
  const p2 = JSON.parse(vec.vectors.find((v) => v.name === 'valid-v2').statement.payload);
  p2.checks[1].reason = null; p2.checks[1].outcome = 'bogus';
  assert.notDeepEqual(validate('witness-payload.v2.schema.json', p2), []);
  const p3 = JSON.parse(vec.vectors.find((v) => v.name === 'valid-v3').statement.payload);
  delete p3.subject_id;
  assert.notDeepEqual(validate('witness-payload.v3.schema.json', p3), []);
  assert.notDeepEqual(validate('evidence-manifest.schema.json', [{ check_id: 'S1', source: 'https://a.example/', commitment: `sha256:${'0'.repeat(64)}` }]), []);
});

test('log receipts, correction payloads and logged bundles validate (docs/LOG.md)', () => {
  const log = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8'));
  let receipts = 0, corrections = 0;
  for (const c of log.cases) {
    if (['proof-tampered', 'checkpoint-forged', 'checkpoint-other-origin'].includes(c.name)) continue;
    if (c.log.receipt) { ok('log-receipt.schema.json', c.log.receipt, c.name); receipts++; }
    for (const x of c.log.corrections) { ok('witness-statement.schema.json', x.statement, c.name); if (!['correction-bad-signature'].includes(c.name)) ok('correction-payload.v1.schema.json', JSON.parse(x.statement.payload), c.name); corrections++; }
  }
  assert.ok(receipts >= 8 && corrections >= 4, `${receipts} receipts, ${corrections} corrections`);
  assert.notDeepEqual(validate('correction-payload.v1.schema.json', { ...JSON.parse(log.entries[3].statement.payload), effect: 'deleted' }), []);
  assert.notDeepEqual(validate('log-receipt.schema.json', { ...log.cases[0].log.receipt, root_hash: 'short' }), []);
});

test('bundles validate, including a real one saved from trooth.co', () => {
  for (const b of bundles) if (!b.expect.error) ok('verification-bundle.v1.schema.json', b.bundle, b.name);
  ok('verification-bundle.v1.schema.json', live, 'trooth.co bundle');
  ok('witness-payload.v2.schema.json', JSON.parse(live.statement.payload), 'trooth.co payload');
});

test('trooth verify --json output validates against verify-result', () => {
  const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
  const r = spawnSync(process.execPath, [cli, 'verify', '--bundle', liveUrl.pathname, '--json'], { encoding: 'utf8', env: { ...process.env, TROOTH_WEB: 'http://127.0.0.1:9', TROOTH_API: 'http://127.0.0.1:9' } });
  assert.equal(r.status, 0, r.stderr);
  const doc = JSON.parse(r.stdout);
  ok('verify-result.schema.json', doc, 'cli output');
  assert.equal(doc.verdict, 'checked');
  assert.equal(doc.statement_id, statementId(live.statement.payload));
});

test('trooth verify --json with a log answer validates against verify-result', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
  for (const name of ['bundle-superseded', 'bundle-v3-logged', 'bundle-forged-checkpoint']) {
    const b = bundles.find((x) => x.name === name);
    const f = join(mkdtempSync(join(tmpdir(), 'trooth-schema-')), 'b.json');
    writeFileSync(f, JSON.stringify(b.bundle));
    const logVkey = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8')).vkey;
    const r = spawnSync(process.execPath, [cli, 'verify', '--bundle', f, '--json', '--log-vkey', logVkey], { encoding: 'utf8', env: { ...process.env, TROOTH_WEB: 'http://127.0.0.1:9', TROOTH_API: 'http://127.0.0.1:9' } });
    const doc = JSON.parse(r.stdout);
    ok('verify-result.schema.json', doc, name);
    assert.equal(doc.verdict, b.expect.verdict, name);
    assert.ok(doc.log, `${name} carries the log part`);
  }
});

test('public-record readings built by the scan worker validate (docs/EVIDENCE.md)', () => {
  for (const n of ['apple.com', 'apple-support.example', 'cloudflare.com', 'nvidia.com']) {
    ok('public-record.v1.schema.json', JSON.parse(readFileSync(new URL(`./fixtures/public-record/${n}.json`, import.meta.url), 'utf8')), n);
  }
  // A signed answer, as a local run of the scan worker served it on 2026-10-07
  // (signed with that run's throwaway keys): the reading, its statement and its receipt.
  const signed = JSON.parse(readFileSync(new URL('./fixtures/public-record/apple.com.signed.json', import.meta.url), 'utf8'));
  ok('public-record.v1.schema.json', signed, 'a signed reading');
  ok('public-record-statement.v1.schema.json', JSON.parse(signed.signed.statement.payload), 'its statement payload');
  ok('witness-statement.schema.json', signed.signed.statement, 'its envelope');
  ok('log-receipt.schema.json', signed.signed.log, 'its receipt');
  assert.equal(signed.entity.id, 'trooth:entity:lei:HWUPKR0MPOU8FGXBT394');
  assert.notDeepEqual(validate('public-record-statement.v1.schema.json', { ...JSON.parse(signed.signed.statement.payload), extra: 1 }), [], 'no field outside the schema is signed');
});

test('stable ids: format, parse and refuse', () => {
  assert.equal(formatId('domain', 'Trooth.CO.'), 'trooth:domain:trooth.co');
  assert.deepEqual(parseId('trooth:mapping:1.0.1'), { type: 'mapping', value: '1.0.1' });
  assert.equal(parseId('trooth:domain:not a domain'), null);
  assert.equal(parseId('trooth:planet:earth'), null);
  assert.throws(() => formatId('statement', 'abc'));
  assert.equal(formatId('cik', '320193'), 'trooth:cik:0000320193');
  assert.equal(formatId('lei', 'hwupkr0mpou8fgxbt394'), 'trooth:lei:HWUPKR0MPOU8FGXBT394');
  assert.equal(parseId('trooth:cik:320193'), null);
  assert.match(statementId('{}'), /^trooth:statement:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a$/);
});

test('RFC 8785 profile: sorting by UTF-16 code units, ECMAScript escaping, integers only', () => {
  assert.equal(canonicalize({ '\u{1F600}': 1, 'דּ': 2, b: [true, null, 'a\u0000\u001f"\\/'] }), '{"b":[true,null,"a\\u0000\\u001f\\"\\\\/"],"\u{1F600}":1,"דּ":2}');
  assert.equal(canonicalize(-0), '0');
  assert.throws(() => canonicalize(0.5), CanonicalizationError);
  assert.throws(() => canonicalize(2 ** 53), CanonicalizationError);
  assert.throws(() => canonicalize('\uD800'), CanonicalizationError);
  assert.equal(isCanonical('{"a":1,"b":2}'), true);
  assert.equal(isCanonical('{"b":2,"a":1}'), false);
  assert.equal(isCanonical('{"a":1e0}'), false);
});

test('generated types are current', () => {
  execFileSync(process.execPath, [new URL('../scripts/gen-types.mjs', import.meta.url).pathname, '--check'], { stdio: 'pipe' });
});

// The fixture was read from the live server and signed by the scan worker's own code with a test key
// under the production key id; only its shape is checked here.
test('an MCP tool reading built and signed by the scan worker validates, and so does its statement (docs/EVIDENCE.md section 9)', () => {
  const r = JSON.parse(readFileSync(new URL('./fixtures/mcp-tools/api.trooth.co-public-mcp.json', import.meta.url), 'utf8'));
  ok('mcp-tools.v1.schema.json', r, 'the reading');
  ok('mcp-tools-statement.v1.schema.json', JSON.parse(r.signed.statement.payload), 'its statement payload');
  assert.notDeepEqual(validate('mcp-tools-statement.v1.schema.json', { ...JSON.parse(r.signed.statement.payload), extra: 1 }), [], 'no field outside the schema is signed');
  ok('log-receipt.schema.json', r.signed.log, 'its log receipt');
});

test('the subjects a reading names are Trooth ids (docs/IDS.md 1.3)', () => {
  const r = JSON.parse(readFileSync(new URL('./fixtures/public-record/nvidia.com.json', import.meta.url), 'utf8'));
  assert.ok(r.subjects.length >= 5);
  for (const s of r.subjects) assert.ok(parseId(s.id), s.id);
  const m = JSON.parse(readFileSync(new URL('./fixtures/mcp-tools/api.trooth.co-public-mcp.json', import.meta.url), 'utf8'));
  assert.deepEqual(parseId(m.subject_id), { type: 'mcp', value: 'api.trooth.co/public/mcp' });
  assert.equal(formatId('registry', 'US-NY:4986044'), 'trooth:registry:US-NY:4986044');
  assert.equal(parseId('trooth:repo:github.com/Troothllc'), null);
});

test('the Phase 3 public record fields validate, and values outside their enums do not (docs/EVIDENCE.md section 10)', () => {
  const r = JSON.parse(readFileSync(new URL('./fixtures/public-record/nvidia.com.json', import.meta.url), 'utf8'));
  const days = { regulator_filing: 90, registry_record: 365, sanctions_list: 7, procurement_exclusion: 7, domain_registration: 30, dns_configuration: 2, certificate_transparency: 7, site_publication: 30, patent_record: 90, merger_review: 30 };
  const p3 = {
    ...r,
    bindings: r.bindings.map((b, i) => ({ ...b, proof_method: i ? 'registry_name_match' : 'regulator_filing' })),
    evidence_classes: Object.entries(days).map(([c, d]) => ({ class: c, sections: ['sec'], stale_after_days: d, does_not_establish: 'One sentence.', read: c !== 'patent_record', observed_at: c !== 'patent_record' ? r.read_at : null, stale_after: c !== 'patent_record' ? r.read_at : null })),
    continuity: { previous: { read_at: r.read_at, record_sha256: 'a'.repeat(64) }, events: [{ kind: 'entity_changed', detail: 'now ties to another entity; kept apart.' }] },
    subjects: [...r.subjects, { id: 'trooth:contact:mailto:psirt@nvidia.com', kind: 'representative', basis: 'a contact the site publishes in security.txt; not a person authorized to act for the entity' }, { id: 'trooth:key:trooth-master-2026-09', kind: 'signing_authority', basis: "the key that signed this reading's statement" }],
  };
  ok('public-record.v1.schema.json', p3, 'a reading with the Phase 3 fields');
  ok('public-record.v1.schema.json', { ...p3, continuity: { previous: null, events: [] } }, 'a first reading');
  const bad = (v, label) => assert.notDeepEqual(validate('public-record.v1.schema.json', v), [], label);
  bad({ ...p3, bindings: [{ ...p3.bindings[0], proof_method: 'trusted' }] }, 'an unknown proof method');
  bad({ ...p3, evidence_classes: [{ ...p3.evidence_classes[0], class: 'rating' }] }, 'an unknown evidence class');
  bad({ ...p3, continuity: { previous: null, events: [{ kind: 'merged', detail: 'x' }] } }, 'an unknown continuity kind');
  bad({ ...p3, subjects: [{ id: 'trooth:contact:x.example', kind: 'officer', basis: 'x' }] }, 'an unknown subject kind');
});

test('contact ids: security.txt contacts in canonical form (docs/IDS.md 1.4)', () => {
  assert.equal(formatId('contact', 'mailto:Security@Example.COM?subject=x'), 'trooth:contact:mailto:Security@example.com');
  assert.equal(formatId('contact', 'https://Example.com/Report/?a=1#b'), 'trooth:contact:example.com/Report');
  assert.equal(formatId('contact', 'security.apple.com'), 'trooth:contact:security.apple.com');
  assert.deepEqual(parseId('trooth:contact:mailto:product-security@apple.com'), { type: 'contact', value: 'mailto:product-security@apple.com' });
  assert.deepEqual(parseId('trooth:contact:security.apple.com/report'), { type: 'contact', value: 'security.apple.com/report' });
  for (const bad of ['trooth:contact:mailto:a@Example.com', 'trooth:contact:mailto:a@localhost', 'trooth:contact:Security.apple.com', 'trooth:contact:example.com/a?b=1', 'trooth:contact:example.com/a#b', 'trooth:contact:https://example.com', 'trooth:contact:tel:+15550100', 'trooth:contact:mailto:a b@example.com']) assert.equal(parseId(bad), null, bad);
  for (const bad of ['http://example.com/report', 'tel:+15550100', 'mailto:a@b', 'https://user:pw@example.com/x']) assert.throws(() => formatId('contact', bad), bad);
  assert.equal(parseId(`trooth:contact:${'a'.repeat(490)}.example.com`), null, 'longer than 500 characters');
  const r = { subjects: [{ id: 'trooth:contact:mailto:psirt@widget.example', kind: 'representative', basis: 'a contact the site publishes in security.txt; not a person authorized to act for the entity' }, { id: 'trooth:key:trooth-master-2026-09', kind: 'signing_authority', basis: "the key that signed this reading's statement" }] };
  for (const s of r.subjects) assert.ok(parseId(s.id), s.id);
});

test('0.14.0: proofs, the declaration, the new subject kinds, continuity kinds and evidence classes validate; values outside their enums do not', () => {
  const r = JSON.parse(readFileSync(new URL('./fixtures/public-record/proofs.example.json', import.meta.url), 'utf8'));
  ok('public-record.v1.schema.json', r, 'a reading with proofs and a declaration');
  ok('public-record.v1.schema.json', { ...r, declaration: null }, 'a reading that did not look for a declaration');
  for (const s of r.subjects) assert.ok(parseId(s.id), s.id);
  for (const p of r.proofs) for (const b of p.binds) assert.ok(parseId(b), b);
  const bad = (v, label) => assert.notDeepEqual(validate('public-record.v1.schema.json', v), [], label);
  bad({ ...r, proofs: [{ ...r.proofs[0], proof_method: 'trusted' }] }, 'an unknown proof method');
  bad({ ...r, proofs: [{ ...r.proofs[0], status: 'verified' }] }, 'an unknown proof status');
  bad({ ...r, proofs: [{ ...r.proofs[0], binds: [r.proofs[0].binds[0]] }] }, 'a proof binding one subject');
  bad({ ...r, declaration: { ...r.declaration, status: 'trusted' } }, 'an unknown declaration status');
  bad({ ...r, bindings: [{ ...r.bindings[0], proof_method: 'self_asserted' }] }, 'an unknown binding proof method');
  ok('public-record.v1.schema.json', { ...r, bindings: r.bindings.map((b) => ({ ...b, proof_method: 'domain_signed_declaration' })) }, 'a new proof method on a binding');
});

test('a declaration trooth declare sign writes validates against declaration.v1, and one with a private key or an extra member does not', () => {
  const k = generateDeclarationKey();
  const d = buildDeclaration({ domain: 'acme.com', privateJwk: k.privateJwk, record: 'https://trooth.co/network/company/acme', products: [{ id: 'widget', name: 'Widget', url: 'https://acme.com/widget' }], apis: [{ base_url: 'https://api.acme.com', mcp: { url: 'https://api.acme.com/mcp', manifest_sha256: 'a'.repeat(64) } }], repositories: ['https://github.com/acme'] });
  ok('declaration.v1.schema.json', d, 'a signed declaration');
  assert.notDeepEqual(validate('declaration.v1.schema.json', { ...d, keys: [{ ...d.keys[0], d: k.privateJwk.d }] }), [], 'a private key');
  assert.notDeepEqual(validate('declaration.v1.schema.json', { ...d, extra: 1 }), [], 'an extra member');
  assert.notDeepEqual(validate('declaration.v1.schema.json', { ...d, products: [{ id: 'Widget', name: 'W', url: 'https://acme.com/' }] }), [], 'a product id outside the pattern');
});

test('company, product and person ids, and a company key id (docs/IDS.md 1.5)', () => {
  assert.equal(formatId('company', 'Acme-Cloud'), 'trooth:company:acme-cloud');
  assert.equal(formatId('product', 'ACME.com/widget'), 'trooth:product:acme.com/widget');
  assert.equal(formatId('person', '3f9a0c2b7d1e4a65'), 'trooth:person:3f9a0c2b7d1e4a65');
  assert.deepEqual(parseId('trooth:key:acme.com#kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'), { type: 'key', value: 'acme.com#kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k' });
  assert.deepEqual(parseId('trooth:key:trooth-master-2026-09'), { type: 'key', value: 'trooth-master-2026-09' });
  for (const bad of ['trooth:company:-acme', 'trooth:company:acme-', 'trooth:company:Acme', 'trooth:company:acme.com', `trooth:company:${'a'.repeat(65)}`,
    'trooth:product:acme.com', 'trooth:product:acme.com/Widget', 'trooth:product:ACME.com/widget', 'trooth:product:acme.com/-w', 'trooth:product:acme.com/a/b',
    'trooth:person:3F9A0C2B7D1E4A65', 'trooth:person:3f9a0c2b7d1e4a6', 'trooth:person:3f9a0c2b7d1e4a650', 'trooth:person:jane.doe',
    'trooth:key:acme.com#short', 'trooth:key:Acme.com#kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k', 'trooth:key:acme#kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k']) assert.equal(parseId(bad), null, bad);
  assert.throws(() => formatId('person', 'Jane Doe'));
  assert.throws(() => formatId('product', 'acme.com'));
});
