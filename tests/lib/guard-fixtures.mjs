// tests/lib/guard-fixtures.mjs - a small Trooth "world" for the guard tests:
// Ed25519 keys generated here (never a Trooth key), signed witness statements
// and public record statements, a Merkle log with a signed checkpoint, witness
// cosignatures, corrections, and a fetch() that answers as trooth.co and
// api.trooth.co do. Every request it is sent is recorded, so a test can show
// what the guard sent and what it did not.
import { generateKeyPairSync, createPublicKey, createHash, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalize, canonicalizeRecord } from '../../bin/lib/jcs.mjs';
import { entryBytes, leafHash, rootOf, inclusionPath, consistencyPath, formatVkey, noteKeyHash, toB64, LOG_ORIGIN } from '../../bin/lib/tlog.mjs';
import { sha256Digest, canonicalManifest } from '../../bin/lib/verify.mjs';
import { statementId } from '../../bin/lib/ids.mjs';

export const API = 'https://api.trooth.test';
export const WEB = 'https://trooth.test';
export const NOW = Date.parse('2026-10-07T12:00:00.000Z');
export const READ_AT = '2026-10-06T12:00:00.000Z';

export function keyPair() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { priv: privateKey, pub: Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url') };
}
export const K = { a: keyPair(), b: keyPair(), log: keyPair(), logX: keyPair(), w1: keyPair(), w2: keyPair(), wx: keyPair() };
export const VKEY = formatVkey(LOG_ORIGIN, K.log.pub);
export const VKEY_IMPOSTOR = formatVkey(LOG_ORIGIN, K.logX.pub);
const cosignerId = (name, pub) => createHash('sha256').update(Buffer.concat([Buffer.from(name), Buffer.from([0x0a, 0x04]), pub])).digest().subarray(0, 4);
const wvkey = (name, pub) => `${name}+${cosignerId(name, pub).toString('hex')}+${Buffer.concat([Buffer.from([4]), pub]).toString('base64')}`;
export const W1 = { name: 'witness.one.test/w', kp: K.w1 };
export const W2 = { name: 'witness.two.test/w', kp: K.w2 };
export const WITNESSES = [wvkey(W1.name, W1.kp.pub), wvkey(W2.name, W2.kp.pub)];

export const keyEntry = (kid, kp, extra = {}) => ({ kid, alg: 'Ed25519', encoding: 'base64', public_key: kp.pub.toString('base64'), status: 'active', ...extra });
export const DEFAULT_KEYS = () => [keyEntry('test-guard-a', K.a), keyEntry('test-guard-b', K.b)];
const sig = (kp, payload) => `ed25519:${sign(null, Buffer.from(payload, 'utf8'), kp.priv).toString('base64')}`;

const MANIFEST = (domain) => [
  { check_id: 'S1', source: `https://${domain}/` },
  { check_id: 'S2', source: `https://${domain}/.well-known/security.txt` },
];

/** A signed v3 witness statement and its manifest. */
export function witnessStatement({ domain, signedDomain = domain, readAt = READ_AT, kid = 'test-guard-a', kp = K.a, version = 'trooth.witness-statement.v3', checks, tamper } = {}) {
  const cs = checks ?? [
    { id: 'S1', category: 'security', kind: 'probe', outcome: 'as expected', reason: null },
    { id: 'S2', category: 'security', kind: 'probe', outcome: 'not as expected', reason: { code: 'expected_item_absent', version: 'trooth.check-explanations.v1', source_ref: `https://${signedDomain}/.well-known/security.txt`, withheld: false, withheld_reason: null } },
  ];
  const manifest = MANIFEST(signedDomain);
  const read = cs.filter((c) => c.outcome !== 'not read').length;
  const asExpected = cs.filter((c) => c.outcome === 'as expected').length;
  const p = {
    statement: version,
    reading_id: `scan_guard_${signedDomain.replace(/[^a-z0-9]/g, '_')}`,
    domain: signedDomain,
    read_at: readAt,
    subject_scope: { domain: signedDomain, surface: 'public', checks_in_scope: cs.length },
    methodology: { standard: 'Trooth Standard 1.0', mapping_version: 'test-1.0.0', mapping_url: 'https://trooth.co/standard/check-mapping/test-1.0.0.json', mapping_digest: sha256Digest('mapping bytes not served in these tests') },
    evaluator: { name: 'trooth-scan-worker', version: 'guard-tests' },
    evidence_manifest: { digest: sha256Digest(canonicalManifest(manifest)), entries: manifest.length, canonicalization: 'trooth.evidence-manifest.v1: JSON array sorted by check_id, keys check_id then source or commitment, no whitespace, UTF-8' },
    checks: cs,
    counts: { read, as_expected: asExpected, not_as_expected: read - asExpected, not_read: cs.length - read, in_reading: cs.length },
    subject_id: `trooth:domain:${signedDomain}`,
    signer: { key_id: kid, issuer: 'trooth.co' },
  };
  if (tamper?.payloadObject) tamper.payloadObject(p);
  const payload = canonicalize(p);
  const statement = { payload, signature: sig(kp, payload), key_id: kid, alg: 'Ed25519', canonicalization: 'RFC8785' };
  if (tamper?.statement) tamper.statement(statement);
  return { statement, manifest };
}

const BASE_RECORD = JSON.parse(readFileSync(new URL('../fixtures/public-record/apple.com.json', import.meta.url), 'utf8'));
const CLASSES = [['regulator_filing', ['sec'], 90], ['registry_record', ['lei', 'registries'], 365], ['sanctions_list', ['sanctions'], 7], ['procurement_exclusion', ['sam'], 7], ['domain_registration', ['domain_registration'], 30], ['site_publication', ['site', 'security_txt'], 30]];

/** A public record reading for `domain`, with evidence_classes, before signing. */
export function publicRecord({ domain, readAt = READ_AT, sanctionsMatches = [], samExclusions = [], entity = true, securityTxt = true, injection = null, classes = true } = {}) {
  const r = JSON.parse(JSON.stringify(BASE_RECORD));
  r.domain = domain; r.subject_id = `trooth:domain:${domain}`; r.read_at = readAt;
  r.entity = entity ? { id: 'trooth:entity:lei:HWUPKR0MPOU8FGXBT394', name: injection ?? 'Acme Test Inc.', identifiers: ['trooth:lei:HWUPKR0MPOU8FGXBT394'], basis: 'the LEI binding is corroborated' } : null;
  r.sanctions = { list: 'OFAC SDN', source: 'https://sanctionslistservice.ofac.treas.gov/', read_at: readAt, names_checked: ['Acme Test Inc.'], matches: sanctionsMatches };
  r.sam = { source: 'https://api.sam.gov/entity-information/v4', read_at: readAt, names_checked: ['Acme Test Inc.'], registrations: [], exclusions: samExclusions };
  r.domain_registration = { source: `https://rdap.org/domain/${domain}`, registrar: 'Test Registrar', registered: '2001-01-01', changed: null, expires: '2030-01-01', transferred: null, status: [] };
  r.security_txt = securityTxt ? { url: `https://${domain}/.well-known/security.txt`, contacts: [`mailto:security@${domain}`], expires: '2027-06-21T01:00:00.000Z', expired: false, policy: null, canonical: [], signed: false } : null;
  if (injection) { r.site = { ...r.site, legal_names: [{ name: injection, source: `https://${domain}/` }] }; r.note = injection; }
  if (classes) r.evidence_classes = CLASSES.map(([c, sections, days]) => ({ class: c, sections, stale_after_days: days, does_not_establish: 'test', read: true, observed_at: readAt, stale_after: new Date(Date.parse(readAt) + days * 86400000).toISOString() }));
  return r;
}

/** Sign a public record answer: the statement naming its RFC 8785 SHA-256. The log receipt is added by the world. */
export function signRecord(record, { kid = 'test-guard-a', kp = K.a, issuedAt = READ_AT, signedDomain = record.domain, tamper } = {}) {
  const sha = createHash('sha256').update(canonicalizeRecord(record)).digest('hex');
  const p = {
    statement: 'trooth.public-record.v1', subject_id: `trooth:domain:${signedDomain}`, domain: signedDomain, read_at: record.read_at,
    record_sha256: sha, record_canonicalization: 'RFC8785', entity_id: record.entity?.id ?? null,
    bindings: record.bindings.map((b) => ({ id: b.id, status: b.status })), sources: record.sources.length,
    issued_at: issuedAt, signer: { key_id: kid, issuer: 'trooth.co' },
  };
  if (signedDomain !== record.domain) p.subject_id = record.subject_id; // only the domain differs
  if (tamper?.payloadObject) tamper.payloadObject(p);
  const payload = canonicalize(p);
  const statement = { payload, signature: sig(kp, payload), key_id: kid, alg: 'Ed25519', canonicalization: 'RFC8785' };
  return { ...record, signed: { record_sha256: sha, record_canonicalization: 'RFC8785', statement, statement_id: statementId(payload), log: null, problem: null } };
}

/** A correction withdrawing `target` (a statement envelope). */
export function correction(target, { kp = K.a, kid = 'test-guard-a', code = 'source_misread', issuedAt = '2026-10-07T00:00:00.000Z', subject = 'trooth:domain:acme.com' } = {}) {
  const payload = canonicalize({ statement: 'trooth.correction.v1', correction_id: `corr_${statementId(target.payload).slice(-8)}`, supersedes: statementId(target.payload), subject_id: subject, effect: 'withdrawn', replacement: null, reason: { code, explanation: 'Withdrawn in a test.' }, issued_at: issuedAt, signer: { key_id: kid, issuer: 'trooth.co' } });
  return { payload, signature: sig(kp, payload), key_id: kid, alg: 'Ed25519', canonicalization: 'RFC8785' };
}

function signNote(text, kp = K.log) {
  return `${text}\n— ${LOG_ORIGIN} ${Buffer.concat([noteKeyHash(LOG_ORIGIN, kp.pub), sign(null, Buffer.from(text, 'utf8'), kp.priv)]).toString('base64')}\n`;
}
function cosign(body, w, ts) {
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(ts));
  const s = sign(null, Buffer.from(`cosignature/v1\ntime ${ts}\n${body}`, 'utf8'), w.kp.priv);
  return `— ${w.name} ${Buffer.concat([cosignerId(w.name, w.kp.pub), t, s]).toString('base64')}\n`;
}

/**
 * Build a world. `domains` maps a domain to:
 *   { projection: 'found'|'absent'|'error'|'withheld'|'contract3'|{domain: 'other'},
 *     witness: options for witnessStatement | null, public: options for publicRecord | null | 'unsigned',
 *     signPublic: options for signRecord, logWitness, logPublic (default true),
 *     correctWitness, correctPublic (add a valid correction) }
 * Options: keys, cosigners (0, 1 or 2; default 2), extraEntries (log grows after the receipts:
 * receipts are against an older checkpoint and the cosigned one is newer), forgeProof, logCheckpointKey.
 */
export function makeWorld({ domains = {}, keys = DEFAULT_KEYS(), cosigners = 2, growAfter = 0, forgeProof = null, down = false, slow = false, hugeProjection = false, logDown = false, cosignAt = NOW - 600000 } = {}) {
  const entries = [];
  const per = {};
  for (const [domain, cfg] of Object.entries(domains)) {
    const out = { cfg };
    if (cfg.witness !== null && cfg.witness !== undefined) {
      out.witness = witnessStatement({ domain, ...cfg.witness });
      if (cfg.logWitness !== false) { out.wIndex = entries.length; entries.push(['witness_statement', out.witness.statement]); }
      if (cfg.correctWitness) { out.wCorr = correction(out.witness.statement, { subject: `trooth:domain:${domain}`, ...(cfg.correctWitness === true ? {} : cfg.correctWitness) }); out.wCorrIndex = entries.length; entries.push(['correction', out.wCorr]); }
    }
    if (cfg.public !== null && cfg.public !== undefined) {
      if (cfg.public === 'unsigned') out.pub = { ...publicRecord({ domain }), signed: null };
      else {
        out.pub = signRecord(publicRecord({ domain, ...cfg.public }), cfg.signPublic || {});
        if (cfg.logPublic !== false) { out.pIndex = entries.length; entries.push(['public_record', out.pub.signed.statement]); }
        if (cfg.correctPublic) { out.pCorr = correction(out.pub.signed.statement, { subject: `trooth:domain:${domain}` }); out.pCorrIndex = entries.length; entries.push(['correction', out.pCorr]); }
      }
    }
    per[domain] = out;
  }
  // Something unrelated in the log, so trees are never trivially small.
  entries.unshift(['witness_statement', witnessStatement({ domain: 'unrelated.test' }).statement]);
  for (const o of Object.values(per)) for (const k of ['wIndex', 'wCorrIndex', 'pIndex', 'pCorrIndex']) if (o[k] !== undefined) o[k] += 1;
  const receiptSize = entries.length;
  for (let i = 0; i < growAfter; i++) entries.push(['witness_statement', witnessStatement({ domain: `later${i}.test` }).statement]);
  const leaves = entries.map(([k, s]) => leafHash(entryBytes(k, s)));
  const rLeaves = leaves.slice(0, receiptSize);
  const cpText = (n, ls) => `${LOG_ORIGIN}\n${n}\n${toB64(rootOf(ls))}\n`;
  const receiptCheckpoint = signNote(cpText(receiptSize, rLeaves));
  const fullText = cpText(leaves.length, leaves);
  const cosignTs = Math.floor(cosignAt / 1000);
  let cosigned = signNote(fullText);
  if (cosigners >= 1) cosigned += cosign(fullText, W1, cosignTs);
  if (cosigners >= 2) cosigned += cosign(fullText, W2, cosignTs);
  const receipt = (i) => {
    const r = { log: LOG_ORIGIN, index: i, tree_size: receiptSize, root_hash: toB64(rootOf(rLeaves)), inclusion_proof: inclusionPath(i, rLeaves).map(toB64), checkpoint: receiptCheckpoint };
    return forgeProof ? forgeProof(r) : r;
  };
  for (const o of Object.values(per)) if (o.pub?.signed && o.pIndex !== undefined) o.pub.signed.log = receipt(o.pIndex);

  const requests = [];
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const text = (status, body) => new Response(body, { status, headers: { 'content-type': 'text/plain' } });
  const bySid = (sid) => {
    for (const o of Object.values(per)) {
      if (o.witness && statementId(o.witness.statement.payload) === sid) return { o, kind: 'w' };
      if (o.pub?.signed?.statement && statementId(o.pub.signed.statement.payload) === sid) return { o, kind: 'p' };
    }
    return null;
  };
  async function fetchFn(url, init = {}) {
    requests.push({ url: String(url), method: init.method || 'GET', headers: init.headers || {} });
    if (down) throw new TypeError('fetch failed');
    if (slow) await new Promise((resolve, reject) => { const t = setTimeout(resolve, 5000); init.signal?.addEventListener('abort', () => { clearTimeout(t); reject(init.signal.reason); }); });
    const u = new URL(url);
    if (`${u.protocol}//${u.host}` === WEB && u.pathname === '/api/network/profile') {
      const d = u.searchParams.get('q');
      const o = per[d];
      if (hugeProjection) return new Response('x'.repeat(3 * 1024 * 1024), { status: 200, headers: { 'content-type': 'application/json' } });
      if (!o) return json(200, { found: false });
      const p = o.cfg.projection ?? 'found';
      if (p === 'absent') return json(200, { found: false });
      if (p === 'error') return json(503, { error: 'unavailable' });
      if (p === 'withheld') return json(200, { found: true, withheld: true, slug: d, name: 'Acme', reason: 'under review' });
      const body = { found: true, contractVersion: p === 'contract3' ? 3 : 2, slug: d, domain: typeof p === 'object' ? p.domain : d, facts: [], name: o.cfg.profileName ?? 'Acme', description: o.cfg.profileText ?? '' };
      if (o.witness) { body.witnessStatement = o.witness.statement; body.witnessEvidenceManifest = o.witness.manifest; }
      if (o.cfg.profileLinks) body.links = o.cfg.profileLinks;
      return json(200, body);
    }
    if (`${u.protocol}//${u.host}` !== API) return json(404, { error: 'not found' });
    if (u.pathname === '/public/keys') return json(200, { keys, list_read_at: new Date(NOW).toISOString() });
    if (logDown && u.pathname.startsWith('/scan/log/v1/')) return json(500, { error: 'log unavailable' });
    if (u.pathname === '/scan/log/v1/checkpoint') return text(200, cosigned);
    if (u.pathname === '/scan/log/v1/proof/consistency') {
      const first = Number(u.searchParams.get('first')), second = Number(u.searchParams.get('second'));
      return json(200, { consistency_proof: consistencyPath(first, leaves.slice(0, second)).map(toB64) });
    }
    if (u.pathname === '/scan/log/v1/lookup') {
      const hit = bySid(u.searchParams.get('statement_id'));
      if (hit && hit.kind === 'w' && hit.o.wIndex !== undefined) return json(200, { found: true, index: hit.o.wIndex, receipt: receipt(hit.o.wIndex) });
      if (hit && hit.kind === 'p' && hit.o.pIndex !== undefined) return json(200, { found: true, index: hit.o.pIndex, receipt: receipt(hit.o.pIndex) });
      return json(404, { found: false });
    }
    if (u.pathname === '/scan/log/v1/corrections') {
      const hit = bySid(u.searchParams.get('statement_id'));
      const out = [];
      if (hit?.kind === 'w' && hit.o.wCorr) out.push({ statement: hit.o.wCorr, receipt: receipt(hit.o.wCorrIndex) });
      if (hit?.kind === 'p' && hit.o.pCorr) out.push({ statement: hit.o.pCorr, receipt: receipt(hit.o.pCorrIndex) });
      if (hit && hit.o.cfg.forgedCorrection) out.push({ statement: correction(hit.kind === 'w' ? hit.o.witness.statement : hit.o.pub.signed.statement, { kp: K.b }), receipt: receipt(0) });
      return json(200, { corrections: out });
    }
    const m = /^\/scan\/public-record\/([^/]+)$/.exec(u.pathname);
    if (m) {
      const d = decodeURIComponent(m[1]);
      if (u.searchParams.get('cached') !== 'only') return json(400, { error: 'the guard must ask with cached=only' });
      const o = per[d];
      const served = o?.cfg.servePublicFor ? per[o.cfg.servePublicFor]?.pub : o?.pub;
      if (!served) return json(404, { error: `no public record reading of ${d} in the last day`, cached: false });
      return json(200, served);
    }
    return json(404, { error: 'not found' });
  }
  return { fetch: fetchFn, requests, per, vkeys: [VKEY], witnesses: WITNESSES, now: () => NOW, api: API, web: WEB, receiptSize, size: leaves.length };
}

export const POLICY_YAML = `# a test policy
policy: vendor-payments
version: 3
applies_to:
  tools: ["stripe.create_payout", "mcp__bank__*"]
  http: [{ method: "POST", host: "*.example-bank.com" }]
host_from: ["url", "endpoint", "host", "domain", "base_url", "webhook_url", "email", "to"]
log: { required: true, min_witnesses: 1 }
rules:
  - id: legal-entity
    require: { claim: legal_entity_registry_record, max_age_days: 365 }
    on_fail: hold
  - id: no-sanctions-match
    require: { claim: no_sanctions_name_match, max_age_days: 7 }
    on_fail: hold
  - id: no-compromised-keys
    require: { signature: valid, key_status: [active, retired_before_use] }
    on_fail: deny
    absolute: true
destinations: { allowed: ["api.stripe.com"] }
unknown_counterparty: hold
source_unreachable: hold
`;
