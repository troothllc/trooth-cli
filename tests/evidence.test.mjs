// tests/evidence.test.mjs - delegation receipts and action evidence references
// (docs/ACTION-EVIDENCE.md): trooth/evidence against objects signed the way
// the Worker signs them (tests/lib/action-fixtures.mjs, a throwaway Ed25519
// key from node:crypto and a fake /public/keys document), and `trooth evidence
// verify` and `trooth delegation verify` end to end, with --online against a
// loopback server. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import {
  verifyEvidence, verifyDelegationReceipt, extractJws, decodeJws, delegationDigest, bindingReferenceSha, canonicalJson as libCanonical,
  EvidenceInputError, EVIDENCE_KEY_KID,
} from '../bin/lib/evidence.mjs';
import * as F from './lib/action-fixtures.mjs';

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const CLOSED = 'http://127.0.0.1:9';
const dir = mkdtempSync(join(tmpdir(), 'trooth-evidence-'));
let n = 0;
const file = (content) => { const p = join(dir, `f${n++}`); writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content)); return p; };

function run(args, { env = {}, stdin } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, ...args], { env: { ...process.env, TROOTH_API: CLOSED, TROOTH_WEB: CLOSED, NO_COLOR: '1', TROOTH_TIMEOUT_MS: '3000', ...env } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
    p.stdin.end(stdin ?? '');
  });
}

const KEY = F.makeKey();
const KEYS = F.keysDoc(KEY);
const keysFile = file(KEYS);
const D = F.delegationDoc();
const NOW = Date.now();
const iatNow = Math.floor(NOW / 1000) - 5;
const evidence = (opts = {}, header = F.EVIDENCE_HEADER, key = KEY) => F.signJws(F.evidencePayload(D, { iat: iatNow, ...opts }), key, header);
const receipt = (opts = {}, header = F.RECEIPT_HEADER, d = D) => F.signJws(F.receiptPayload(d, opts), KEY, header);
const tamper = (jws) => { const [h, p, s] = jws.split('.'); const pl = JSON.parse(Buffer.from(p, 'base64url')); pl.authorization_details[0].instructedAmount.amount = '9999.00'; return `${h}.${Buffer.from(JSON.stringify(pl)).toString('base64url')}.${s}`; };

/* ------------------------------------------------------------- library ---- */

test('a reference signed the way the Worker signs it checks, and its summary carries every printed field', () => {
  const r = verifyEvidence(evidence(), KEYS, { now: NOW });
  assert.equal(r.status, 'valid', r.problems.join('; '));
  assert.equal(r.signature, 'valid'); assert.equal(r.kid, EVIDENCE_KEY_KID);
  assert.deepEqual(r.key, { state: 'active', purpose: 'signed-references', trusted: true, reason: 'The key is active.' });
  assert.match(r.jti, /^ev_[0-9a-f]{32}$/); assert.equal(r.state_url, `https://api.trooth.co/public/action-evidence/${r.jti}`);
  const s = r.summary;
  assert.equal(s.action, 'trooth_payment'); assert.equal(s.verb, 'pay'); assert.equal(s.amount, '125.00'); assert.equal(s.currency, 'USD');
  assert.equal(s.target_domain, 'vendor.example'); assert.equal(s.delegation.id, D.id); assert.equal(s.delegation.sha256, F.delegationDigestOf(D));
  assert.deepEqual(s.delegation.limit, { amount: '500.00', currency: 'USD' });
  assert.equal(s.boundary_version, 'trooth.responsibility-boundary.v1-draft');
  assert.deepEqual(s.counterparty, { domain: 'vendor.example', status: 'read', read_at: F.READING.read_at, log_index: 4211, statement_sha256: 'c'.repeat(64), source: F.READING.source });
  assert.equal(s.approval.delegation.method, 'identity_provider'); assert.equal(s.approval.action, null);
  assert.equal(s.issued_at, new Date(iatNow * 1000).toISOString()); assert.equal(s.expires_at, new Date((iatNow + 600) * 1000).toISOString());
  assert.equal(s.binding.matches_mandate, null);
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
});

test('a data share, an action approval and an unread counterparty are summarized as such', () => {
  const r = verifyEvidence(evidence({ details: [F.DATA_DETAIL], actionApproval: F.APPROVAL, reading: { status: 'not_read', source: F.READING.source } }), KEYS, { now: NOW });
  assert.equal(r.status, 'valid', r.problems.join('; '));
  assert.equal(r.summary.action, 'trooth_data_share'); assert.equal(r.summary.data_class, 'internal'); assert.equal(r.summary.amount, null);
  assert.equal(r.summary.approval.action.approved_by, F.APPROVAL.approved_by);
  assert.equal(r.summary.counterparty.status, 'not_read'); assert.equal(r.summary.counterparty.read_at, null);
});

test('not trusted: a changed payload, another key, an unknown kid, another purpose, a compromised key, alg not EdDSA, malformed', () => {
  const bad = verifyEvidence(tamper(evidence()), KEYS, { now: NOW });
  assert.equal(bad.status, 'not_trusted'); assert.equal(bad.signature, 'invalid'); assert.equal(bad.summary, null);
  assert.equal(verifyEvidence(evidence({}, F.EVIDENCE_HEADER, F.makeKey()), KEYS, { now: NOW }).signature, 'invalid');
  const unknown = verifyEvidence(evidence({}, { ...F.EVIDENCE_HEADER, kid: 'trooth-evidence-2099' }), KEYS, { now: NOW });
  assert.equal(unknown.status, 'not_trusted'); assert.match(unknown.reason, /not on the key list/); assert.equal(unknown.signature, 'not_checked');
  const ledger = verifyEvidence(evidence(), F.keysDoc(KEY, { purpose: 'trust-ledger' }), { now: NOW });
  assert.equal(ledger.status, 'not_trusted'); assert.match(ledger.reason, /purpose "trust-ledger", not signed-references/);
  const comp = verifyEvidence(evidence(), F.keysDoc(KEY, { status: 'compromised', compromised_at: '2026-10-01T00:00:00Z' }), { now: NOW });
  assert.equal(comp.status, 'not_trusted'); assert.equal(comp.key.state, 'compromised');
  const retiredLater = verifyEvidence(evidence(), F.keysDoc(KEY, { retired_at: new Date(NOW + 86400000).toISOString() }), { now: NOW });
  assert.equal(retiredLater.status, 'valid', 'a key retired after iat still vouches for what it signed before');
  assert.equal(verifyEvidence(evidence({}, { ...F.EVIDENCE_HEADER, alg: 'none' }), KEYS, { now: NOW }).status, 'not_trusted');
  assert.equal(verifyEvidence('a.b', KEYS).status, 'not_trusted');
  assert.equal(verifyEvidence('e30.e30.AAAA', { nokeys: true }).status, 'not_trusted');
  assert.throws(() => decodeJws('x.y'), EvidenceInputError);
  assert.equal(verifyEvidence(evidence(), KEYS.keys, { now: NOW }).status, 'valid', 'a bare keys array is accepted');
});

test('mismatch: a delegation receipt passed as evidence (wrong typ), the wrong format, a lifetime over 600 s, an iat in the future', () => {
  const typ = verifyEvidence(evidence({}, F.RECEIPT_HEADER), KEYS, { now: NOW });
  assert.equal(typ.status, 'mismatch'); assert.equal(typ.signature, 'valid'); assert.match(typ.reason, /typ is "trooth-delegation-receipt\+jwt".*trooth delegation verify/);
  const rcpt = verifyEvidence(receipt(), KEYS, { now: NOW });
  assert.equal(rcpt.status, 'mismatch');
  const fmt = F.evidencePayload(D, { iat: iatNow }); fmt.format = 'trooth.action-evidence.v2';
  assert.match(verifyEvidence(F.signJws(fmt, KEY, F.EVIDENCE_HEADER), KEYS, { now: NOW }).reason, /format is "trooth.action-evidence.v2"/);
  assert.match(verifyEvidence(evidence({ ttl: 3600 }), KEYS, { now: NOW }).reason, /lifetime is 3600 s/);
  assert.match(verifyEvidence(evidence({ iat: iatNow + 3600 }), KEYS, { now: NOW }).reason, /in the future/);
  const kid = F.evidencePayload(D, { iat: iatNow }); kid.verify.kid = 'trooth-runtime-2026';
  assert.equal(verifyEvidence(F.signJws(kid, KEY, F.EVIDENCE_HEADER), KEYS, { now: NOW }).status, 'mismatch');
});

test('expired is a state: everything else holds, and exp has passed', () => {
  const r = verifyEvidence(evidence({ iat: iatNow - 3600 }), KEYS, { now: NOW });
  assert.equal(r.status, 'expired'); assert.equal(r.signature, 'valid'); assert.deepEqual(r.problems, []);
  assert.ok(r.summary && r.summary.amount === '125.00');
  assert.equal(verifyEvidence(evidence({ iat: iatNow - 3600 }), KEYS, { now: (iatNow - 3300) * 1000 }).status, 'valid');
});

test('the mandate binding: SHA-256 of protocol, newline, reference', () => {
  assert.equal(bindingReferenceSha('ap2', 'mandate-0001-abcdef'), F.evidencePayload(D).binding.reference_sha256);
  const jws = evidence();
  const ok = verifyEvidence(jws, KEYS, { now: NOW, binding: { protocol: 'ap2', reference: 'mandate-0001-abcdef' } });
  assert.equal(ok.status, 'valid'); assert.equal(ok.summary.binding.matches_mandate, true);
  const other = verifyEvidence(jws, KEYS, { now: NOW, binding: { protocol: 'acp', reference: 'mandate-0001-abcdef' } });
  assert.equal(other.status, 'mismatch'); assert.equal(other.summary.binding.matches_mandate, false); assert.match(other.reason, /not bound to this mandate/);
});

test('extractJws: the JWS, the API\'s JSON (evidence, receipt, a delegations list), and refusals', () => {
  const jws = evidence();
  assert.equal(extractJws(`  ${jws}\n`, 'evidence').jws, jws);
  assert.equal(extractJws(JSON.stringify({ id: 'act_x', status: 'issued', jti: 'ev_x', evidence: jws, expires_at: 'x' }), 'evidence').jws, jws);
  assert.equal(extractJws(JSON.stringify({ jti: 'ev_x', evidence: jws }), 'evidence').jws, jws);
  const r = receipt();
  const created = extractJws(JSON.stringify({ ok: true, delegation: D, digest: 'sha256:x', token: 'dl_secret', receipt: r }), 'delegation');
  assert.equal(created.jws, r); assert.equal(created.delegation.id, D.id);
  const listed = extractJws(JSON.stringify({ delegations: [{ ...D, digest: 'sha256:x', revoked_at: null, receipts: [{ event: 'created', recorded_at: 'x', receipt: r }] }] }), 'delegation');
  assert.equal(listed.jws, r); assert.equal(delegationDigest(listed.delegation), F.delegationDigestOf(D));
  assert.throws(() => extractJws(JSON.stringify({ delegations: [{ receipts: [{ receipt: r }, { receipt: r }] }] }), 'delegation'), /lists 2 delegation receipts/);
  assert.throws(() => extractJws(JSON.stringify({ receipt: r }), 'evidence'), /run trooth delegation verify/);
  assert.throws(() => extractJws('hello world', 'evidence'), EvidenceInputError);
  assert.throws(() => extractJws('{nope', 'evidence'), /does not parse/);
  assert.throws(() => extractJws('', 'evidence'), /empty/);
  assert.equal(libCanonical({ b: 1, a: [true, null, 'x'], c: undefined }), '{"a":[true,null,"x"],"b":1}');
});

test('a delegation receipt checks; with its document, the digest is checked and the scope reported', () => {
  const r = verifyDelegationReceipt(receipt(), KEYS, { now: NOW });
  assert.equal(r.status, 'valid', r.problems.join('; '));
  const s = r.summary;
  assert.equal(s.event, 'created'); assert.equal(s.delegation_id, D.id); assert.equal(s.agent_jkt, D.agent.jkt);
  assert.deepEqual(s.actions, ['trooth_payment']); assert.equal(s.target_domain, 'vendor.example');
  assert.equal(s.expires_at, D.expires_at); assert.equal(s.delegation_expired, false); assert.equal(s.recorded_at, '2026-10-15T11:58:00.000Z');
  assert.equal(s.scope, null); assert.equal(s.scope_source, 'not supplied');
  const withDoc = verifyDelegationReceipt(receipt(), KEYS, { now: NOW, delegation: { ...D, digest: 'sha256:x', revoked_at: null, receipts: [] } });
  assert.equal(withDoc.status, 'valid');
  assert.deepEqual(withDoc.summary.scope, { role: 'buyer', limit: { amount: '500.00', currency: 'USD' }, data_class: null, approval_above: '250.00' });
  const changed = verifyDelegationReceipt(receipt(), KEYS, { now: NOW, delegation: { ...D, limit: { amount: '50000.00', currency: 'USD' } } });
  assert.equal(changed.status, 'mismatch'); assert.equal(changed.summary.scope, null); assert.match(changed.reason, /hashes to/);
  const revoked = verifyDelegationReceipt(receipt({ event: 'revoked', approval: null, at: Date.parse('2026-10-20T10:00:00.123Z') }), KEYS, { now: NOW });
  assert.equal(revoked.status, 'valid', revoked.problems.join('; ')); assert.equal(revoked.summary.event, 'revoked'); assert.equal(revoked.summary.approval, null);
  assert.equal(verifyDelegationReceipt(receipt(), KEYS, { now: Date.parse('2027-01-01T00:00:00Z') }).summary.delegation_expired, true);
});

test('a delegation receipt: bad signature, unknown kid, wrong typ, an event outside created and revoked', () => {
  const r = receipt();
  const [h, p, sig] = r.split('.');
  const pl = JSON.parse(Buffer.from(p, 'base64url')); pl.delegation.actions = ['trooth_payment', 'trooth_data_share'];
  assert.equal(verifyDelegationReceipt(`${h}.${Buffer.from(F.canonicalJson(pl)).toString('base64url')}.${sig}`, KEYS).status, 'not_trusted');
  assert.equal(verifyDelegationReceipt(receipt({}, { ...F.RECEIPT_HEADER, kid: 'nope' }), KEYS).status, 'not_trusted');
  const typ = verifyDelegationReceipt(evidence(), KEYS, { now: NOW });
  assert.equal(typ.status, 'mismatch'); assert.match(typ.reason, /trooth evidence verify/);
  const ev = F.receiptPayload(D); ev.event = 'renewed';
  assert.equal(verifyDelegationReceipt(F.signJws(ev, KEY, F.RECEIPT_HEADER), KEYS).status, 'mismatch');
});

/* ----------------------------------------------------------------- CLI ---- */

test('trooth evidence verify: a valid reference prints its summary and exits 0', async () => {
  const r = await run(['evidence', 'verify', file(evidence()), '--keys', keysFile]);
  assert.equal(r.code, 0, r.err);
  for (const want of [/checks/, /pay 125\.00 USD to Vendor Inc\./, /target {7}vendor\.example/, new RegExp(`delegation {3}${D.id}`), /boundary {5}trooth\.responsibility-boundary\.v1-draft/, /counterparty vendor\.example: Trooth's signed reading of 2026-10-15T09:00:00\.000Z, log index 4211/, /issued {7}20/, /expires {6}20/, /--online reads/]) assert.match(r.out, want);
  assert.equal(r.err, '');
});

test('trooth evidence verify --json prints one typed document', async () => {
  const jws = evidence();
  const r = await run(['evidence', 'verify', file({ jti: 'ev_x', evidence: jws }), '--keys', keysFile, '--json', '--protocol', 'ap2', '--reference', 'mandate-0001-abcdef']);
  assert.equal(r.code, 0, r.err);
  const doc = JSON.parse(r.out);
  assert.equal(doc.ok, true); assert.equal(doc.exit, 0); assert.equal(doc.kind, 'action-evidence'); assert.equal(doc.status, 'valid');
  assert.equal(doc.signature, 'valid'); assert.equal(doc.kid, EVIDENCE_KEY_KID); assert.equal(doc.online, null);
  assert.equal(doc.summary.amount, '125.00'); assert.equal(doc.summary.binding.matches_mandate, true);
  assert.equal(doc.payload.format, 'trooth.action-evidence.v1'); assert.equal(doc.header.typ, 'trooth-action-evidence+jwt');
  assert.equal(doc.sources.keys, keysFile); assert.equal(doc.sources.keys_read_at, KEYS.list_read_at);
  for (const k of ['status', 'reason', 'problems', 'signature', 'kid', 'key', 'header', 'payload', 'sha256', 'issued_at', 'expires_at', 'summary', 'jti', 'state_url', 'online', 'sources', 'ok', 'exit']) assert.ok(k in doc, k);
});

test('trooth evidence verify exit codes: 8 bad signature or unknown kid, 9 wrong typ or another mandate, 11 expired, 2 usage', async () => {
  const bad = await run(['evidence', 'verify', file(tamper(evidence())), '--keys', keysFile]);
  assert.equal(bad.code, 8); assert.match(bad.out, /not trusted/); assert.match(bad.out, /signature does not verify/);
  const unknown = await run(['evidence', 'verify', file(evidence({}, { ...F.EVIDENCE_HEADER, kid: 'x' })), '--keys', keysFile, '--json']);
  assert.equal(unknown.code, 8); assert.equal(JSON.parse(unknown.out).status, 'not_trusted');
  const typ = await run(['evidence', 'verify', file(evidence({}, F.RECEIPT_HEADER)), '--keys', keysFile]);
  assert.equal(typ.code, 9); assert.match(typ.out, /mismatch/);
  assert.equal((await run(['evidence', 'verify', file(evidence()), '--keys', keysFile, '--protocol', 'acp', '--reference', 'other'])).code, 9);
  const exp = await run(['evidence', 'verify', file(evidence({ iat: iatNow - 7200 })), '--keys', keysFile, '--json']);
  assert.equal(exp.code, 11); const e = JSON.parse(exp.out); assert.equal(e.status, 'expired'); assert.equal(e.ok, false); assert.equal(e.summary.amount, '125.00');
  assert.match((await run(['evidence', 'verify', file(evidence({ iat: iatNow - 7200 })), '--keys', keysFile])).out, /expired/);
  assert.equal((await run(['evidence', 'verify', file('not a jws'), '--keys', keysFile])).code, 2);
  assert.equal((await run(['evidence', 'verify', join(dir, 'missing'), '--keys', keysFile])).code, 2);
  assert.equal((await run(['evidence', 'verify', '--keys', keysFile])).code, 2);
  assert.equal((await run(['evidence', 'check', file(evidence()), '--keys', keysFile])).code, 2);
  assert.equal((await run(['evidence', 'verify', file(evidence()), '--keys', keysFile, '--protocol', 'ap2'])).code, 2);
  const err = await run(['evidence', 'verify', file('nope'), '--keys', keysFile, '--json']);
  assert.equal(JSON.parse(err.out).exit, 2);
});

test('trooth evidence verify - reads stdin; without --keys an unreachable key list exits 3', async () => {
  const r = await run(['evidence', 'verify', '-', '--keys', keysFile], { stdin: evidence() });
  assert.equal(r.code, 0, r.err);
  const down = await run(['evidence', 'verify', file(evidence())]);
  assert.equal(down.code, 3); assert.match(down.err, /key list could not be read/);
});

test('--online: the key list and the public state from the API; issued 0, redeemed and revoked 12, expired 11, unknown 1, an error 3', async () => {
  const states = new Map();
  const srv = http.createServer((req, res) => {
    if (req.url === '/public/keys') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(KEYS)); }
    const m = /^\/public\/action-evidence\/(ev_[0-9a-f]+)$/.exec(req.url);
    const st = m && states.get(m[1]);
    if (st === 500) { res.writeHead(500, { 'content-type': 'application/json' }); return res.end('{}'); }
    if (!st) { res.writeHead(404, { 'content-type': 'application/json' }); return res.end('{"error":"not_found"}'); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jti: m[1], state: st, expires_at: '2026-10-15T12:10:00.000Z', redeemed_at: st === 'redeemed' ? '2026-10-15T12:01:00.000Z' : null }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const env = { TROOTH_API: `http://127.0.0.1:${srv.address().port}` };
  try {
    const want = { issued: 0, redeemed: 12, revoked: 12, expired: 11, 500: 3 };
    for (const [st, code] of Object.entries(want)) {
      const jws = evidence();
      states.set(decodeJws(jws).payload.jti, st === '500' ? 500 : st);
      const r = await run(['evidence', 'verify', file(jws), '--online', '--json'], { env });
      assert.equal(r.code, code, `${st}: ${r.err}`);
      if (code !== 3) { const doc = JSON.parse(r.out); assert.equal(doc.online.state, st); assert.equal(doc.sources.keys, `${env.TROOTH_API}/public/keys`); }
    }
    const unknown = await run(['evidence', 'verify', file(evidence()), '--online'], { env });
    assert.equal(unknown.code, 1); assert.match(unknown.out, /not known to/);
    const redeemed = evidence(); states.set(decodeJws(redeemed).payload.jti, 'redeemed');
    assert.match((await run(['evidence', 'verify', file(redeemed), '--online'], { env })).out, /state {8}redeemed {2}redeemed at 2026-10-15T12:01:00\.000Z/);
    const bad = await run(['evidence', 'verify', file(tamper(evidence())), '--online', '--json'], { env });
    assert.equal(bad.code, 8); assert.equal(JSON.parse(bad.out).online, null, 'an untrusted reference is not looked up');
  } finally { srv.close(); }
});

test('trooth delegation verify: the create response checks with its scope; --json; bad signature 8; another document 9', async () => {
  const created = file({ ok: true, delegation: D, digest: `sha256:${F.delegationDigestOf(D)}`, receipt: receipt() });
  const r = await run(['delegation', 'verify', created, '--keys', keysFile]);
  assert.equal(r.code, 0, r.err);
  for (const want of [/created/, new RegExp(`delegation {3}${D.id}`), new RegExp(`agent key {4}${D.agent.jkt}`), /actions {6}trooth_payment/, /target {7}vendor\.example/, /limit {8}500\.00 USD/, /approval {5}above 250\.00 USD/, /expires {6}2026-11-14T12:00:00\.000Z/, /recorded {5}2026-10-15T11:58:00\.000Z/]) assert.match(r.out, want);
  const j = await run(['delegation', 'verify', created, '--keys', keysFile, '--json']);
  const doc = JSON.parse(j.out);
  assert.equal(doc.exit, 0); assert.equal(doc.kind, 'delegation-receipt'); assert.equal(doc.summary.scope.approval_above, '250.00'); assert.equal(doc.sources.delegation, created);
  const bare = await run(['delegation', 'verify', '-', '--keys', keysFile], { stdin: receipt({ event: 'revoked', approval: null }) });
  assert.equal(bare.code, 0, bare.err); assert.match(bare.out, /revoked/); assert.match(bare.out, /pass --delegation/);
  const r2 = receipt(); const [h, p, s] = r2.split('.');
  assert.equal((await run(['delegation', 'verify', file(`${h}.${p}.${s.slice(0, -4)}AAAA`), '--keys', keysFile])).code, 8);
  const other = await run(['delegation', 'verify', file(receipt()), '--keys', keysFile, '--delegation', file({ delegation: { ...D, approval_above: '499.00' } })]);
  assert.equal(other.code, 9); assert.match(other.out, /hashes to/);
  assert.equal((await run(['delegation', 'verify', file(evidence()), '--keys', keysFile])).code, 9);
  assert.equal((await run(['delegation', 'verify', file({ evidence: evidence() }), '--keys', keysFile])).code, 2);
});

/* --------------------------------------------------------- witness log ---- */

test('verifyLogCommitment: a commitment signed the way the Worker signs it checks against the original; every rule is enforced', async () => {
  const { verifyLogCommitment, commitmentFromLogEntry } = await import('../bin/lib/evidence.mjs');
  const ev = evidence(); const rc = receipt();
  const ok = verifyLogCommitment(F.commitment(ev, 'action_evidence', KEY), ev, KEYS);
  assert.equal(ok.status, 'valid', ok.problems.join('; '));
  assert.equal(ok.kind, 'action_evidence'); assert.equal(ok.signature, 'valid'); assert.equal(ok.kid, EVIDENCE_KEY_KID);
  assert.equal(ok.committed_sha256, F.sha256Hex(ev)); assert.equal(ok.expected_sha256, F.sha256Hex(ev));
  assert.equal(verifyLogCommitment(F.commitment(rc, 'delegation_receipt', KEY), rc, KEYS).status, 'valid');
  // the key list as an array works too
  assert.equal(verifyLogCommitment(F.commitment(rc, 'delegation_receipt', KEY), rc, KEYS.keys).status, 'valid');
  const mm = (c, orig = ev, opts) => { const r = verifyLogCommitment(c, orig, KEYS, opts); assert.equal(r.status, 'mismatch', JSON.stringify(r.problems)); return r.reason; };
  const nt = (c, keys = KEYS) => { const r = verifyLogCommitment(c, ev, keys); assert.equal(r.status, 'not_trusted', JSON.stringify(r.problems)); return r.reason; };
  // another object's digest, a one-character change, another kind
  assert.match(mm(F.commitment(evidence(), 'action_evidence', KEY)), /not .*the SHA-256 of the JWS checked/);
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY), `${ev} `, { kind: 'action_evidence' }), /not .*the SHA-256 of the JWS checked/);
  assert.match(mm(F.commitment(ev, 'delegation_receipt', KEY)), /kind is "delegation_receipt", not action_evidence/);
  assert.match(mm(F.commitment(rc, 'action_evidence', KEY), rc), /kind is "action_evidence", not delegation_receipt/);
  assert.equal(verifyLogCommitment(F.commitment(rc, 'action_evidence', KEY), rc, KEYS, { kind: 'action_evidence' }).status, 'valid', 'opts.kind overrides');
  // typ, format, extra or missing keys, iat, sha256 form
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY, { header: { ...F.COMMITMENT_HEADER, typ: 'trooth-action-evidence+jwt' } })), /typ/);
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY, { extra: { format: 'trooth.log-commitment.v2' } })), /format/);
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY, { extra: { domain: 'vendor.example' } })), /not exactly format, kind, sha256 and iat/);
  assert.match(mm(F.signJws({ format: 'trooth.log-commitment.v1', kind: 'action_evidence', sha256: F.sha256Hex(ev) }, KEY, F.COMMITMENT_HEADER)), /not exactly/);
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY, { iat: 1.5 })), /iat/);
  assert.match(mm(F.commitment(ev, 'action_evidence', KEY, { sha256: F.sha256Hex(ev).toUpperCase() })), /64 lowercase hex/);
  // the original is neither kind
  assert.match(mm(F.commitment('a.b.c', 'action_evidence', KEY), 'a.b.c'), /cannot be checked/);
  // signature, key, alg, malformed
  const other = F.makeKey();
  assert.match(nt(F.commitment(ev, 'action_evidence', other)), /signature does not verify/);
  assert.match(nt(F.commitment(ev, 'action_evidence', KEY, { header: { ...F.COMMITMENT_HEADER, kid: 'trooth-runtime-2026-10' } })), /purpose "trust-ledger"/);
  assert.match(nt(F.commitment(ev, 'action_evidence', KEY, { header: { ...F.COMMITMENT_HEADER, kid: 'nope' } })), /not on the key list/);
  assert.match(nt(F.commitment(ev, 'action_evidence', KEY, { header: { ...F.COMMITMENT_HEADER, alg: 'none' } })), /alg/);
  assert.match(nt('not.a.jws!'), /malformed/);
  assert.match(nt(F.commitment(ev, 'action_evidence', KEY), F.keysDoc(KEY, { state: 'compromised', status: 'revoked', compromised_at: '2026-01-01T00:00:00.000Z' })), /not trusted/);
  // the entry wrapper
  const c = F.commitment(ev, 'action_evidence', KEY);
  const got = commitmentFromLogEntry(F.logEntry(12, 'action_evidence', c, F.sha256Hex(ev)));
  assert.deepEqual({ kind: got.kind, jws: got.jws, index: got.index }, { kind: 'action_evidence', jws: c, index: 12 });
  assert.equal(commitmentFromLogEntry(JSON.stringify(F.logEntry(1, 'delegation_receipt', c, 'a'))).kind, 'delegation_receipt');
  assert.throws(() => commitmentFromLogEntry({ index: 0, kind: 'witness_statement', entry: { kind: 'witness_statement', statement: { payload: '{}' } } }), EvidenceInputError);
  assert.throws(() => commitmentFromLogEntry({ index: 0, kind: 'action_evidence', entry: { statement: { payload: '{"not":"a jws"}' } } }), EvidenceInputError);
  assert.throws(() => commitmentFromLogEntry('nope'), EvidenceInputError);
});

test('extractJws returns the log place the API answers with: log, receipt_log, a listed receipt\'s log', () => {
  const ev = evidence(); const rc = receipt();
  const place = { statement_id: `trooth:statement:${'c'.repeat(64)}`, index: 8, url: 'https://api.trooth.co/scan/log/v1/entries/8' };
  assert.deepEqual(extractJws(JSON.stringify({ evidence: ev, log: place }), 'evidence').log, place);
  assert.equal(extractJws(JSON.stringify({ evidence: ev, log: null }), 'evidence').log, null);
  assert.equal(extractJws(ev, 'evidence').log, null);
  assert.deepEqual(extractJws(JSON.stringify({ receipt: rc, delegation: D, receipt_log: { ...place, index: 7 } }), 'delegation').log.index, 7);
  assert.equal(extractJws(JSON.stringify({ delegations: [{ ...D, receipts: [{ event: 'created', receipt: rc, log: { ...place, index: 3 } }] }] }), 'delegation').log.index, 3);
  assert.equal(extractJws(JSON.stringify({ delegation: { ...D, receipts: [{ event: 'created', receipt: rc, log: null }] } }.delegation), 'delegation').log, null);
  assert.equal(extractJws(JSON.stringify({ evidence: ev, log: { index: -1 } }), 'evidence').log.index, null);
});

test('--log: logged at index N; another digest, another kind, no entry or a bad signature 9 or 8; an unreadable log 3; no index 2', async () => {
  const entries = new Map();
  const srv = http.createServer((req, res) => {
    if (req.url === '/public/keys') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify(KEYS)); }
    const m = /^\/scan\/log\/v1\/entries\/(\d+)$/.exec(req.url);
    const e = m && entries.get(Number(m[1]));
    if (e === 500) { res.writeHead(500, { 'content-type': 'application/json' }); return res.end('{}'); }
    if (!e) { res.writeHead(404, { 'content-type': 'application/json' }); return res.end('{"error":"no such entry"}'); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(e));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const env = { TROOTH_API: `http://127.0.0.1:${srv.address().port}` };
  const put = (i, kind, original, opts) => entries.set(i, F.logEntry(i, kind, F.commitment(original, kind, opts?.key ?? KEY, opts), F.sha256Hex(original)));
  const place = (i) => ({ statement_id: 'x', index: i, url: `https://api.trooth.co/scan/log/v1/entries/${i}` });
  try {
    // an authorization answer carrying log.index
    const ev = evidence(); put(8, 'action_evidence', ev);
    const ok = await run(['evidence', 'verify', file({ evidence: ev, log: place(8) }), '--log'], { env });
    assert.equal(ok.code, 0, ok.err + ok.out);
    assert.match(ok.out, /log {10}logged at index 8/);
    const j = JSON.parse((await run(['evidence', 'verify', file({ evidence: ev, log: place(8) }), '--log', '--json'], { env })).out);
    assert.equal(j.exit, 0); assert.equal(j.log.status, 'valid'); assert.equal(j.log.index, 8); assert.equal(j.log.index_source, 'the input JSON');
    assert.equal(j.log.committed_sha256, j.sha256); assert.equal(j.sources.log, `${env.TROOTH_API}/scan/log/v1/entries/8`);
    // --keys from a file with --log: still verifies the commitment with those keys
    assert.equal((await run(['evidence', 'verify', file({ evidence: ev, log: place(8) }), '--log', '--keys', keysFile], { env })).code, 0);
    // a bare JWS with --log-index (implies --log)
    const bare = await run(['evidence', 'verify', file(ev), '--log-index', '8', '--json'], { env });
    assert.equal(bare.code, 0, bare.err); assert.equal(JSON.parse(bare.out).log.index_source, '--log-index');
    // a delegation create answer carrying receipt_log
    const rc = receipt(); put(7, 'delegation_receipt', rc);
    const d = await run(['delegation', 'verify', file({ ok: true, delegation: D, receipt: rc, receipt_log: place(7) }), '--log'], { env });
    assert.equal(d.code, 0, d.err + d.out); assert.match(d.out, /logged at index 7/);
    // a GET /v1/delegations entry with the receipt's own log
    assert.equal((await run(['delegation', 'verify', file({ delegations: [{ ...D, receipts: [{ event: 'created', receipt: rc, log: place(7) }] }] }), '--log'], { env })).code, 0);
    // entry 8 is a commitment to another reference: 9
    const ev2 = evidence();
    const wrong = await run(['evidence', 'verify', file({ evidence: ev2, log: place(8) }), '--log', '--json'], { env });
    assert.equal(wrong.code, 9); const w = JSON.parse(wrong.out); assert.equal(w.status, 'valid'); assert.equal(w.log.status, 'mismatch'); assert.match(w.log.reason, /SHA-256 of the JWS checked/);
    assert.match((await run(['evidence', 'verify', file({ evidence: ev2, log: place(8) }), '--log'], { env })).out, /not logged as this JWS/);
    // the receipt checked against the evidence entry: another kind, 9
    assert.equal((await run(['delegation', 'verify', file(rc), '--log-index', '8'], { env })).code, 9);
    // no entry at that index: 9
    assert.equal((await run(['evidence', 'verify', file(ev), '--log-index', '99'], { env })).code, 9);
    // a commitment signed by another key: 8
    put(9, 'action_evidence', ev, { key: F.makeKey() });
    assert.equal((await run(['evidence', 'verify', file(ev), '--log-index', '9'], { env })).code, 8);
    // a log that answers 500: 3, with the output still printed
    entries.set(10, 500);
    const down = await run(['evidence', 'verify', file(ev), '--log-index', '10', '--json'], { env });
    assert.equal(down.code, 3); assert.equal(JSON.parse(down.out).log.status, 'unreadable');
    // an expired reference that is logged stays 11; one that is not logged becomes 9
    const old = evidence({ iat: iatNow - 7200 }); put(11, 'action_evidence', old);
    assert.equal((await run(['evidence', 'verify', file(old), '--log-index', '11'], { env })).code, 11);
    assert.equal((await run(['evidence', 'verify', file(old), '--log-index', '8'], { env })).code, 9);
    // no index anywhere: 2; a pending log (null): 2; a bad --log-index: 2
    assert.equal((await run(['evidence', 'verify', file(ev), '--log'], { env })).code, 2);
    const pend = await run(['evidence', 'verify', file({ evidence: ev, log: null }), '--log'], { env });
    assert.equal(pend.code, 2); assert.match(pend.err, /no log index/);
    assert.equal((await run(['evidence', 'verify', file(ev), '--log-index', 'x'], { env })).code, 2);
    // an untrusted reference is not looked up in the log
    const t = await run(['evidence', 'verify', file(tamper(ev)), '--log-index', '8', '--json'], { env });
    assert.equal(t.code, 8); assert.equal(JSON.parse(t.out).log, null);
    // without --log nothing is read from the log
    const plain = JSON.parse((await run(['evidence', 'verify', file({ evidence: ev, log: place(8) }), '--json'], { env })).out);
    assert.equal(plain.log, null); assert.equal(plain.sources.log, null);
  } finally { srv.close(); }
});
