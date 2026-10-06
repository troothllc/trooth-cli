// tests/vectors/generate.mjs - builds tests/vectors/vectors.json, the cases any
// implementation of docs/VERIFY.md must agree on.
//
//   node tests/vectors/generate.mjs           write vectors.json
//   node tests/vectors/generate.mjs --check   exit 1 if vectors.json differs from what this builds
//
// THE KEYS HERE ARE TEST KEYS. Their seeds are derived from public strings below,
// so anyone can regenerate every signature; that is the point. They are not on
// Trooth's key list and nothing signed with them means anything outside this
// folder. Ed25519 signatures are deterministic, so the output is byte-stable.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { canonicalManifest, sha256Digest } from '../../bin/lib/verify.mjs';

const here = new URL('.', import.meta.url);
const seedOf = (label) => createHash('sha256').update(`trooth test vectors v1 / ${label} / NOT A TROOTH KEY`).digest();

function keyPair(label) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seedOf(label)]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const pub = Buffer.from(createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url');
  return { priv, pub };
}

const A = keyPair('key-a');
const B = keyPair('key-b');
const sig = (kp, payload) => `ed25519:${sign(null, Buffer.from(payload, 'utf8'), kp.priv).toString('base64')}`;

const MAPPING = readFileSync(new URL('mapping-test-1.0.0.json', here));
const MAPPING_URL = 'https://trooth.co/standard/check-mapping/test-1.0.0.json';
const MANIFEST = [
  { check_id: 'S1', source: 'https://acme-vectors.com/' },
  { check_id: 'S2', source: 'https://acme-vectors.com/.well-known/security.txt' },
  { check_id: 'S3', commitment: sha256Digest('private reference opened only by its holder') },
];

function v2(over = {}) {
  const checks = over.checks ?? [
    { id: 'S1', category: 'security', kind: 'probe', outcome: 'as expected', reason: null },
    { id: 'S2', category: 'security', kind: 'probe', outcome: 'not as expected', reason: { code: 'expected_item_absent', version: 'trooth.check-explanations.v1', source_ref: 'https://acme-vectors.com/.well-known/security.txt', withheld: false, withheld_reason: null } },
    { id: 'S3', category: 'security', kind: 'probe', outcome: 'not read', reason: { code: 'timeout', version: 'trooth.check-explanations.v1', source_ref: null, withheld: true, withheld_reason: 'private source' } },
  ];
  const read = checks.filter((c) => c.outcome !== 'not read').length;
  const asExpected = checks.filter((c) => c.outcome === 'as expected').length;
  const counts = over.counts ?? { read, as_expected: asExpected, not_as_expected: read - asExpected, not_read: checks.length - read, in_reading: checks.length };
  return JSON.stringify({
    statement: 'trooth.witness-statement.v2',
    reading_id: 'scan_vectors_1',
    domain: over.domain ?? 'acme-vectors.com',
    read_at: over.readAt ?? '2026-10-01T12:00:00.000Z',
    subject_scope: { domain: over.domain ?? 'acme-vectors.com', surface: 'public', checks_in_scope: checks.length },
    methodology: { standard: 'Trooth Standard 1.0', mapping_version: 'test-1.0.0', mapping_url: MAPPING_URL, mapping_digest: sha256Digest(MAPPING) },
    evaluator: { name: 'trooth-scan-worker', version: 'vectors' },
    evidence_manifest: { digest: sha256Digest(canonicalManifest(MANIFEST)), entries: MANIFEST.length, canonicalization: 'trooth.evidence-manifest.v1: JSON array sorted by check_id, keys check_id then source or commitment, no whitespace, UTF-8' },
    checks,
    counts,
  });
}

function v1() {
  return JSON.stringify({
    statement: 'trooth.witness-statement.v1',
    reading_id: 'scan_vectors_v1',
    domain: 'acme-vectors.com',
    read_at: '2026-09-20T12:00:00.000Z',
    checks: [{ id: 'S1', category: 'security', kind: 'probe', outcome: 'as expected' }, { id: 'S2', category: 'security', kind: 'probe', outcome: 'not read' }],
    counts: { read: 1, as_expected: 1 },
  });
}

const st = (payload, kp = A, kid = 'test-key-a') => ({ payload, signature: sig(kp, payload), key_id: kid, alg: 'Ed25519', canonicalization: 'json-fixed-key-order-no-whitespace-utf8' });
const keyA = (extra = {}) => ({ kid: 'test-key-a', alg: 'Ed25519', encoding: 'base64', public_key: A.pub.toString('base64'), status: 'active', ...extra });
const keyB = { kid: 'test-key-b', alg: 'Ed25519', encoding: 'hex', public_key: B.pub.toString('hex'), status: 'active' };
const KEYS = [keyA(), keyB];

const good = v2();
const tamperedPayload = good.replace('"as expected"', '"not read"');
const vectors = [
  { name: 'valid-v2', note: 'Everything matches.', statement: st(good), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'valid-v2-hex-key', note: 'The same check with a key published in hex.', statement: st(good, B, 'test-key-b'), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'valid-v1', note: 'A v1 statement binds no mapping or manifest; narrower, not a failure.', statement: st(v1()), keys: KEYS, mapping: false, manifest: null, domain: 'acme-vectors.com', expect: { verdict: 'checked_v1', signature: 'valid' } },
  { name: 'v2-no-mapping-supplied', note: 'Not supplied is never reported as a match.', statement: st(good), keys: KEYS, mapping: false, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'partially_checked', signature: 'valid' } },
  { name: 'tampered-payload', note: 'One outcome changed after signing.', statement: { ...st(good), payload: tamperedPayload }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'invalid' } },
  { name: 'reserialized-payload', note: 'Same JSON, different bytes: the signature covers bytes, not meaning.', statement: { ...st(good), payload: JSON.stringify(JSON.parse(good), null, 1) }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'invalid' } },
  { name: 'wrong-key', note: 'Signed with key B but naming key A.', statement: st(good, B, 'test-key-a'), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'invalid' } },
  { name: 'unknown-key-id', note: 'A key id not on the list is not a Trooth key.', statement: st(good, A, 'test-key-z'), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'invalid' } },
  { name: 'compromised-key', note: 'Valid mathematics, compromised key: never relied on.', statement: st(good), keys: [keyA({ status: 'compromised', compromised_at: '2026-10-02T00:00:00.000Z' }), keyB], mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'valid' } },
  { name: 'revoked-without-reason', note: 'Revoked with no recorded reason is treated as compromised.', statement: st(good), keys: [keyA({ status: 'revoked', revoked_at: '2026-10-02T00:00:00.000Z' }), keyB], mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'valid' } },
  { name: 'retired-after-signing', note: 'Retired after the time the statement carries: still relied on.', statement: st(good), keys: [keyA({ status: 'retired', retired_at: '2026-10-05T00:00:00.000Z' }), keyB], mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'retired-before-signing', note: 'The statement carries a time after the key was retired.', statement: st(good), keys: [keyA({ status: 'retired', retired_at: '2026-09-25T00:00:00.000Z' }), keyB], mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'valid' } },
  { name: 'mapping-mismatch', note: 'A different mapping document than the one signed.', statement: st(good), keys: KEYS, mapping: 'other', manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'manifest-mismatch', note: 'One source changed in the manifest.', statement: st(good), keys: KEYS, mapping: true, manifest: MANIFEST.map((e) => (e.check_id === 'S1' ? { check_id: 'S1', source: 'https://elsewhere.example/' } : e)), domain: 'acme-vectors.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'domain-mismatch', note: 'A genuine statement for another domain.', statement: st(good), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-lookalike.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'counts-disagree', note: 'Signed, but the signed counts contradict the signed checks.', statement: st(v2({ counts: { read: 3, as_expected: 3, not_as_expected: 0, not_read: 0, in_reading: 3 } })), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'malformed-signature', note: 'No algorithm prefix.', statement: { ...st(good), signature: st(good).signature.replace('ed25519:', '') }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
  { name: 'wrong-alg', note: 'A statement naming another algorithm is not checked as Ed25519.', statement: { ...st(good), alg: 'RS256' }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
];

const doc = {
  description: 'Test vectors for docs/VERIFY.md. Each case gives a statement, a key list, whether the mapping is the signed one (true), a different one ("other") or not supplied (false), a manifest, the domain asked about, and the expected verdict and signature result. The keys are test keys derived from public strings in generate.mjs; they are not Trooth keys.',
  mapping_file: 'mapping-test-1.0.0.json',
  other_mapping_file: 'mapping-test-other.json',
  vectors,
};
const text = JSON.stringify(doc, null, 2) + '\n';
const target = new URL('vectors.json', here);
if (process.argv.includes('--check')) {
  if (readFileSync(target, 'utf8') !== text) { console.error('vectors.json differs from what generate.mjs builds'); process.exit(1); }
  console.log(`vectors.json reproduces: ${vectors.length} cases`);
} else {
  writeFileSync(target, text);
  console.log(`wrote vectors.json: ${vectors.length} cases`);
}
