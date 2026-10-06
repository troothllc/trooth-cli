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
import { canonicalManifest, sha256Digest, makeBundle } from '../../bin/lib/verify.mjs';
import { canonicalize } from '../../bin/lib/jcs.mjs';

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

// v3: the same reading as v2, with the subject named by its stable id and the
// signing key named inside the signed bytes, serialized as RFC 8785 (JCS). The
// non-ASCII and U+2028 text in a withheld reason makes every implementation's
// string escaping meet the same bytes.
function v3obj(over = {}) {
  const base = JSON.parse(v2({ domain: over.domain }));
  base.statement = 'trooth.witness-statement.v3';
  base.reading_id = 'scan_vectors_3';
  base.subject_id = over.subjectId ?? `trooth:domain:${over.domain ?? 'acme-vectors.com'}`;
  base.signer = { key_id: over.signerKid ?? 'test-key-a', issuer: 'trooth.co' };
  base.checks[2].reason.withheld_reason = 'source privée\u2028held by its owner';
  return base;
}
const v3 = (over) => canonicalize(v3obj(over));
const st3 = (payload, kp = A, kid = 'test-key-a', label = 'RFC8785') => ({ payload, signature: sig(kp, payload), key_id: kid, alg: 'Ed25519', canonicalization: label });

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
  { name: 'valid-v3', note: 'A v3 statement: RFC 8785 bytes, subject id and signer inside the signed bytes.', statement: st3(v3()), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'v3-no-manifest-supplied', note: 'Not supplied is never reported as a match, in v3 either.', statement: st3(v3()), keys: KEYS, mapping: true, manifest: null, domain: 'acme-vectors.com', expect: { verdict: 'partially_checked', signature: 'valid' } },
  { name: 'v3-not-canonical', note: 'Signed correctly, but the payload bytes are not the RFC 8785 form: refused before the signature is checked.', statement: st3(JSON.stringify(v3obj())), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
  { name: 'v3-fraction', note: 'A number written 2.0 is not canonical: the canonical text of the same value is 2.', statement: st3(v3().replace('"read":2}', '"read":2.0}')), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
  { name: 'v3-wrong-label', note: 'A v3 payload in an envelope that names the v2 canonicalization.', statement: st3(v3(), A, 'test-key-a', 'json-fixed-key-order-no-whitespace-utf8'), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
  { name: 'v3-signer-differs', note: 'The envelope names key A; the signed bytes name key B.', statement: st3(v3({ signerKid: 'test-key-b' })), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
  { name: 'v3-tampered', note: 'One outcome changed after signing.', statement: { ...st3(v3()), payload: v3().replace('"outcome":"as expected"', '"outcome":"not read"') }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'invalid' } },
  { name: 'v3-subject-id-disagrees', note: 'Signed, but the stable id names another domain than the payload does.', statement: st3(v3({ subjectId: 'trooth:domain:acme-lookalike.com' })), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'v3-domain-mismatch', note: 'A genuine v3 statement for another domain.', statement: st3(v3()), keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-lookalike.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'wrong-alg', note: 'A statement naming another algorithm is not checked as Ed25519.', statement: { ...st(good), alg: 'RS256' }, keys: KEYS, mapping: true, manifest: MANIFEST, domain: 'acme-vectors.com', expect: { verdict: 'signature_not_trusted', signature: 'malformed' } },
];

const doc = {
  description: 'Test vectors for docs/VERIFY.md. Each case gives a statement, a key list, whether the mapping is the signed one (true), a different one ("other") or not supplied (false), a manifest, the domain asked about, and the expected verdict and signature result. The keys are test keys derived from public strings in generate.mjs; they are not Trooth keys.',
  mapping_file: 'mapping-test-1.0.0.json',
  other_mapping_file: 'mapping-test-other.json',
  vectors,
};
// Bundles: the same checks, carried in one portable file (docs/VERIFY.md section 7).
const OTHER = readFileSync(new URL('mapping-test-other.json', here));
const bundleOf = (statement, over = {}) => makeBundle({ domain: 'acme-vectors.com', statement, manifest: MANIFEST, keys: KEYS, keysReadAt: '2026-10-06T00:00:00.000Z', keysSource: 'https://api.trooth.co/public/keys', mappingUrl: MAPPING_URL, mappingBytes: MAPPING, createdAt: '2026-10-06T00:00:00.000Z', ...over });
const bundles = [
  { name: 'bundle-v3', note: 'Everything needed, in one file, checked with no network.', bundle: bundleOf(st3(v3())), expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'bundle-v2', note: 'A v2 statement in a bundle.', bundle: bundleOf(st(good)), expect: { verdict: 'checked', signature: 'valid' } },
  { name: 'bundle-no-mapping', note: 'A bundle saved without the mapping bytes.', bundle: bundleOf(st3(v3()), { mappingBytes: undefined }), expect: { verdict: 'partially_checked', signature: 'valid' } },
  { name: 'bundle-other-mapping', note: 'The bytes carried are not the mapping that was signed.', bundle: bundleOf(st3(v3()), { mappingBytes: OTHER }), expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'bundle-asked-other-domain', note: 'The reader asks about a different domain than the bundle names.', bundle: bundleOf(st3(v3())), domain: 'acme-lookalike.com', expect: { verdict: 'mismatch', signature: 'valid' } },
  { name: 'bundle-compromised-key', note: 'The key list carried in the bundle marks the key compromised.', bundle: bundleOf(st3(v3()), { keys: [keyA({ status: 'compromised', compromised_at: '2026-10-02T00:00:00.000Z' }), keyB] }), expect: { verdict: 'signature_not_trusted', signature: 'valid' } },
  { name: 'not-a-bundle', note: 'A document that is not a bundle is refused, not checked.', bundle: { bundle: 'something.else', statement: st(good) }, expect: { error: 'not_a_bundle' } },
];

const write = (file, value, count, what) => {
  const text = JSON.stringify(value, null, 2) + '\n';
  const target = new URL(file, here);
  if (process.argv.includes('--check')) {
    if (readFileSync(target, 'utf8') !== text) { console.error(`${file} differs from what generate.mjs builds`); process.exit(1); }
    console.log(`${file} reproduces: ${count} ${what}`);
  } else {
    writeFileSync(target, text);
    console.log(`wrote ${file}: ${count} ${what}`);
  }
};
write('vectors.json', doc, vectors.length, 'cases');
write('bundles.json', { description: 'Verification bundles (trooth.verification-bundle.v1) and the verdict each must reach when checked with no network. `domain`, when present, is the domain the reader asks about in place of the one the bundle names. The keys are the same test keys as vectors.json.', bundles }, bundles.length, 'bundles');
