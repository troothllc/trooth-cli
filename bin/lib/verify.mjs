// bin/lib/verify.mjs - the independent check of a Trooth witness statement.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// This is the normative check described in docs/VERIFY.md. It trusts nothing
// Trooth's website or API says about a statement: it takes the statement's
// exact payload bytes, the published key list and, for a v2 statement, the
// exact bytes of the check mapping and the evidence manifest, and decides
// for itself. It imports only node:crypto, so it can be copied, audited and
// re-implemented.
//
// The rules match Trooth's own verifiers (trooth-os-worker-f
// src/witness-statement.ts and src/key-trust.ts; trooth-web
// scripts/lib/witness-statement-check.mjs). tests/vectors/ holds the cases
// any implementation must agree on.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { isCanonical } from './jcs.mjs';
import { formatId, statementId } from './ids.mjs';

export const WITNESS_STATEMENT_V1 = 'trooth.witness-statement.v1';
export const WITNESS_STATEMENT_V2 = 'trooth.witness-statement.v2';
export const WITNESS_STATEMENT_V3 = 'trooth.witness-statement.v3';
export const VERIFICATION_BUNDLE_V1 = 'trooth.verification-bundle.v1';
/** The canonicalization label a v3 envelope carries. */
export const JCS_LABEL = 'RFC8785';

/** Reason codes a v2 check may carry, and the one outcome each may go with. */
export const REASONS = {
  source_unavailable: 'not read',
  timeout: 'not read',
  evaluator_limitation: 'not read',
  carried_from_earlier_reading: 'not read',
  check_misconfigured: 'not read',
  contrary_observation: 'not as expected',
  expected_item_absent: 'not as expected',
};

export const ASSURANCE = {
  v1: 'A valid v1 signature shows that Trooth\'s key signed these outcome bytes for this reading. It does not bind the check mapping, the evaluator version, the subject scope or the evidence sources.',
  v2: 'A valid v2 signature shows that Trooth\'s key signed these outcome bytes together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company\'s identity, an independently established time, or anything the reading did not read.',
  v3: 'A valid v3 signature shows that Trooth\'s key signed these RFC 8785 canonical outcome bytes, naming the subject by its stable id and the signing key inside the signed bytes, together with the digest of the exact check mapping, the evaluator version, the subject scope and the digest of the evidence manifest. It does not establish the company\'s identity, an independently established time, or anything the reading did not read.',
};

/** sha256:<hex> over exact bytes; a string is taken as its UTF-8 bytes. */
export function sha256Digest(bytes) {
  return `sha256:${createHash('sha256').update(typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : Buffer.from(bytes)).digest('hex')}`;
}

/** The canonical manifest bytes: entries sorted by check_id, fixed key order, no whitespace. */
export function canonicalManifest(entries) {
  if (!Array.isArray(entries)) throw new Error('the manifest is not a list');
  const sorted = [...entries].sort((a, b) => (a.check_id < b.check_id ? -1 : a.check_id > b.check_id ? 1 : 0));
  const seen = new Set();
  for (const e of sorted) {
    if (!e || typeof e.check_id !== 'string') throw new Error('a manifest entry has no check_id');
    if (seen.has(e.check_id)) throw new Error(`the manifest lists ${e.check_id} twice`);
    seen.add(e.check_id);
  }
  return JSON.stringify(sorted.map((e) => ('source' in e ? { check_id: e.check_id, source: e.source } : { check_id: e.check_id, commitment: e.commitment })));
}

function iso(v) {
  if (v === null || v === undefined || v === '') return null;
  const t = typeof v === 'number' ? v : Date.parse(String(v));
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** The lifecycle state of a published key. */
export function keyState(k) {
  if (!k) return 'unknown';
  if (iso(k.compromised_at)) return 'compromised';
  const status = String(k.status || '').toLowerCase();
  if (status === 'compromised') return 'compromised';
  if (iso(k.retired_at) || status === 'retired') return 'retired';
  if (status === 'revoked' || iso(k.revoked_at)) return 'revoked_unrecorded';
  if (status === 'active' || status === '') return 'active';
  return 'unknown';
}

/** Whether a valid signature from `kid`, carrying the time `signedAt`, may be relied on. */
export function keyTrust(kid, keys, signedAt) {
  const k = (keys || []).find((x) => x && x.kid === kid) || null;
  const state = keyState(k);
  if (state === 'active') return { kid, state, trusted: true, reason: 'The key is active.' };
  if (state === 'retired') {
    const retiredAt = iso(k.retired_at);
    const at = iso(signedAt);
    if (retiredAt && at && Date.parse(at) < Date.parse(retiredAt)) return { kid, state, trusted: true, reason: `Retired at ${retiredAt}; this signature carries the earlier time ${at}.` };
    return { kid, state, trusted: false, reason: retiredAt ? `Retired at ${retiredAt}; this signature carries ${at || 'no time'}, which is not before it.` : 'Retired with no recorded retirement time.' };
  }
  if (state === 'compromised') return { kid, state, trusted: false, reason: 'The key is compromised. No signature from it is relied on.' };
  if (state === 'revoked_unrecorded') return { kid, state, trusted: false, reason: 'The key is revoked with no recorded reason, so it is treated as compromised.' };
  return { kid, state, trusted: false, reason: 'The key id is not on the key list, so it is not a Trooth key.' };
}

/** The raw 32-byte Ed25519 public key a key-list entry carries (hex or base64). */
export function keyBytes(k) {
  const v = String(k?.public_key || '');
  if (k?.encoding === 'hex' || (/^[0-9a-f]{64}$/i.test(v) && k?.encoding !== 'base64')) return Buffer.from(v, 'hex');
  return Buffer.from(v, 'base64');
}

function ed25519Valid(publicKey32, signature64, message) {
  if (publicKey32.length !== 32 || signature64.length !== 64) return false;
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey32.toString('base64url') }, format: 'jwk' });
    return edVerify(null, message, key, signature64);
  } catch {
    return false;
  }
}

/** Count identities a payload must satisfy, for either version. Empty means they hold. */
export function countProblems(p) {
  const problems = [];
  const checks = Array.isArray(p?.checks) ? p.checks : [];
  const read = checks.filter((c) => c.outcome !== 'not read').length;
  const asExpected = checks.filter((c) => c.outcome === 'as expected').length;
  for (const c of checks) {
    if (!['as expected', 'not as expected', 'not read'].includes(c?.outcome)) problems.push(`${c?.id}: outcome "${c?.outcome}" is not one of the three`);
  }
  if (p?.counts?.read !== read) problems.push(`counts.read is ${p?.counts?.read}; the checks give ${read}`);
  if (p?.counts?.as_expected !== asExpected) problems.push(`counts.as_expected is ${p?.counts?.as_expected}; the checks give ${asExpected}`);
  if (p?.statement === WITNESS_STATEMENT_V2 || p?.statement === WITNESS_STATEMENT_V3) {
    const c = p.counts || {};
    if (c.read + c.not_read !== c.in_reading) problems.push('read + not_read does not equal in_reading');
    if (c.as_expected + c.not_as_expected !== c.read) problems.push('as_expected + not_as_expected does not equal read');
    if (c.in_reading !== checks.length) problems.push(`in_reading is ${c.in_reading}; ${checks.length} checks are listed`);
    if (p.subject_scope?.checks_in_scope !== checks.length) problems.push('subject_scope.checks_in_scope does not equal the checks listed');
    for (const ch of checks) {
      if (ch.outcome === 'as expected') continue;
      const r = ch.reason;
      if (!r || !(r.code in REASONS)) { problems.push(`${ch.id}: "${ch.outcome}" carries no known reason`); continue; }
      if (REASONS[r.code] !== ch.outcome) problems.push(`${ch.id}: reason ${r.code} cannot go with "${ch.outcome}"`);
      if (r.withheld && r.source_ref) problems.push(`${ch.id}: marked withheld but publishes a source`);
      if (r.withheld && !r.withheld_reason) problems.push(`${ch.id}: withheld with no reason given`);
    }
  }
  if (p?.statement === WITNESS_STATEMENT_V3) {
    let want = null;
    try { want = formatId('domain', p.domain); } catch { want = null; }
    if (!want || p.subject_id !== want) problems.push(`subject_id is ${p.subject_id}; the payload's domain gives ${want ?? 'no valid id'}`);
    if (p.subject_scope?.domain !== p.domain) problems.push('subject_scope.domain does not equal domain');
  }
  return problems;
}

/**
 * Check one statement.
 *   statement     { payload, signature, key_id, alg }   payload is the exact signed string
 *   keys          the `keys` array of api.trooth.co/public/keys (or a saved copy)
 *   mappingBytes  the exact bytes of the check mapping the payload names (v2), or undefined
 *   manifest      the evidence manifest entries (v2), or undefined
 *   domain        the domain the caller is about to rely on, or undefined
 *
 * Returns a result whose `verdict` is one of:
 *   checked               signature valid, key trusted, counts hold, subject matches,
 *                         and (v2) mapping and manifest both match what was signed
 *                         (v2 and v3 statements both reach `checked`)
 *   checked_v1            the same for a v1 statement, which binds no mapping or manifest
 *   partially_checked     all of the above that could be checked held, but the mapping
 *                         or the manifest was not supplied
 *   signature_not_trusted malformed, signature invalid, or key not trusted
 *   mismatch              a supplied mapping, manifest or domain does not match what was
 *                         signed, or the signed counts disagree with the signed checks
 */
export function verifyStatement({ statement, keys, mappingBytes, manifest, domain }) {
  let payload = null;
  try { payload = JSON.parse(String(statement?.payload ?? '')); } catch { payload = null; }
  const version = payload?.statement === WITNESS_STATEMENT_V1 ? 'v1' : payload?.statement === WITNESS_STATEMENT_V2 ? 'v2' : payload?.statement === WITNESS_STATEMENT_V3 ? 'v3' : 'unknown';
  // v3 adds three conditions to a well-formed envelope: the canonicalization it
  // names is RFC 8785, the payload bytes ARE the canonical form (so there is one
  // byte string per meaning), and the key named inside the signed bytes is the
  // key the envelope names.
  const v3Formed = version !== 'v3' || (statement?.canonicalization === JCS_LABEL && isCanonical(statement.payload) && payload?.signer?.key_id === statement?.key_id);
  const key = keyTrust(String(statement?.key_id ?? ''), keys, typeof payload?.read_at === 'string' ? payload.read_at : null);

  let signature = 'malformed';
  const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(statement?.signature ?? ''));
  const published = (keys || []).find((k) => k && k.kid === statement?.key_id);
  if (m && statement?.alg === 'Ed25519' && typeof statement.payload === 'string' && version !== 'unknown' && v3Formed) {
    signature = published && ed25519Valid(keyBytes(published), Buffer.from(m[1], 'base64'), Buffer.from(statement.payload, 'utf8')) ? 'valid' : 'invalid';
  }

  const trusted = signature === 'valid' && key.trusted;
  const result = {
    version,
    signature,
    key,
    trusted,
    subject: { signed: payload?.domain ?? null, asked: domain ?? null, status: 'not_checked' },
    binding: { status: 'unchecked', mapping: 'not_supplied', manifest: 'not_supplied' },
    counts: { identities_hold: false, problems: [] },
    read_at: typeof payload?.read_at === 'string' ? payload.read_at : null,
    reading_id: payload?.reading_id ?? null,
    statement_id: typeof statement?.payload === 'string' ? statementId(statement.payload) : null,
    assurance: ASSURANCE[version] || 'Not a Trooth witness statement this checker knows.',
    verdict: 'signature_not_trusted',
  };
  if (!trusted) return result;

  result.counts.problems = countProblems(payload);
  result.counts.identities_hold = result.counts.problems.length === 0;
  if (domain !== undefined) {
    const want = String(domain).toLowerCase().replace(/\.$/, '');
    result.subject.status = String(payload.domain || '').toLowerCase() === want ? 'match' : 'mismatch';
  }
  if (version === 'v1') {
    result.binding = { status: 'absent', mapping: 'absent', manifest: 'absent' };
  } else {
    const mapping = mappingBytes === undefined ? 'not_supplied' : sha256Digest(mappingBytes) === payload.methodology?.mapping_digest ? 'match' : 'mismatch';
    let man = 'not_supplied';
    if (manifest !== undefined) {
      try { man = sha256Digest(canonicalManifest(manifest)) === payload.evidence_manifest?.digest && manifest.length === payload.evidence_manifest?.entries ? 'match' : 'mismatch'; } catch { man = 'mismatch'; }
    }
    result.binding = { status: mapping === 'mismatch' || man === 'mismatch' ? 'mismatch' : mapping === 'match' && man === 'match' ? 'bound' : 'partially_checked', mapping, manifest: man };
  }

  if (!result.counts.identities_hold || result.subject.status === 'mismatch' || result.binding.status === 'mismatch') result.verdict = 'mismatch';
  else if (version === 'v1') result.verdict = 'checked_v1';
  else if (result.binding.status === 'bound') result.verdict = 'checked';
  else result.verdict = 'partially_checked';
  return result;
}

export class BundleError extends Error {}

/** Read a trooth.verification-bundle.v1 document into verifyStatement's inputs. Throws BundleError. */
export function bundleInputs(bundle) {
  if (!bundle || typeof bundle !== 'object' || bundle.bundle !== VERIFICATION_BUNDLE_V1) throw new BundleError(`not a ${VERIFICATION_BUNDLE_V1} document`);
  if (!bundle.statement || typeof bundle.statement.payload !== 'string') throw new BundleError('the bundle carries no statement with a payload');
  if (!bundle.keys || !Array.isArray(bundle.keys.keys)) throw new BundleError('the bundle carries no key list');
  if (bundle.manifest !== null && bundle.manifest !== undefined && !Array.isArray(bundle.manifest)) throw new BundleError('the bundle manifest is not a list');
  let mappingBytes;
  if (bundle.mapping !== null && bundle.mapping !== undefined) {
    const b64 = bundle.mapping.bytes_base64;
    if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) throw new BundleError('the bundle mapping is not standard base64');
    mappingBytes = Buffer.from(b64, 'base64');
  }
  return {
    statement: bundle.statement,
    keys: bundle.keys.keys,
    keysReadAt: typeof bundle.keys.list_read_at === 'string' ? bundle.keys.list_read_at : null,
    mappingBytes,
    manifest: Array.isArray(bundle.manifest) ? bundle.manifest : undefined,
    domain: typeof bundle.domain === 'string' ? bundle.domain : undefined,
  };
}

/** Check a bundle entirely offline. `domain` overrides the domain the bundle names. */
export function verifyBundle(bundle, { domain } = {}) {
  const i = bundleInputs(bundle);
  const result = verifyStatement({ statement: i.statement, keys: i.keys, mappingBytes: i.mappingBytes, manifest: i.manifest, domain: domain ?? i.domain });
  return { ...result, keys_read_at: i.keysReadAt };
}

/** Assemble a bundle from inputs already read. The mapping bytes are carried exactly. */
export function makeBundle({ domain, statement, manifest, keys, keysReadAt, keysSource, mappingUrl, mappingBytes, createdAt }) {
  return {
    bundle: VERIFICATION_BUNDLE_V1,
    created_at: createdAt ?? new Date().toISOString(),
    domain: domain ?? null,
    statement,
    manifest: Array.isArray(manifest) ? manifest : null,
    keys: { keys, list_read_at: keysReadAt ?? null, source: keysSource ?? null },
    mapping: mappingBytes === undefined ? null : { url: mappingUrl ?? null, digest: sha256Digest(mappingBytes), bytes_base64: Buffer.from(mappingBytes).toString('base64') },
  };
}
