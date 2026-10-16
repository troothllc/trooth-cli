// bin/lib/evidence.mjs - the offline check of the two objects Trooth signs for
// action authorization: delegation receipts and action evidence references.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// Both are Ed25519 compact JWS signed by Trooth's evidence key (kid
// trooth-evidence-2026-10), which https://api.trooth.co/public/keys publishes
// with purpose "signed-references". docs/ACTION-EVIDENCE.md describes both
// objects and every rule this file applies. The header and claims match
// trooth-os-worker-f src/action-authz.ts (signEvidence, delegationReceiptPayload,
// issueInner, verifyEvidence, verifyDelegationReceipt).
//
// It imports only node:crypto and the key-trust rules of ./verify.mjs, so it
// can be copied, audited and re-implemented. It sends nothing: the caller
// supplies the key list.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { keyTrust, keyBytes } from './verify.mjs';

export const EVIDENCE_FORMAT = 'trooth.action-evidence.v1';
export const EVIDENCE_TYP = 'trooth-action-evidence+jwt';
export const DELEGATION_RECEIPT_FORMAT = 'trooth.delegation-receipt.v1';
export const DELEGATION_RECEIPT_TYP = 'trooth-delegation-receipt+jwt';
export const DELEGATION_FORMAT = 'trooth.delegation.v1';
/** The kid Trooth's evidence key carries on /public/keys. */
export const EVIDENCE_KEY_KID = 'trooth-evidence-2026-10';
/** The purpose /public/keys states for the key that signs both objects. */
export const SIGNED_REFERENCES_PURPOSE = 'signed-references';
export const ISSUER = 'https://api.trooth.co';
export const KEYS_URL = 'https://api.trooth.co/public/keys';
export const STATUS_URL_PREFIX = 'https://api.trooth.co/public/action-evidence/';
/** Where the public witness log serves entry N. */
export const LOG_ENTRY_URL_PREFIX = 'https://api.trooth.co/scan/log/v1/entries/';
/** The commitment the witness log holds for each receipt and reference (never the object itself). */
export const LOG_COMMITMENT_FORMAT = 'trooth.log-commitment.v1';
export const LOG_COMMITMENT_TYP = 'trooth-log-commitment+jwt';
/** The log's entry kind for each object, by the object's typ. */
export const LOG_KIND_OF_TYP = { 'trooth-action-evidence+jwt': 'action_evidence', 'trooth-delegation-receipt+jwt': 'delegation_receipt' };
/** An evidence reference lives ten minutes (EVIDENCE_TTL_S in the Worker). */
export const EVIDENCE_TTL_S = 600;
/** How far ahead of this machine's clock an iat may be before it is refused. */
export const CLOCK_SKEW_S = 60;
/** The largest compact JWS accepted (a reference is a few kilobytes). */
export const MAX_JWS_BYTES = 256 * 1024;
/** The states GET /public/action-evidence/<jti> answers with. */
export const PUBLIC_STATES = ['issued', 'redeemed', 'expired', 'revoked'];

const B64URL = /^[A-Za-z0-9_-]+$/;
const HEX64 = /^[0-9a-f]{64}$/;

/** Input that is not a compact JWS, or JSON that holds none. */
export class EvidenceInputError extends Error {}

/** The canonical JSON the Worker signs and digests: sorted keys, no spaces, undefined members dropped. */
export function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
}

const sha256Hex = (s) => createHash('sha256').update(Buffer.from(String(s), 'utf8')).digest('hex');

/** The reference_sha256 an evidence reference carries for a mandate: SHA-256 of `${protocol}\n${reference}`. */
export function bindingReferenceSha(protocol, reference) {
  return sha256Hex(`${protocol}\n${reference}`);
}

/**
 * The digest a delegation receipt names (delegation.sha256): SHA-256 of the
 * canonical JSON of the delegation document. Takes the `delegation` object of
 * the create response, or an entry of GET /v1/delegations (its digest,
 * revoked_at and receipts members are not part of the document and are left out).
 */
export function delegationDigest(delegation) {
  if (!delegation || typeof delegation !== 'object' || Array.isArray(delegation)) throw new EvidenceInputError('the delegation document is not an object');
  const { digest, revoked_at, receipts, ...doc } = delegation; // eslint-disable-line no-unused-vars
  return sha256Hex(canonicalJson(doc));
}

/** True when `s` has the shape of a compact JWS: three base64url segments. */
export function looksLikeJws(s) {
  const parts = String(s).split('.');
  return parts.length === 3 && parts.every((p) => B64URL.test(p));
}

/**
 * The compact JWS in what a user saved: the JWS itself, or the JSON the Worker
 * answers with. For 'evidence': `evidence` (POST /v1/action-authorizations,
 * GET /v1/action-authorizations/<id>, GET /public/action-evidence/<jti>/reference)
 * or `jws`. For 'delegation': `receipt` (POST /v1/delegations, POST
 * /v1/delegations/<id>/revoke), `jws`, or the one receipt in a GET
 * /v1/delegations answer; the delegation document beside it is returned too.
 */
export function extractJws(text, kind) {
  const s = String(text ?? '').trim();
  if (!s) throw new EvidenceInputError('the input is empty');
  if (Buffer.byteLength(s, 'utf8') > MAX_JWS_BYTES * 4) throw new EvidenceInputError(`the input is over ${MAX_JWS_BYTES * 4} bytes`);
  if (s[0] !== '{' && s[0] !== '[') {
    const compact = s.replace(/\s+/g, '');
    if (!looksLikeJws(compact)) throw new EvidenceInputError('not a compact JWS (three base64url segments separated by dots) and not JSON');
    return { jws: compact, delegation: null, log: null };
  }
  let doc;
  try { doc = JSON.parse(s); } catch { throw new EvidenceInputError('the input starts like JSON but does not parse'); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new EvidenceInputError('the JSON is not an object');
  const field = kind === 'delegation' ? 'receipt' : 'evidence';
  const other = kind === 'delegation' ? 'evidence' : 'receipt';
  let jws = typeof doc[field] === 'string' ? doc[field] : typeof doc.jws === 'string' ? doc.jws : null;
  let delegation = kind === 'delegation' && doc.delegation && typeof doc.delegation === 'object' && !Array.isArray(doc.delegation) ? doc.delegation : null;
  // Where the API says the object sits in the witness log: `log` (an
  // authorization, a receipt in a list), `receipt_log` (POST /v1/delegations
  // and its revoke). null while the append is pending.
  let log = logPlaceOf(kind === 'delegation' ? (doc.receipt_log !== undefined ? doc.receipt_log : doc.log) : doc.log);
  if (!jws && kind === 'delegation' && Array.isArray(doc.delegations)) {
    const found = [];
    for (const d of doc.delegations) for (const r of (d && Array.isArray(d.receipts) ? d.receipts : [])) if (r && typeof r.receipt === 'string') found.push({ jws: r.receipt, delegation: d, log: logPlaceOf(r.log) });
    if (found.length !== 1) throw new EvidenceInputError(`the JSON lists ${found.length} delegation receipts; save the one to check by itself`);
    ({ jws, delegation, log } = found[0]);
  }
  if (!jws && kind === 'delegation' && Array.isArray(doc.receipts)) {
    const found = doc.receipts.filter((r) => r && typeof r.receipt === 'string');
    if (found.length !== 1) throw new EvidenceInputError(`the JSON lists ${found.length} delegation receipts; save the one to check by itself`);
    jws = found[0].receipt; delegation = doc; log = logPlaceOf(found[0].log);
  }
  if (!jws) {
    const hint = typeof doc[other] === 'string' ? ` It holds \`${other}\`: run trooth ${kind === 'delegation' ? 'evidence' : 'delegation'} verify on it.` : '';
    throw new EvidenceInputError(`the JSON holds no \`${field}\` or \`jws\` string.${hint}`);
  }
  jws = jws.trim();
  if (!looksLikeJws(jws)) throw new EvidenceInputError(`its \`${field}\` is not a compact JWS`);
  return { jws, delegation, log };
}

/** A `log` member as the API writes it, { statement_id, index, url }, or null. */
function logPlaceOf(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const index = Number.isSafeInteger(v.index) && v.index >= 0 ? v.index : null;
  return { statement_id: typeof v.statement_id === 'string' ? v.statement_id : null, index, url: typeof v.url === 'string' ? v.url : null };
}

/** Decode a compact JWS without checking it. Throws EvidenceInputError when it is not one. */
export function decodeJws(jws) {
  const s = String(jws ?? '');
  if (Buffer.byteLength(s, 'utf8') > MAX_JWS_BYTES) throw new EvidenceInputError(`the JWS is over ${MAX_JWS_BYTES} bytes`);
  const parts = s.split('.');
  if (parts.length !== 3 || !parts.every((p) => B64URL.test(p))) throw new EvidenceInputError('not a compact JWS');
  const json = (p, what) => {
    let v;
    try { v = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')); } catch { throw new EvidenceInputError(`the JWS ${what} is not base64url JSON`); }
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new EvidenceInputError(`the JWS ${what} is not a JSON object`);
    return v;
  };
  return { header: json(parts[0], 'header'), payload: json(parts[1], 'payload'), signingInput: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
}

function ed25519Valid(publicKey32, signature64, message) {
  if (publicKey32.length !== 32 || signature64.length !== 64) return false;
  try {
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey32.toString('base64url') }, format: 'jwk' });
    return edVerify(null, Buffer.from(message, 'utf8'), key, signature64);
  } catch {
    return false;
  }
}

const keyListOf = (keys) => (Array.isArray(keys) ? keys : keys && Array.isArray(keys.keys) ? keys.keys : null);
const isoOfSeconds = (s) => (Number.isInteger(s) ? new Date(s * 1000).toISOString() : null);
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const str = (v) => (typeof v === 'string' ? v : null);

/**
 * The checks both objects share: decode, alg, kid on the list with purpose
 * signed-references and trusted at iat, the Ed25519 signature over the JWS
 * signing input, then typ, format, iss and the kid the payload names. Returns
 * the partial result; `status` is null when everything so far holds.
 */
function checkCommon(kind, jws, keys, typ, format) {
  const res = {
    kind, status: null, reason: null, problems: [], signature: 'not_checked',
    kid: null, key: null, header: null, payload: null, sha256: null, issued_at: null, expires_at: null, summary: null,
  };
  const notTrusted = (why) => { res.status = 'not_trusted'; res.reason = why; res.problems.push(why); return res; };
  res.sha256 = sha256Hex(String(jws ?? ''));
  let d;
  try { d = decodeJws(jws); } catch (e) { return notTrusted(`malformed: ${e.message}`); }
  res.header = d.header; res.payload = d.payload;
  res.issued_at = isoOfSeconds(d.payload.iat);
  res.kid = str(d.header.kid);
  if (d.header.alg !== 'EdDSA') return notTrusted(`the header's alg is ${JSON.stringify(d.header.alg)}, not EdDSA`);
  if (!res.kid) return notTrusted('the header names no kid');
  const why = keyAndSignature(res, d, keys);
  if (why) return notTrusted(why);
  const p = d.payload;
  if (d.header.typ !== typ) {
    const hint = d.header.typ === EVIDENCE_TYP ? ' (an action evidence reference: trooth evidence verify)' : d.header.typ === DELEGATION_RECEIPT_TYP ? ' (a delegation receipt: trooth delegation verify)' : '';
    res.problems.push(`the header's typ is ${JSON.stringify(d.header.typ ?? null)}, not ${typ}${hint}`);
  }
  if (p.format !== format) res.problems.push(`format is ${JSON.stringify(p.format ?? null)}, not ${format}`);
  if (p.iss !== ISSUER) res.problems.push(`iss is ${JSON.stringify(p.iss ?? null)}, not ${ISSUER}`);
  if (!Number.isInteger(p.iat)) res.problems.push('iat is not a whole number of seconds');
  if (!isObj(p.verify) || p.verify.kid !== res.kid) res.problems.push(`verify.kid does not name the kid in the header (${res.kid})`);
  return res;
}

/**
 * The kid on the key list with purpose signed-references, trusted at
 * res.issued_at, and the Ed25519 signature over the signing input. Sets
 * res.key and res.signature; returns why it is not trusted, or null.
 */
function keyAndSignature(res, d, keys) {
  const list = keyListOf(keys);
  if (!list) return 'no key list: expected {keys: [...]} as https://api.trooth.co/public/keys answers, or an array of keys';
  const k = list.find((x) => x && x.kid === res.kid) || null;
  if (!k) { res.key = { state: 'unknown', purpose: null, trusted: false, reason: 'The key id is not on the key list, so it is not a Trooth key.' }; return `kid ${res.kid} is not on the key list`; }
  const t = keyTrust(res.kid, list, res.issued_at);
  res.key = { state: t.state, purpose: str(k.purpose), trusted: t.trusted, reason: t.reason };
  if (k.purpose !== SIGNED_REFERENCES_PURPOSE) return `kid ${res.kid} is published with purpose ${JSON.stringify(k.purpose ?? null)}, not ${SIGNED_REFERENCES_PURPOSE}`;
  if (!t.trusted) return `kid ${res.kid} is not trusted: ${t.reason}`;
  if (!ed25519Valid(keyBytes(k), d.signature, d.signingInput)) { res.signature = 'invalid'; return 'the Ed25519 signature does not verify over the JWS signing input'; }
  res.signature = 'valid';
  return null;
}

function finish(res, now) {
  if (res.status) return res;
  if (res.problems.length) { res.status = 'mismatch'; res.reason = res.problems[0]; return res; }
  if (res.kind === 'action-evidence' && Number.isInteger(res.payload.exp) && res.payload.exp * 1000 <= now) {
    res.status = 'expired'; res.reason = `expired at ${res.expires_at}`;
    return res;
  }
  res.status = 'valid';
  return res;
}

function delegationScope(d) {
  if (!isObj(d)) return null;
  return {
    role: str(d.role),
    limit: isObj(d.limit) ? { amount: str(d.limit.amount), currency: str(d.limit.currency) } : null,
    data_class: str(d.data_class),
    approval_above: str(d.approval_above),
  };
}

/**
 * Check an action evidence reference against a key list (the JSON of
 * https://api.trooth.co/public/keys, or its keys array).
 *
 * status: 'valid' (everything holds and it has not expired), 'expired' (it
 * holds, and exp has passed: a state, not an error), 'not_trusted' (malformed,
 * alg not EdDSA, kid not on the list or not purpose signed-references, key not
 * trusted, or the signature does not verify), 'mismatch' (the signature
 * verifies, but typ, format, iss, the claims, the lifetime or the binding do
 * not hold). Never throws on bad input.
 */
export function verifyEvidence(jws, keys, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const res = checkCommon('action-evidence', jws, keys, EVIDENCE_TYP, EVIDENCE_FORMAT);
  res.jti = null; res.state_url = null;
  if (res.status) return res;
  const p = res.payload;
  res.expires_at = isoOfSeconds(p.exp);
  if (typeof p.jti === 'string' && /^ev_[0-9a-f]{32}$/.test(p.jti)) { res.jti = p.jti; res.state_url = `${STATUS_URL_PREFIX}${p.jti}`; }
  else res.problems.push('jti is not ev_ and 32 hex characters');
  if (!Number.isInteger(p.exp)) res.problems.push('exp is not a whole number of seconds');
  else if (Number.isInteger(p.iat) && (p.exp <= p.iat || p.exp - p.iat > EVIDENCE_TTL_S)) res.problems.push(`its lifetime is ${p.exp - p.iat} s; a reference lives at most ${EVIDENCE_TTL_S} s`);
  if (Number.isInteger(p.iat) && p.iat * 1000 > now + CLOCK_SKEW_S * 1000) res.problems.push(`iat ${res.issued_at} is in the future by this machine's clock`);
  const ad = Array.isArray(p.authorization_details) && p.authorization_details.length === 1 && isObj(p.authorization_details[0]) ? p.authorization_details[0] : null;
  if (!ad) res.problems.push('authorization_details is not one object');
  else if (ad.type !== 'trooth_payment' && ad.type !== 'trooth_data_share') res.problems.push(`authorization_details[0].type ${JSON.stringify(ad.type)} is not trooth_payment or trooth_data_share`);
  const dl = isObj(p.delegation) ? p.delegation : null;
  if (!dl || typeof dl.id !== 'string') res.problems.push('delegation.id is missing');
  if (!isObj(p.binding) || typeof p.binding.protocol !== 'string' || !HEX64.test(String(p.binding.reference_sha256))) res.problems.push('binding is not {protocol, reference_sha256}');
  if (!isObj(p.responsibility) || typeof p.responsibility.version !== 'string') res.problems.push('responsibility.version is missing');
  if (!isObj(p.counterparty) || !isObj(p.counterparty.reading)) res.problems.push('counterparty.reading is missing');
  if (!isObj(p.approval) || !isObj(p.approval.delegation)) res.problems.push('approval.delegation is missing');
  if (dl && isObj(dl.target) && isObj(p.counterparty) && p.counterparty.domain !== dl.target.domain) res.problems.push('counterparty.domain is not the delegation\'s target domain');

  let bindingChecked = null;
  if (opts.binding && (opts.binding.protocol !== undefined || opts.binding.reference !== undefined)) {
    const want = bindingReferenceSha(String(opts.binding.protocol ?? ''), String(opts.binding.reference ?? ''));
    bindingChecked = isObj(p.binding) && p.binding.protocol === opts.binding.protocol && p.binding.reference_sha256 === want;
    if (!bindingChecked) res.problems.push(`it is not bound to this mandate: binding is ${isObj(p.binding) ? `${p.binding.protocol} ${p.binding.reference_sha256}` : 'missing'}, the mandate given hashes to ${opts.binding.protocol} ${want}`);
  }
  const reading = isObj(p.counterparty) && isObj(p.counterparty.reading) ? p.counterparty.reading : {};
  const pay = ad && ad.type === 'trooth_payment';
  res.summary = {
    jti: res.jti,
    authorization_id: str(p.authorization_id),
    action: ad ? str(ad.type) : null,
    verb: ad && Array.isArray(ad.actions) ? str(ad.actions[0]) : null,
    amount: pay && isObj(ad.instructedAmount) ? str(ad.instructedAmount.amount) : null,
    currency: pay && isObj(ad.instructedAmount) ? str(ad.instructedAmount.currency) : null,
    data_class: ad && !pay && Array.isArray(ad.datatypes) ? str(ad.datatypes[0]) : null,
    creditor_name: ad ? str(ad.creditorName) : null,
    description: ad ? str(ad.description) : null,
    locations: ad && Array.isArray(ad.locations) ? ad.locations.filter((x) => typeof x === 'string') : [],
    target_domain: dl && isObj(dl.target) ? str(dl.target.domain) : null,
    principal: isObj(p.principal) ? { workspace: str(p.principal.workspace), user: str(p.principal.user) } : null,
    delegation: dl ? {
      id: str(dl.id), sha256: str(dl.sha256), agent_jkt: isObj(dl.agent) ? str(dl.agent.jkt) : null,
      actions: Array.isArray(dl.actions) ? dl.actions.filter((x) => typeof x === 'string') : [],
      expires_at: str(dl.expires_at), ...delegationScope(dl),
    } : null,
    approval: {
      delegation: isObj(p.approval) && isObj(p.approval.delegation) ? approvalOf(p.approval.delegation) : null,
      action: isObj(p.approval) && isObj(p.approval.action) ? approvalOf(p.approval.action) : null,
    },
    binding: isObj(p.binding) ? { protocol: str(p.binding.protocol), reference_sha256: str(p.binding.reference_sha256), matches_mandate: bindingChecked } : null,
    boundary_version: isObj(p.responsibility) ? str(p.responsibility.version) : null,
    counterparty: {
      domain: isObj(p.counterparty) ? str(p.counterparty.domain) : null,
      status: str(reading.status),
      read_at: str(reading.read_at),
      log_index: Number.isInteger(reading.log_index) ? reading.log_index : null,
      statement_sha256: str(reading.statement_sha256),
      source: str(reading.source),
    },
    issued_at: res.issued_at,
    expires_at: res.expires_at,
  };
  return finish(res, now);
}

function approvalOf(a) {
  return { approved_by: str(a.approved_by), approved_at: str(a.approved_at), method: str(a.method), acr: str(a.acr), idp: isObj(a.idp) ? { provider: str(a.idp.provider), domain: str(a.idp.domain) } : null };
}

/**
 * Check a delegation receipt against a key list. opts.delegation, when given,
 * is the delegation document (the create response's `delegation`, or an entry
 * of GET /v1/delegations): its digest must be the one the receipt names, and
 * then its limit, data class, approval threshold and role are reported as the
 * scope. A receipt does not expire; whether the delegation it names has
 * expired is reported in summary.delegation_expired.
 *
 * status: 'valid', 'not_trusted' or 'mismatch', as for verifyEvidence.
 */
export function verifyDelegationReceipt(jws, keys, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const res = checkCommon('delegation-receipt', jws, keys, DELEGATION_RECEIPT_TYP, DELEGATION_RECEIPT_FORMAT);
  if (res.status) return res;
  const p = res.payload;
  if (p.event !== 'created' && p.event !== 'revoked') res.problems.push(`event ${JSON.stringify(p.event ?? null)} is not created or revoked`);
  const recorded = typeof p.recorded_at === 'string' ? Date.parse(p.recorded_at) : NaN;
  if (!Number.isFinite(recorded)) res.problems.push('recorded_at is not a time');
  else if (Number.isInteger(p.iat) && Math.floor(recorded / 1000) !== p.iat) res.problems.push('recorded_at is not the time iat names');
  const dl = isObj(p.delegation) ? p.delegation : null;
  if (!dl || typeof dl.id !== 'string') res.problems.push('delegation.id is missing');
  else {
    if (!HEX64.test(String(dl.sha256))) res.problems.push('delegation.sha256 is not 64 hex characters');
    if (dl.format !== DELEGATION_FORMAT) res.problems.push(`delegation.format is not ${DELEGATION_FORMAT}`);
  }
  let scope = null, scopeSource = 'not supplied';
  if (opts.delegation) {
    let digest = null;
    try { digest = delegationDigest(opts.delegation); } catch (e) { res.problems.push(e.message); }
    if (digest !== null) {
      if (dl && digest === dl.sha256 && opts.delegation.id === dl.id) { scope = delegationScope(opts.delegation); scopeSource = 'delegation document, digest matches'; }
      else { res.problems.push(`the delegation document supplied hashes to ${digest}, not the ${dl ? dl.sha256 : 'missing'} the receipt names`); scopeSource = 'delegation document, digest does not match'; }
    }
  }
  const exp = dl && typeof dl.expires_at === 'string' ? Date.parse(dl.expires_at) : NaN;
  res.summary = {
    event: str(p.event),
    delegation_id: dl ? str(dl.id) : null,
    delegation_sha256: dl ? str(dl.sha256) : null,
    agent_jkt: dl && isObj(dl.agent) ? str(dl.agent.jkt) : null,
    actions: dl && Array.isArray(dl.actions) ? dl.actions.filter((x) => typeof x === 'string') : [],
    target_domain: dl && isObj(dl.target) ? str(dl.target.domain) : null,
    principal: dl && isObj(dl.principal) ? { workspace: str(dl.principal.workspace), user: str(dl.principal.user) } : null,
    expires_at: dl ? str(dl.expires_at) : null,
    delegation_expired: Number.isFinite(exp) ? exp <= now : null,
    recorded_at: str(p.recorded_at),
    by: str(p.by),
    approval: isObj(p.approval) ? approvalOf(p.approval) : null,
    scope_source: scopeSource,
    scope,
    meaning: str(p.meaning),
  };
  return finish(res, now);
}

/* ------------------------------------------------------ witness log ---- */

/**
 * The commitment JWS in a witness log entry, as GET
 * https://api.trooth.co/scan/log/v1/entries/<n> answers: its envelope's
 * payload. Takes the parsed JSON (or the text). Throws EvidenceInputError
 * when the entry is not a delegation_receipt or action_evidence entry
 * holding a compact JWS.
 */
export function commitmentFromLogEntry(entry) {
  let e = entry;
  if (typeof e === 'string') { try { e = JSON.parse(e); } catch { throw new EvidenceInputError('the log entry is not JSON'); } }
  if (!isObj(e)) throw new EvidenceInputError('the log entry is not a JSON object');
  const kind = str(e.kind) ?? (isObj(e.entry) ? str(e.entry.kind) : null);
  if (kind !== 'delegation_receipt' && kind !== 'action_evidence') throw new EvidenceInputError(`the log entry is a ${JSON.stringify(kind)} entry, not a delegation_receipt or action_evidence commitment`);
  const st = isObj(e.entry) && isObj(e.entry.statement) ? e.entry.statement : null;
  const payload = st ? str(st.payload) : null;
  if (!payload || !looksLikeJws(payload)) throw new EvidenceInputError('the log entry\'s envelope payload is not a compact JWS commitment');
  return { kind, jws: payload, index: Number.isSafeInteger(e.index) ? e.index : null, statement_id: str(e.statement_id), logged_at: str(e.logged_at) };
}

/**
 * Check a witness log commitment against the receipt or reference it should
 * commit to. The commitment is the compact JWS the log holds (the payload of
 * the entry's envelope; commitmentFromLogEntry); originalJws is the compact
 * JWS the holder has, exactly as held; keys is the JSON of
 * https://api.trooth.co/public/keys (or its keys array).
 *
 * The commitment's alg must be EdDSA, its kid on the list with purpose
 * signed-references and trusted at its iat, its Ed25519 signature valid, its
 * typ trooth-log-commitment+jwt, its payload exactly {format, kind, sha256,
 * iat} with format trooth.log-commitment.v1, kind the original's
 * (action_evidence for a trooth-action-evidence+jwt, delegation_receipt for a
 * trooth-delegation-receipt+jwt; opts.kind overrides) and sha256 the
 * lowercase hex SHA-256 of originalJws's UTF-8 bytes.
 *
 * status: 'valid', 'not_trusted' (malformed, alg, kid, key or signature) or
 * 'mismatch' (it verifies, but typ, format, kind, the keys or the digest do
 * not hold). Never throws on bad input.
 */
export function verifyLogCommitment(commitmentJws, originalJws, keys, opts = {}) {
  const res = {
    kind: null, status: null, reason: null, problems: [], signature: 'not_checked', kid: null, key: null,
    header: null, payload: null, committed_sha256: null, expected_sha256: sha256Hex(String(originalJws ?? '')), committed_at: null, issued_at: null,
  };
  const notTrusted = (why) => { res.status = 'not_trusted'; res.reason = why; res.problems.push(why); return res; };
  let want = typeof opts.kind === 'string' ? opts.kind : null;
  if (!want) {
    try { want = LOG_KIND_OF_TYP[decodeJws(originalJws).header.typ] ?? null; } catch { want = null; }
  }
  res.kind = want;
  let d;
  try { d = decodeJws(commitmentJws); } catch (e) { return notTrusted(`the commitment is malformed: ${e.message}`); }
  res.header = d.header; res.payload = d.payload;
  res.issued_at = isoOfSeconds(d.payload.iat); res.committed_at = res.issued_at;
  res.kid = str(d.header.kid);
  if (d.header.alg !== 'EdDSA') return notTrusted(`the commitment's alg is ${JSON.stringify(d.header.alg)}, not EdDSA`);
  if (!res.kid) return notTrusted('the commitment names no kid');
  const why = keyAndSignature(res, d, keys);
  if (why) return notTrusted(`the commitment: ${why}`);
  const p = d.payload;
  if (d.header.typ !== LOG_COMMITMENT_TYP) res.problems.push(`the commitment's typ is ${JSON.stringify(d.header.typ ?? null)}, not ${LOG_COMMITMENT_TYP}`);
  const keysSeen = Object.keys(p).sort().join(',');
  if (keysSeen !== 'format,iat,kind,sha256') res.problems.push(`the commitment payload has ${keysSeen || 'no keys'}, not exactly format, kind, sha256 and iat`);
  if (p.format !== LOG_COMMITMENT_FORMAT) res.problems.push(`the commitment format is ${JSON.stringify(p.format ?? null)}, not ${LOG_COMMITMENT_FORMAT}`);
  if (!want) res.problems.push('the original is not a delegation receipt or an action evidence reference, so the kind cannot be checked');
  else if (p.kind !== want) res.problems.push(`the commitment kind is ${JSON.stringify(p.kind ?? null)}, not ${want}`);
  if (!Number.isInteger(p.iat)) res.problems.push('the commitment iat is not a whole number of seconds');
  res.committed_sha256 = typeof p.sha256 === 'string' ? p.sha256 : null;
  if (typeof p.sha256 !== 'string' || !HEX64.test(p.sha256)) res.problems.push('the commitment sha256 is not 64 lowercase hex characters');
  else if (p.sha256 !== res.expected_sha256) res.problems.push(`the commitment is to sha256 ${p.sha256}, not ${res.expected_sha256}, the SHA-256 of the JWS checked`);
  if (res.problems.length) { res.status = 'mismatch'; res.reason = res.problems[0]; return res; }
  res.status = 'valid';
  return res;
}
