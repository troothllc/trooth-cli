// bin/lib/guard-evidence.mjs - gathering and checking the evidence the guard
// decides on (docs/GUARD.md section 4): a cached bundle or the network, then
// every check done locally, reduced to the abstract facts guard-decide.mjs
// reads.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// What leaves the machine: requests to Trooth that carry only a domain (the
// host being checked, or a parent of it) or a statement id. The action, its
// arguments and the tool name are never sent. No URL found inside a record or
// a vendor's content is ever fetched; the one URL read from a signed payload
// is the check mapping, and only under {web}/standard/check-mapping/.

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { verifyStatement, verifyCorrection, bundleInputs, makeBundle, keyTrust, keyBytes, sha256Digest } from './verify.mjs';
import { checkReceipt, openCheckpoint, verifyConsistency, fromB64, toB64, LOG_ORIGIN } from './tlog.mjs';
import { checkCosignatures } from './witness.mjs';
import { canonicalizeRecord, isCanonical } from './jcs.mjs';
import { formatId, statementId } from './ids.mjs';
import { hostCandidates, isNonRecordHost, isDomainName, isHostOrParent, normalizeHost } from './guard-policy.mjs';

export const GUARD_BUNDLE_V1 = 'trooth.guard-bundle.v1';
export const PUBLIC_RECORD_FORMAT = 'trooth.public-record.v1';
export const PUBLIC_RECORD_STATEMENT = 'trooth.public-record.v1';
const PROJECTION_CONTRACT = 2;
const DAY = 86400000;

/** Default stale-after days when a record carries no evidence_classes (the scan worker's own values). */
export const CLASS_DEFAULT_DAYS = { regulator_filing: 90, registry_record: 365, sanctions_list: 7, procurement_exclusion: 7, domain_registration: 30, site_publication: 30 };
/** The freshness of a claim from a witness statement when the rule gives no max_age_days. */
export const READING_DEFAULT_DAYS = 30;

export const LIMITS = { projection: 2 * 1024 * 1024, small: 1024 * 1024, publicRecord: 4 * 1024 * 1024, checkpoint: 64 * 1024 };

class Unreachable extends Error {}

/* ------------------------------------------------------------- network ---- */

async function get(ctx, url, maxBytes, accept = 'application/json') {
  // Never past the decision's deadline (ctx.deadline, set per decision by guard.mjs).
  const left = Number.isFinite(ctx.deadline) ? ctx.deadline - Date.now() : Infinity;
  if (left <= 0) throw new Unreachable(`${new URL(url).host} was not asked: the decision deadline passed`);
  let res;
  try {
    res = await ctx.fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(Math.max(1, Math.min(ctx.timeoutMs, left))), headers: { accept, 'user-agent': ctx.userAgent } });
  } catch (e) {
    throw new Unreachable(`${new URL(url).host} could not be reached: ${e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? `no answer within ${ctx.timeoutMs} ms` : (e && e.message) || e}`);
  }
  const len = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(len) && len > maxBytes) { try { await res.body?.cancel(); } catch {} throw new Unreachable(`${url.split('?')[0]} is ${len} bytes, over the ${maxBytes}-byte limit`); }
  let buf;
  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      let step;
      try { step = await reader.read(); } catch (e) { throw new Unreachable(`${url.split('?')[0]} stopped answering: ${e && e.message}`); }
      if (step.done) break;
      total += step.value.byteLength;
      if (total > maxBytes) { try { await reader.cancel(); } catch {} throw new Unreachable(`${url.split('?')[0]} passed the ${maxBytes}-byte limit`); }
      chunks.push(Buffer.from(step.value));
    }
    buf = Buffer.concat(chunks);
  } else {
    buf = Buffer.from(typeof res.text === 'function' ? await res.text() : '', 'utf8');
    if (buf.length > maxBytes) throw new Unreachable(`${url.split('?')[0]} passed the ${maxBytes}-byte limit`);
  }
  return { status: res.status, contentType: String(res.headers?.get?.('content-type') || '').toLowerCase(), bytes: buf, text: buf.toString('utf8') };
}

function json(r, what) {
  if (!/\bjson\b/.test(r.contentType)) throw new Unreachable(`${what} answered HTTP ${r.status} with ${r.contentType || 'no content type'}, not JSON`);
  try { return JSON.parse(r.text); } catch { throw new Unreachable(`${what} answered with a body that is not JSON`); }
}

const sameHost = (a, b) => { const x = normalizeHost(String(a ?? '')); return !!x && x.replace(/^www\./, '') === b; };

/** The record projection for one domain: absent, found (with its witness statement), or Unreachable. */
async function readProjection(ctx, domain) {
  const r = await get(ctx, `${ctx.web}/api/network/profile?q=${encodeURIComponent(domain)}&contract=${PROJECTION_CONTRACT}`, LIMITS.projection);
  if (r.status < 200 || r.status > 299) throw new Unreachable(`the record projection answered HTTP ${r.status}`);
  const body = json(r, 'the record projection');
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Unreachable('the record projection answered with something that is not a record');
  if (body.found === false && body.ambiguous !== true) return { kind: 'absent' };
  if (body.found !== true) throw new Unreachable('the record projection did not say whether a record was found');
  return {
    kind: 'found',
    projection: {
      found: true,
      domain: typeof body.domain === 'string' ? body.domain : null,
      contract_version: body.withheld === true ? null : (Number.isInteger(body.contractVersion) ? body.contractVersion : null),
      withheld: body.withheld === true,
    },
    statement: body.withheld === true ? null : (body.witnessStatement && typeof body.witnessStatement === 'object' ? body.witnessStatement : null),
    manifest: Array.isArray(body.witnessEvidenceManifest) ? body.witnessEvidenceManifest : undefined,
  };
}

async function readLogFor(ctx, sid) {
  const base = `${ctx.api}/scan/log/v1`;
  const look = await get(ctx, `${base}/lookup?statement_id=${encodeURIComponent(sid)}`, LIMITS.small);
  let receipt = null;
  if (look.status === 200) receipt = json(look, 'the log').receipt ?? null;
  else if (look.status !== 404) throw new Unreachable(`the log answered HTTP ${look.status}`);
  let corrections = [];
  // Asked even for a statement the log does not hold: a correction can stand on its own.
  const c = await get(ctx, `${base}/corrections?statement_id=${encodeURIComponent(sid)}`, LIMITS.small);
  if (c.status === 200) corrections = json(c, "the log's corrections").corrections ?? [];
  else if (c.status !== 404) throw new Unreachable(`the log's corrections answered HTTP ${c.status}`);
  if (!Array.isArray(corrections)) corrections = [];
  return { receipt, corrections: corrections.slice(0, 64) };
}

/**
 * Read everything for one domain from the network into a guard bundle.
 * Returns { kind: 'absent' } or { kind: 'found', bundle }. Throws Unreachable.
 */
export async function fetchBundle(ctx, domain) {
  const proj = await readProjection(ctx, domain);
  if (proj.kind === 'absent') return { kind: 'absent' };
  const kr = await get(ctx, `${ctx.api}/public/keys`, LIMITS.small);
  if (kr.status !== 200) throw new Unreachable(`the key list answered HTTP ${kr.status}`);
  const kdoc = json(kr, 'the key list');
  if (!Array.isArray(kdoc.keys)) throw new Unreachable('the key list has no keys array');
  const keys = kdoc.keys;
  const keysReadAt = typeof kdoc.list_read_at === 'string' ? kdoc.list_read_at : new Date(ctx.now()).toISOString();
  const bundle = {
    bundle: GUARD_BUNDLE_V1,
    created_at: new Date(ctx.now()).toISOString(),
    domain,
    projection: proj.projection,
    keys: { keys, list_read_at: keysReadAt, source: `${ctx.api}/public/keys` },
    witness: null,
    witness_log_unavailable: null,
    public_record: null,
    public_record_corrections: [],
    public_record_unavailable: null,
    log: { checkpoint: null, consistency: {} },
  };
  const receipts = [];
  if (proj.statement && typeof proj.statement.payload === 'string') {
    let payload = null;
    try { payload = JSON.parse(proj.statement.payload); } catch {}
    let mappingBytes, mappingUrl = null;
    const mu = payload?.methodology?.mapping_url;
    if (typeof mu === 'string' && mu.startsWith(`${ctx.web}/standard/check-mapping/`) && /^[A-Za-z0-9._/-]+\.json$/.test(mu.slice(ctx.web.length + 1))) {
      try { const m = await get(ctx, mu, LIMITS.small, '*/*'); if (m.status === 200) { mappingBytes = m.bytes; mappingUrl = mu; } } catch {}
    }
    let log;
    try { log = await readLogFor(ctx, statementId(proj.statement.payload)); }
    catch (e) { bundle.witness_log_unavailable = e.message; }
    bundle.witness = makeBundle({ domain, statement: proj.statement, manifest: proj.manifest, keys, keysReadAt, keysSource: `${ctx.api}/public/keys`, mappingUrl, mappingBytes, createdAt: bundle.created_at, log: log ? { vkey: ctx.vkeys[0] ?? '', receipt: log.receipt, corrections: log.corrections } : undefined });
    if (log?.receipt) receipts.push(log.receipt);
  }
  try {
    const pr = await get(ctx, `${ctx.api}/scan/public-record/${encodeURIComponent(domain)}?cached=only`, LIMITS.publicRecord);
    if (pr.status === 200) {
      bundle.public_record = json(pr, 'the public record');
      const st = bundle.public_record?.signed?.statement;
      if (st && typeof st.payload === 'string') {
        try { bundle.public_record_corrections = (await readLogFor(ctx, statementId(st.payload))).corrections; }
        catch (e) { bundle.public_record_corrections_unavailable = e.message; }
      }
      if (bundle.public_record?.signed?.log) receipts.push(bundle.public_record.signed.log);
    } else if (pr.status !== 404) bundle.public_record_unavailable = `the public record answered HTTP ${pr.status}`;
  } catch (e) { bundle.public_record_unavailable = e.message; }
  if (receipts.length) {
    try {
      const cp = await get(ctx, `${ctx.api}/scan/log/v1/checkpoint`, LIMITS.checkpoint, 'text/plain');
      if (cp.status === 200) {
        bundle.log.checkpoint = cp.text;
        const size = Number(/^[^\n]*\n(\d{1,19})\n/.exec(cp.text)?.[1]);
        for (const r of receipts) {
          if (!Number.isSafeInteger(r?.tree_size) || !Number.isSafeInteger(size) || size <= r.tree_size) continue;
          const key = `${r.tree_size}-${size}`;
          if (bundle.log.consistency[key]) continue;
          const p = await get(ctx, `${ctx.api}/scan/log/v1/proof/consistency?first=${r.tree_size}&second=${size}`, LIMITS.small);
          if (p.status === 200) { const proof = json(p, 'the consistency proof').consistency_proof; if (Array.isArray(proof)) bundle.log.consistency[key] = proof.slice(0, 64); }
        }
      }
    } catch { /* the cosignature count then comes from the receipt alone */ }
  }
  return { kind: 'found', bundle };
}

/* --------------------------------------------------------------- cache ---- */

export function cachePath(dir, domain) {
  if (!isDomainName(domain)) throw new Error(`not a domain: ${domain}`);
  return join(dir, `${domain}.trooth-guard.json`);
}

export function readCached(dir, domain) {
  const p = cachePath(dir, domain);
  if (!existsSync(p)) return null;
  try {
    const b = JSON.parse(readFileSync(p, 'utf8'));
    if (!b || b.bundle !== GUARD_BUNDLE_V1 || typeof b.created_at !== 'string') return null;
    return b;
  } catch { return null; }
}

export function writeCached(dir, bundle) {
  mkdirSync(dir, { recursive: true });
  const p = cachePath(dir, bundle.domain);
  const tmp = `${p}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(bundle, null, 2) + '\n', { mode: 0o644 });
  renameSync(tmp, p);
  return p;
}

/* ------------------------------------------------------ local checking ---- */

function ed25519Valid(published, sigField, payload) {
  const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(sigField ?? ''));
  if (!m || !published) return false;
  try {
    const pk = keyBytes(published);
    if (pk.length !== 32) return false;
    return edVerify(null, Buffer.from(payload, 'utf8'), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pk.toString('base64url') }, format: 'jwk' }), Buffer.from(m[1], 'base64'));
  } catch { return false; }
}

function keyStatusOf(kt) {
  if (kt.state === 'active') return 'active';
  if (kt.state === 'retired') return kt.trusted ? 'retired_before_use' : 'retired_after_use';
  if (kt.state === 'compromised') return 'compromised';
  if (kt.state === 'revoked_unrecorded') return 'revoked';
  return 'unknown';
}
const KEY_ORDER = ['active', 'retired_before_use', 'retired_after_use', 'unknown', 'revoked', 'compromised'];
const LOG_ORDER = ['included', 'not_logged', 'unavailable', 'proof_invalid'];
const worst = (order, a, b) => (order.indexOf(a) >= order.indexOf(b) ? a : b);

/** Pinned witnesses that cosigned a checkpoint shown to cover this receipt's tree. */
export function cosignersFor(receipt, logPart, vkeys, witnesses, now) {
  const counted = new Set();
  const add = (note) => { try { for (const c of checkCosignatures(note, witnesses, now)) if (c.valid) counted.add(c.name); } catch {} };
  if (typeof receipt?.checkpoint === 'string') add(receipt.checkpoint);
  const note = logPart?.checkpoint;
  if (typeof note === 'string') {
    let cp = null;
    for (const k of vkeys) { try { cp = openCheckpoint(note, k); break; } catch {} }
    const rRoot = fromB64(receipt?.root_hash);
    if (cp && rRoot && Number.isSafeInteger(receipt.tree_size)) {
      if (cp.size === BigInt(receipt.tree_size)) { if (cp.root.equals(rRoot)) add(note); }
      else if (cp.size > BigInt(receipt.tree_size)) {
        const proof = (logPart.consistency?.[`${receipt.tree_size}-${cp.size}`] || []).map(fromB64);
        if (proof.length && !proof.some((p) => !p) && verifyConsistency(receipt.tree_size, Number(cp.size), rRoot, cp.root, proof)) add(note);
      }
    }
  }
  return counted.size;
}

function iso(ms) { return new Date(ms).toISOString(); }
/** A value from a served document, reduced to characters that cannot carry an instruction, for a detail line. */
const safe = (v) => String(v ?? '').replace(/[^A-Za-z0-9._:/@+#-]/g, '?').slice(0, 96);
const prose = (v) => String(v ?? '').replace(/[^A-Za-z0-9 ._:/@+#,()-]/g, '?').slice(0, 160);
function plusDays(at, days) { const t = Date.parse(at); return Number.isFinite(t) ? iso(t + days * DAY) : null; }

/**
 * Check one guard bundle for `domain` (the record's subject, the host or a
 * parent of it) and reduce it to the facts guard-decide.mjs reads. Pure but
 * for the clock passed in.
 */
export function factsFromBundle(bundle, { domain, host, vkeys, witnesses, now }) {
  const detail = {};
  const facts = {
    now, host, target: 'ok', source: 'network', record: true, subject: formatId('domain', domain),
    schema_supported: true, signature: 'absent', key_status: 'active', subject_match: true,
    log: 'included', witnesses: Infinity, claims: {}, detail,
  };
  const note = (k, s) => { if (!detail[k]) detail[k] = s; };
  const claimsDetail = {};
  detail.claims = claimsDetail;
  const keys = Array.isArray(bundle?.keys?.keys) ? bundle.keys.keys : [];
  if (bundle.domain !== domain) { facts.subject_match = false; note('subject', `the bundle names ${safe(bundle.domain)}, not ${domain}`); }
  if (!isHostOrParent(domain, host)) { facts.subject_match = false; note('subject', `${domain} is not ${host} or a parent domain of it`); }
  const pj = bundle.projection || {};
  if (pj.withheld) note('record', 'the record is withheld while a report about it is reviewed');
  else if (pj.contract_version !== PROJECTION_CONTRACT) { facts.schema_supported = false; note('schema', `the record projection is contract ${safe(pj.contract_version)}; this guard reads contract ${PROJECTION_CONTRACT}`); }
  if (pj.domain !== null && pj.domain !== undefined && !sameHost(pj.domain, domain)) { facts.subject_match = false; note('subject', `the record served for ${domain} is the record for ${safe(pj.domain)}`); }

  const artifacts = [];
  const setSig = (s, why) => { if (s === 'invalid') { facts.signature = 'invalid'; note('signature', why); } else if (facts.signature === 'absent') facts.signature = 'valid'; };
  const setKey = (k, why) => { facts.key_status = worst(KEY_ORDER, facts.key_status, k); if (k !== 'active' && k !== 'retired_before_use') note('key', why); };
  const setLog = (l, why) => { const w = worst(LOG_ORDER, facts.log, l); facts.log = w; if (l !== 'included') note('log', why); };

  /* --- the witness statement --- */
  if (bundle.witness) {
    let i = null;
    try { i = bundleInputs(bundle.witness); } catch (e) { setSig('invalid', `the saved witness statement cannot be read: ${e.message}`); }
    if (i) {
      let payload = null;
      try { payload = JSON.parse(i.statement.payload); } catch {}
      const ver = payload?.statement;
      if (typeof ver === 'string' && ver.startsWith('trooth.witness-statement.') && !['trooth.witness-statement.v1', 'trooth.witness-statement.v2', 'trooth.witness-statement.v3'].includes(ver)) {
        facts.schema_supported = false; note('schema', `the witness statement is ${safe(ver)}; this guard reads v1, v2 and v3`);
      } else {
        const log = bundle.witness_log_unavailable ? { unavailable: bundle.witness_log_unavailable } : { vkeys, receipt: i.log?.receipt ?? null, corrections: i.log?.corrections ?? [] };
        const r = verifyStatement({ statement: i.statement, keys, mappingBytes: i.mappingBytes, manifest: i.manifest, domain, log });
        const ks = keyStatusOf(r.key);
        setKey(ks, `witness statement: ${prose(r.key.reason)}`);
        if (r.signature !== 'valid') setSig('invalid', r.signature === 'malformed' ? 'the witness statement is malformed (not the canonical bytes, or the signer inside differs)' : (keys.some((k) => k?.kid === i.statement.key_id) ? 'the witness statement signature does not check' : `the witness statement names key ${safe(i.statement.key_id)}, which is not on the key list`));
        else if (r.trusted) {
          if (r.counts.problems.length) setSig('invalid', `the signed counts disagree with the signed checks (${r.counts.problems.length} problem${r.counts.problems.length === 1 ? '' : 's'})`);
          else if (r.binding.status === 'mismatch') setSig('invalid', `the ${r.binding.mapping === 'mismatch' ? 'check mapping' : 'evidence manifest'} is not the one the statement signed`);
          else setSig('valid');
          if (r.subject.status === 'mismatch') { facts.subject_match = false; note('subject', `the witness statement was signed for ${safe(r.subject.signed)}, not ${domain}`); }
          const ls = !r.log ? 'not_logged' : r.log.status === 'checkpoint_invalid' ? 'proof_invalid' : r.log.status;
          setLog(ls, `witness statement: ${prose(r.log?.reason || 'not in the log')}`);
          const sha = r.statement_id.slice('trooth:statement:'.length);
          const idx = ls === 'included' ? r.log.index : null;
          if (ls === 'included') facts.witnesses = Math.min(facts.witnesses, cosignersFor(i.log.receipt, bundle.log, vkeys, witnesses, now));
          const disputed = !!r.log?.superseded_by;
          // With the log unreadable, a correction that supersedes the statement cannot be
          // ruled out, whatever log.required says: its claims are not there to stand on.
          const unknownCorrections = ls === 'unavailable';
          const at = r.read_at;
          const add = (name) => { if (unknownCorrections) { claimsDetail[name] = 'the log could not be asked whether a correction supersedes the witness statement'; return; } facts.claims[name] = { fact_id: `${r.statement_id}#${name}`, statement_sha256: sha, log_index: idx, observed_at: at, stale_after: plusDays(at, READING_DEFAULT_DAYS), disputed }; };
          add('trooth_reading');
          for (const c of Array.isArray(payload?.checks) ? payload.checks : []) {
            if (c && typeof c.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(c.id)) {
              if (c.outcome === 'as expected') add(`check:${c.id}`);
              else claimsDetail[`check:${c.id}`] = `check ${c.id} was "${prose(c.outcome)}" in the signed reading`;
            }
          }
          artifacts.push('witness_statement');
        } else setSig('valid');
      }
    }
  } else {
    claimsDetail.trooth_reading = pj.withheld ? 'the record is withheld' : 'the record carries no signed witness statement';
  }

  /* --- the public record statement --- */
  const d = bundle.public_record;
  const prMissing = (why) => { for (const c of ['legal_entity_registry_record', 'no_sanctions_name_match', 'no_sam_exclusion_name_match', 'domain_registration_record', 'security_txt_published']) claimsDetail[c] = claimsDetail[c] || why; };
  if (!d) prMissing(bundle.public_record_unavailable ? `the public record could not be read: ${bundle.public_record_unavailable}` : `no cached public record reading of ${domain}`);
  else if (d.format !== PUBLIC_RECORD_FORMAT) {
    if (typeof d.format === 'string' && d.format.startsWith('trooth.public-record.')) { facts.schema_supported = false; note('schema', `the public record is ${safe(d.format)}; this guard reads ${PUBLIC_RECORD_FORMAT}`); }
    else prMissing('the public record answer is not a public record reading');
  } else {
    if (d.domain !== domain) { facts.subject_match = false; note('subject', `the public record served for ${domain} is a reading of ${safe(d.domain)}`); }
    const s = d.signed;
    if (!s || typeof s !== 'object' || !s.statement) prMissing('the public record reading is not signed');
    else {
      const st = s.statement;
      const { signed, ...record } = d;
      void signed;
      let sha = null;
      try { sha = createHash('sha256').update(canonicalizeRecord(record), 'utf8').digest('hex'); } catch {}
      let p = null;
      try { p = JSON.parse(String(st.payload)); } catch {}
      const ver = p?.statement;
      if (typeof ver === 'string' && ver.startsWith('trooth.public-record.') && ver !== PUBLIC_RECORD_STATEMENT) { facts.schema_supported = false; note('schema', `the public record statement is ${safe(ver)}; this guard reads ${PUBLIC_RECORD_STATEMENT}`); }
      else if (!sha || sha !== s.record_sha256) setSig('invalid', 'the public record is not the one its statement names: its RFC 8785 SHA-256 differs');
      else if (!p || ver !== PUBLIC_RECORD_STATEMENT || st.alg !== 'Ed25519' || st.canonicalization !== 'RFC8785' || typeof st.payload !== 'string' || !isCanonical(st.payload)) setSig('invalid', 'the public record statement is not RFC 8785 bytes signed with Ed25519');
      else if (p.signer?.key_id !== st.key_id || p.signer?.issuer !== 'trooth.co') setSig('invalid', 'the signer inside the public record statement is not the envelope key');
      else if (p.record_sha256 !== sha || p.read_at !== d.read_at || p.subject_id !== d.subject_id) setSig('invalid', 'the public record statement names another reading');
      else {
        if (p.domain !== domain || p.subject_id !== `trooth:domain:${domain}`) { facts.subject_match = false; note('subject', `the public record statement was signed for ${safe(p.domain)}, not ${domain}`); }
        const published = keys.find((k) => k && k.kid === st.key_id);
        const kt = keyTrust(st.key_id, keys, typeof p.issued_at === 'string' ? p.issued_at : null);
        setKey(keyStatusOf(kt), `public record statement: ${prose(kt.reason)}`);
        if (!ed25519Valid(published, st.signature, st.payload)) setSig('invalid', published ? 'the public record statement signature does not check' : `the public record statement names key ${safe(st.key_id)}, which is not on the key list`);
        else {
          setSig('valid');
          const sid = statementId(st.payload);
          let ls = 'not_logged', idx = null, why = 'the public record statement is not in the log';
          if (s.log) {
            const rc = checkReceipt({ kind: 'public_record', statement: st, receipt: s.log, vkeys });
            ls = rc.status === 'included' ? 'included' : 'proof_invalid';
            why = `public record statement: ${prose(rc.reason)}`;
            if (ls === 'included') { idx = rc.index; facts.witnesses = Math.min(facts.witnesses, cosignersFor(s.log, bundle.log, vkeys, witnesses, now)); }
          }
          setLog(ls, why);
          // A correction that could not be read cannot be ruled out.
          if (bundle.public_record_corrections_unavailable) setLog('unavailable', 'the log could not be asked whether a correction supersedes the public record statement');
          let disputed = false;
          for (const c of Array.isArray(bundle.public_record_corrections) ? bundle.public_record_corrections : []) {
            const v = verifyCorrection({ correction: c?.statement, receipt: c?.receipt, keys, vkeys, statementIdValue: sid });
            if (v.valid) disputed = true;
          }
          const shaHex = sid.slice('trooth:statement:'.length);
          const classes = Array.isArray(d.evidence_classes) ? d.evidence_classes : [];
          const cls = (name, own) => {
            const c = classes.find((x) => x && x.class === name);
            if (c && c.read && typeof c.observed_at === 'string') return { observed_at: c.observed_at, stale_after: typeof c.stale_after === 'string' ? c.stale_after : plusDays(c.observed_at, c.stale_after_days ?? CLASS_DEFAULT_DAYS[name]) };
            const at = typeof own === 'string' && Date.parse(own) < Date.parse(d.read_at) ? own : d.read_at;
            return { observed_at: at, stale_after: plusDays(at, CLASS_DEFAULT_DAYS[name]) };
          };
          const add = (name, t) => { if (bundle.public_record_corrections_unavailable) { claimsDetail[name] = 'the log could not be asked whether a correction supersedes the public record statement'; return; } facts.claims[name] = { fact_id: `${sid}#${name}`, statement_sha256: shaHex, log_index: idx, observed_at: t.observed_at, stale_after: t.stale_after, disputed }; };
          if (d.entity && typeof d.entity === 'object') {
            const reg = classes.find((x) => x?.class === 'registry_record' && x.read);
            add('legal_entity_registry_record', cls(reg || !classes.find((x) => x?.class === 'regulator_filing' && x.read) ? 'registry_record' : 'regulator_filing'));
          } else claimsDetail.legal_entity_registry_record = 'the signed public record names no corroborated legal entity for the domain';
          if (d.sanctions && Array.isArray(d.sanctions.matches)) {
            if (d.sanctions.matches.length === 0) add('no_sanctions_name_match', cls('sanctions_list', d.sanctions.read_at));
            else claimsDetail.no_sanctions_name_match = `the sanctions list has ${d.sanctions.matches.length} entr${d.sanctions.matches.length === 1 ? 'y' : 'ies'} with the same name (a name match is not an identification)`;
          } else claimsDetail.no_sanctions_name_match = 'the sanctions list was not read in the signed public record';
          if (d.sam && Array.isArray(d.sam.exclusions)) {
            if (d.sam.exclusions.length === 0) add('no_sam_exclusion_name_match', cls('procurement_exclusion', d.sam.read_at));
            else claimsDetail.no_sam_exclusion_name_match = `SAM.gov lists ${d.sam.exclusions.length} exclusion record${d.sam.exclusions.length === 1 ? '' : 's'} with the same name (a name match is not an identification)`;
          } else claimsDetail.no_sam_exclusion_name_match = 'SAM.gov was not read in the signed public record';
          if (d.domain_registration && typeof d.domain_registration === 'object') add('domain_registration_record', cls('domain_registration'));
          else claimsDetail.domain_registration_record = 'the signed public record holds no domain registration';
          const txt = d.security_txt;
          if (txt && typeof txt === 'object' && txt.expired !== true && !(typeof txt.expires === 'string' && Date.parse(txt.expires) <= now)) add('security_txt_published', cls('site_publication'));
          else claimsDetail.security_txt_published = txt ? 'the security.txt in the signed public record is expired' : 'the signed public record holds no security.txt';
          artifacts.push('public_record');
        }
      }
    }
  }
  // A record withheld while a report about it is reviewed: whatever its signed
  // public record says, every claim is disputed until the review closes.
  if (pj.withheld) for (const c of Object.values(facts.claims)) { c.disputed = true; c.disputed_by = 'withheld'; }
  claimsDetail.domain_control_confirmed = 'domain control is not in any signed Trooth artifact today';
  if (facts.signature === 'absent') { facts.log = 'not_logged'; facts.witnesses = 0; }
  if (!Number.isFinite(facts.witnesses)) facts.witnesses = 0;
  return facts;
}

/* ------------------------------------------------------------ gathering ---- */

/**
 * Gather the facts for a host: the exact host, then its parents down to two
 * labels; for each, a fresh cached bundle, then (unless offline) the network.
 */
export async function gatherFacts(ctx, host) {
  const now = ctx.now();
  const base = { now, host, target: 'ok', source: 'network', record: false, subject: '', schema_supported: true, signature: 'absent', key_status: 'unknown', subject_match: true, log: 'not_logged', witnesses: 0, claims: {}, detail: {} };
  if (isNonRecordHost(host)) return { ...base, target: 'non_record', subject: '' };
  base.subject = formatId('domain', host);
  const candidates = hostCandidates(host);
  if (!candidates.length) return { ...base, detail: { record: `${host} is under a shared domain where a record cannot stand for it` } };
  const seenCached = [];
  for (const domain of candidates) {
    let bundle = null, source = null;
    if (ctx.cache?.dir) {
      const b = readCached(ctx.cache.dir, domain);
      if (b) {
        const age = now - Date.parse(b.created_at);
        if (ctx.offline || (Number.isFinite(age) && age >= -60000 && age <= ctx.cache.maxAgeSeconds * 1000)) { bundle = b; source = 'cache'; }
        else seenCached.push(domain);
      }
    }
    if (!bundle) {
      if (ctx.offline) continue;
      let got;
      try { got = await fetchBundle(ctx, domain); }
      catch (e) {
        if (e instanceof Unreachable) return { ...base, source: 'unreachable', detail: { source: `${e.message}; no fresh cached bundle for ${domain}` } };
        throw e;
      }
      if (got.kind === 'absent') continue;
      bundle = got.bundle;
      source = 'network';
      if (ctx.cache?.dir) { try { writeCached(ctx.cache.dir, bundle); } catch { /* a cache that cannot be written is not fatal */ } }
    }
    const facts = factsFromBundle(bundle, { domain, host, vkeys: ctx.vkeys, witnesses: ctx.witnesses, now });
    return { ...facts, source };
  }
  if (ctx.offline) return { ...base, source: 'unreachable', detail: { source: `offline, and no cached bundle for ${candidates.join(', ')}` } };
  return { ...base, detail: { record: `no Trooth record for ${candidates.join(', ')}` } };
}

export { Unreachable, sha256Digest, toB64, LOG_ORIGIN };
