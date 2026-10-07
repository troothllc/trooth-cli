// bin/lib/guard-decide.mjs - the guard's decision table (docs/GUARD.md
// section 5) as one pure function over abstract facts, kept apart from how
// the facts were gathered so it can be checked exhaustively
// (tests/guard-model.test.mjs, spec/GuardDecision.tla).
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// decideFrom(facts, policy) reads no clock, no network and no prose. The
// same facts and the same policy always give the same decision.
//
// facts:
//   now               epoch milliseconds the decision is made at
//   host              the host the action is about, or null
//   target            'ok' | 'none' | 'ambiguous' | 'non_record'
//                     (no host in the typed arguments; more than one; an IP
//                     literal, localhost or a single-label name)
//   source            'network' | 'cache' | 'unreachable'
//   record            a Trooth record exists for the host or a parent of it
//   subject           the Trooth id of the record checked, e.g. trooth:domain:acme.com
//   schema_supported  every signed artifact is a version this guard reads
//   signature         'valid' | 'invalid' | 'absent' (absent: no signed artifact)
//   key_status        'active' | 'retired_before_use' | 'retired_after_use' |
//                     'revoked' | 'compromised' | 'unknown' (the worst over the
//                     artifacts, at each one's signing time)
//   subject_match     every signed subject is the host or a parent domain of it
//   log               'included' | 'not_logged' | 'unavailable' | 'proof_invalid'
//   witnesses         pinned witnesses that cosigned a checkpoint covering every entry
//   claims            { <claim>: { observed_at, stale_after, disputed, fact_id,
//                       statement_sha256, log_index } } for each claim present
//   detail            optional strings carried into reasons

export const GUARD_DECISION_SCHEMA = 'https://trooth.co/schemas/guard-decision.v1.json';
export const REASON_CODES = ['RULE_PASSED', 'EVIDENCE_MISSING', 'EVIDENCE_STALE', 'EVIDENCE_DISPUTED', 'NO_RECORD', 'SIGNATURE_INVALID', 'KEY_NOT_TRUSTED', 'NOT_IN_LOG', 'SUBJECT_MISMATCH', 'SCHEMA_UNSUPPORTED', 'ABSOLUTE_RULE_FAILED', 'SOURCE_UNREACHABLE'];
export const KEY_STATUSES = ['active', 'retired_before_use', 'retired_after_use', 'revoked', 'compromised', 'unknown'];
export const TRUSTED = ['active', 'retired_before_use'];
const DAY = 86400000;
/** A clock difference tolerated before an observation counts as dated in the future. */
export const FUTURE_SKEW_MS = 5 * 60 * 1000;

const iso = (ms) => new Date(ms).toISOString();

/**
 * The state of one rule's evidence: 'present', 'missing', 'stale' or
 * 'disputed', with the effective stale-after time when the claim is there.
 */
export function claimState(rule, claim, now) {
  if (!claim) return { state: 'missing', limit: null };
  const observed = Date.parse(claim.observed_at);
  let limit = null;
  if (Number.isFinite(observed)) {
    if (rule.require.max_age_days) limit = observed + rule.require.max_age_days * DAY;
    else if (claim.stale_after && Number.isFinite(Date.parse(claim.stale_after))) limit = Date.parse(claim.stale_after);
  }
  if (claim.disputed) return { state: 'disputed', limit };
  if (!Number.isFinite(observed) || limit === null) return { state: 'stale', limit, why: 'no freshness window is known for it' };
  if (observed > now + FUTURE_SKEW_MS) return { state: 'stale', limit, why: 'it is dated in the future' };
  if (now > limit) return { state: 'stale', limit, why: `it was observed ${claim.observed_at} and stale after ${iso(limit)}` };
  return { state: 'present', limit };
}

function evidenceOf(claim, limit) {
  return { fact_id: claim.fact_id, statement_sha256: claim.statement_sha256, log_index: claim.log_index ?? null, observed_at: claim.observed_at, stale_after: limit === null ? (claim.stale_after ?? null) : iso(limit) };
}

/** The decision for these facts under this policy. Pure. */
export function decideFrom(facts, policy) {
  const f = facts;
  const d = f.detail || {};
  const reasons = [];
  const evidence = [];
  const finish = (decision) => {
    const out = {
      decision,
      reasons,
      subject: f.subject || '',
      policy: { id: policy.id, version: policy.version, sha256: policy.sha256 },
      evidence,
      decided_at: iso(f.now),
    };
    if (f.action) out.action = f.action;
    const errs = validateDecision(out);
    if (errs.length) throw new Error(`the guard produced a decision outside its schema: ${errs.join('; ')}`);
    return out;
  };
  const why = (code, detail, extra = {}) => { const r = { code, ...extra }; if (detail) r.detail = String(detail); reasons.push(r); };

  // 0. Which host. No typed argument names one: nothing to look up.
  if (f.target === 'none' || f.target === 'ambiguous' || (!f.host && f.target !== 'non_record')) {
    why('EVIDENCE_MISSING', f.target === 'ambiguous' ? 'the typed arguments name more than one host, or a host field holds a value the guard cannot read as one host' : 'no typed argument names the host this action is about', { needed: 'target_host' });
    return finish('hold');
  }
  // 1. No source reachable and nothing cached: never fail open.
  if (f.target !== 'non_record' && f.source === 'unreachable') {
    why('SOURCE_UNREACHABLE', d.source || 'no Trooth source answered and no cached bundle is held');
    return finish(policy.source_unreachable === 'deny' ? 'deny' : 'hold');
  }
  // 2. No record for the host or any parent.
  if (f.target === 'non_record' || !f.record) {
    why('NO_RECORD', f.target === 'non_record' ? 'an IP address, localhost or single-label name has no Trooth record' : (d.record || 'no Trooth record for the host or a parent domain of it'));
    return finish(policy.unknown_counterparty === 'deny' ? 'deny' : 'hold');
  }
  // 3. A version this guard does not read.
  if (!f.schema_supported) {
    why('SCHEMA_UNSUPPORTED', d.schema || 'a signed artifact is in a version this guard does not read');
    return finish('hold');
  }
  // 4. Failed proof: the signature, the key at signing time, the subject.
  if (f.signature === 'invalid') why('SIGNATURE_INVALID', d.signature);
  if (f.signature !== 'absent' && !TRUSTED.includes(f.key_status)) why('KEY_NOT_TRUSTED', d.key || `the signing key is ${f.key_status}`);
  if (!f.subject_match) why('SUBJECT_MISMATCH', d.subject || 'a signed subject is not the host or a parent domain of it');
  if (reasons.length) return finish('deny');
  // 5. The log.
  let held = false;
  if (f.signature !== 'absent') {
    if (f.log === 'proof_invalid') { why('NOT_IN_LOG', d.log || 'the log proof does not check'); return finish('deny'); }
    if (policy.log.required) {
      if (f.log !== 'included') { why('NOT_IN_LOG', d.log || (f.log === 'unavailable' ? 'the log could not be read' : 'the statement is not in the log')); held = true; }
      else if (f.witnesses < policy.log.min_witnesses) { why('NOT_IN_LOG', `${f.witnesses} pinned witness${f.witnesses === 1 ? '' : 'es'} cosigned a checkpoint covering the statement; the policy asks for ${policy.log.min_witnesses}`); held = true; }
    }
  }
  // 6. Each rule.
  let denied = false;
  for (const rule of policy.rules) {
    let failCode = null, failDetail = null, needed = null, factId;
    if (rule.require.claim) {
      const name = rule.require.claim;
      // A claim stands only on a valid signature: with none, every claim is missing.
      const claim = f.signature === 'valid' && f.claims ? f.claims[name] : undefined;
      const st = claimState(rule, claim, f.now);
      if (claim) { factId = claim.fact_id; evidence.push(evidenceOf(claim, st.limit)); }
      if (st.state === 'missing') { failCode = 'EVIDENCE_MISSING'; needed = name; failDetail = (d.claims && d.claims[name]) || `no signed, logged claim ${name}`; }
      else if (st.state === 'disputed') { failCode = 'EVIDENCE_DISPUTED'; failDetail = facts.claims?.[name]?.disputed_by === 'withheld' ? `the record is withheld while a report about it is reviewed, so ${name} is disputed` : `a correction Trooth signed and logged supersedes the statement that carries ${name}`; }
      else if (st.state === 'stale') { failCode = 'EVIDENCE_STALE'; failDetail = `${name}: ${st.why}`; }
    } else {
      if (f.signature !== 'valid') { failCode = 'EVIDENCE_MISSING'; needed = 'signature'; failDetail = 'no valid signature'; }
      else if (!rule.require.key_status.includes(f.key_status)) { failCode = 'KEY_NOT_TRUSTED'; failDetail = `the signing key is ${f.key_status}; the rule accepts ${rule.require.key_status.join(', ')}`; }
    }
    if (!failCode) {
      why('RULE_PASSED', null, factId ? { rule_id: rule.id, fact_id: factId } : { rule_id: rule.id });
      continue;
    }
    const extra = { rule_id: rule.id };
    if (factId) extra.fact_id = factId;
    if (needed) extra.needed = needed;
    if (rule.absolute) { why('ABSOLUTE_RULE_FAILED', `${failCode}: ${failDetail}`, extra); denied = true; }
    else { why(failCode, failDetail, extra); held = true; }
  }
  // 7. Any deny, else any hold, else allow.
  return finish(denied ? 'deny' : held ? 'hold' : 'allow');
}

/** Check a decision against schemas/guard-decision.v1.schema.json. Returns a list of problems. */
export function validateDecision(d) {
  const errs = [];
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(d)) return ['the decision is not an object'];
  for (const k of ['decision', 'reasons', 'subject', 'policy', 'evidence', 'decided_at']) if (!(k in d)) errs.push(`missing ${k}`);
  if (!['allow', 'hold', 'deny'].includes(d.decision)) errs.push('decision is not allow, hold or deny');
  if (!Array.isArray(d.reasons)) errs.push('reasons is not a list');
  else d.reasons.forEach((r, i) => {
    if (!isObj(r) || !REASON_CODES.includes(r.code)) errs.push(`reasons[${i}].code is not a known code`);
    for (const k of ['fact_id', 'rule_id', 'needed', 'detail']) if (r && k in r && typeof r[k] !== 'string') errs.push(`reasons[${i}].${k} is not a string`);
  });
  if (typeof d.subject !== 'string') errs.push('subject is not a string');
  if (!isObj(d.policy) || !['id', 'version', 'sha256'].every((k) => k in d.policy)) errs.push('policy lacks id, version or sha256');
  if (!Array.isArray(d.evidence)) errs.push('evidence is not a list');
  else d.evidence.forEach((e, i) => { if (!isObj(e) || !['fact_id', 'statement_sha256', 'log_index', 'observed_at', 'stale_after'].every((k) => k in e)) errs.push(`evidence[${i}] lacks a required field`); });
  if ('action' in d && !isObj(d.action)) errs.push('action is not an object');
  if (typeof d.decided_at !== 'string' || !Number.isFinite(Date.parse(d.decided_at))) errs.push('decided_at is not a date-time');
  if (Array.isArray(d.reasons) && d.decision === 'allow' && (!d.reasons.length || d.reasons.some((r) => r.code !== 'RULE_PASSED'))) errs.push('an allow carries a reason other than RULE_PASSED');
  return errs;
}
