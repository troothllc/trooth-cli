// bin/lib/guard/errors.mjs - the errors the guard adapters throw, and the
// helpers they share. Copyright 2026 Trooth, LLC. Licensed under the Apache
// License, Version 2.0.
//
// A GuardHold or GuardDeny carries the Decision that caused it (`.decision`),
// so the caller can show the reason codes and route a hold to a person. The
// guard answers allow, hold or deny about an action under the customer's
// policy; it never labels a company.

const DECISIONS = new Set(['allow', 'hold', 'deny']);

/** The reason codes of a Decision, in order. */
export function reasonCodes(decision) {
  return Array.isArray(decision?.reasons) ? decision.reasons.map((r) => r?.code).filter(Boolean) : [];
}

/** One plain sentence for a Decision, for a log line, an error message or the model. */
export function describeDecision(decision) {
  const d = decision?.decision ?? 'hold';
  const a = decision?.action && typeof decision.action === 'object' ? decision.action : {};
  const host = a.host ?? (typeof decision?.subject === 'string' && decision.subject ? decision.subject : null);
  const what = [a.tool ? `the call to ${a.tool}` : 'this action', host ? `for ${host}` : ''].filter(Boolean).join(' ');
  const pol = decision?.policy?.id ? ` under policy ${decision.policy.id}${decision.policy.version != null ? ` version ${decision.policy.version}` : ''}` : '';
  const codes = reasonCodes(decision);
  const why = codes.length ? ` Reasons: ${codes.join(', ')}.` : '';
  if (d === 'allow') return `Trooth guard: allow ${what}${pol}.${why}`;
  if (d === 'deny') return `Trooth guard: deny ${what}${pol}. The call was stopped.${why}`;
  return `Trooth guard: hold ${what}${pol}. A person must approve it before it runs.${why}`;
}

export class GuardError extends Error {
  constructor(decision, message) {
    super(message ?? describeDecision(decision));
    this.name = 'GuardError';
    /** The Decision that caused this error. */
    this.decision = decision;
    /** The reason codes of that Decision. */
    this.reasons = reasonCodes(decision);
  }
}

/** The policy needs a person to approve the action before it runs. */
export class GuardHold extends GuardError {
  constructor(decision, message) {
    super(decision, message);
    this.name = 'GuardHold';
    this.code = 'TROOTH_GUARD_HOLD';
  }
}

/** The policy stops the action. */
export class GuardDeny extends GuardError {
  constructor(decision, message) {
    super(decision, message);
    this.name = 'GuardDeny';
    this.code = 'TROOTH_GUARD_DENY';
  }
}

/**
 * The Decision behind an error a framework threw, or null. Frameworks wrap
 * what a tool hook throws: LangChain JS createAgent wraps GuardDeny in
 * MiddlewareError (the original in .cause), and @openai/agents wraps the tool
 * input tripwire in ToolCallError (the original in .error, the Decision in
 * .result.output.outputInfo.decision). This walks .cause and .error.
 */
export function guardDecisionOf(err) {
  for (let e = err, i = 0; e && typeof e === 'object' && i < 8; e = e.cause ?? e.error, i++) {
    // By code as well as by class, so a second copy of this module (a bundler, two installs) still matches.
    if ((e instanceof GuardError || e.code === 'TROOTH_GUARD_HOLD' || e.code === 'TROOTH_GUARD_DENY') && DECISIONS.has(e.decision?.decision)) return e.decision;
    const d = e.result?.output?.outputInfo?.decision;
    if (d && typeof d === 'object' && DECISIONS.has(d.decision)) return d;
  }
  return null;
}

/** The error for a hold or deny Decision; null for allow. */
export function errorFor(decision) {
  if (decision?.decision === 'deny') return new GuardDeny(decision);
  if (decision?.decision === 'allow') return null;
  return new GuardHold(decision);
}

function policyRef(guard) {
  const p = guard?.policy;
  if (!p || typeof p !== 'object') return { id: null, version: null, sha256: null };
  return { id: p.id ?? p.policy ?? null, version: p.version ?? null, sha256: p.sha256 ?? null };
}

/**
 * A hold Decision with SOURCE_UNREACHABLE, made locally when the guard itself
 * failed or answered with something that is not a Decision. An adapter never
 * turns a failure into allow.
 */
export function failClosedDecision(guard, input, detail) {
  return {
    decision: 'hold',
    reasons: [{ code: 'SOURCE_UNREACHABLE', detail: `the guard gave no decision: ${String(detail).slice(0, 300)}` }],
    subject: input?.host ?? '',
    policy: policyRef(guard),
    evidence: [],
    action: { tool: input?.tool ?? null, host: input?.host ?? null },
    decided_at: new Date().toISOString(),
  };
}

function checked(guard, input, d) {
  if (d === null) return null;
  if (!d || typeof d !== 'object' || !DECISIONS.has(d.decision)) return failClosedDecision(guard, input, 'the answer was not a Decision');
  return d;
}

/** guard.decideToolCall, failing closed. Null when the policy does not cover the tool. */
export async function decideToolCallSafely(guard, toolCall) {
  const input = { tool: toolCall?.name ?? null, host: null };
  try {
    if (typeof guard?.applies === 'function' && !guard.applies(toolCall.name)) return null;
    try { input.host = guard.targetHost?.(toolCall) ?? null; } catch { /* the decision reports it */ }
    return checked(guard, input, await guard.decideToolCall(toolCall));
  } catch (e) {
    return failClosedDecision(guard, input, e?.message ?? e);
  }
}

/** guard.decide, failing closed. */
export async function decideSafely(guard, input) {
  try {
    return checked(guard, input, await guard.decide(input)) ?? failClosedDecision(guard, input, 'the answer was null');
  } catch (e) {
    return failClosedDecision(guard, input, e?.message ?? e);
  }
}

/** Arguments as an object: a JSON string is parsed; anything unparsable is kept as given. */
export function parseArgs(args) {
  if (typeof args !== 'string') return args ?? {};
  try { return JSON.parse(args); } catch { return args; }
}

/**
 * Whether a resume value approves a held action. Accepted: true, 'approve',
 * { type: 'approve' }, { approved: true }, and the LangChain HITL form
 * { decisions: [{ type: 'approve' }, ...] } when every decision approves.
 */
export function isApproval(resume) {
  if (resume === true || resume === 'approve') return true;
  if (!resume || typeof resume !== 'object') return false;
  if (resume.type === 'approve' || resume.approved === true) return true;
  if (Array.isArray(resume.decisions) && resume.decisions.length) return resume.decisions.every((d) => d?.type === 'approve');
  return false;
}
