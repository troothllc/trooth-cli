// bin/lib/guard.mjs - trooth/guard: the pre-execution guardrail (docs/GUARD.md).
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// The guard runs inside the customer's agent. Before a consequential tool
// call it finds the host the call is about (from typed arguments only),
// reads Trooth's signed, logged artifacts for that host (a cached bundle or
// the network), checks every signature, key, log proof and cosignature on
// this machine, and applies the customer's written policy. It answers allow,
// hold or deny about the ACTION under the CUSTOMER's policy, with reason
// codes. It never labels a company, and it never grants a permission the
// agent's own controls do not already give.
//
// Only a domain (or a statement id) is ever sent to Trooth. The action and its
// arguments stay on this machine. This module prints nothing and never exits
// the process. It imports only node: built-ins and this package's modules.

import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { PINNED_LOG_VKEYS, PINNED_WITNESSES } from './log-trust.mjs';
import { parseVkey } from './tlog.mjs';
import { parseCosignerVkey } from './witness.mjs';
import { parsePolicy as parsePolicyText, PolicyError, toolCovered, targetHosts, normalizeHost, normalizePolicy, hostOfValue, asText } from './guard-policy.mjs';
import { decideFrom, validateDecision, GUARD_DECISION_SCHEMA, REASON_CODES } from './guard-decide.mjs';
import { gatherFacts, fetchBundle, writeCached, readCached, factsFromBundle, Unreachable } from './guard-evidence.mjs';

export { PolicyError, GUARD_DECISION_SCHEMA, REASON_CODES, decideFrom, validateDecision, normalizePolicy };

let VERSION = '0.0.0';
try { VERSION = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version; } catch {}

/** Parse a policy (YAML subset or JSON). Throws PolicyError. */
export function parsePolicy(text, format) {
  return parsePolicyText(text, format);
}

/** Read and parse a policy file; the format follows the extension (.json, else YAML). Throws PolicyError. */
export async function loadPolicy(path) {
  let text;
  try { text = await readFile(path, 'utf8'); }
  catch (e) { throw new PolicyError(`the policy file could not be read: ${path} (${e && e.code ? e.code : e})`); }
  return parsePolicyText(text, /\.json$/i.test(String(path)) ? 'json' : 'yaml');
}

/**
 * Make a guard. Throws PolicyError for a policy that is not a parsed policy
 * and Error for options it refuses (failMode 'allow', a malformed key).
 */
export function createGuard(opts = {}) {
  const { policy } = opts;
  if (!policy || typeof policy !== 'object' || typeof policy.sha256 !== 'string' || !Array.isArray(policy.rules)) throw new PolicyError('createGuard needs a policy from parsePolicy or loadPolicy.');
  const failMode = opts.failMode ?? 'hold';
  if (failMode === 'allow') throw new Error("failMode 'allow' is refused: the guard never fails open on a consequential action.");
  if (failMode !== 'hold' && failMode !== 'deny') throw new Error(`failMode must be 'hold' or 'deny', not ${JSON.stringify(failMode)}.`);
  const vkeys = opts.vkeys ?? PINNED_LOG_VKEYS;
  if (!Array.isArray(vkeys) || !vkeys.length) throw new Error('createGuard needs at least one log verifier key (vkeys); none is pinned in this release.');
  for (const k of vkeys) parseVkey(k);
  const witnesses = (opts.witnesses ?? PINNED_WITNESSES).map((w) => (typeof w === 'string' ? { vkey: w } : w));
  for (const w of witnesses) parseCosignerVkey(w.vkey);
  const fetchFn = opts.fetch ?? globalThis.fetch;
  if (typeof fetchFn !== 'function' && !opts.offline) throw new Error('no fetch is available; pass opts.fetch or use offline mode.');
  const now = opts.now ?? (() => Date.now());
  const cache = opts.cache && opts.cache.dir ? { dir: String(opts.cache.dir), maxAgeSeconds: Number.isFinite(opts.cache.maxAgeSeconds) ? Math.max(0, opts.cache.maxAgeSeconds) : 900 } : null;
  const offline = !!opts.offline;
  if (offline && !cache) throw new Error('offline mode reads only cached bundles; pass cache: { dir }.');
  const strip = (u, d) => String(u ?? d).replace(/\/+$/, '');
  const ctx = {
    fetch: fetchFn, now, cache, offline, vkeys, witnesses,
    api: strip(opts.api, 'https://api.trooth.co'),
    web: strip(opts.web, 'https://trooth.co'),
    timeoutMs: Number.isFinite(opts.timeoutMs) ? Math.max(100, opts.timeoutMs) : 10000,
    // One deadline for a whole decision. Each request has its own timeoutMs, but a
    // decision may make many in a row (each parent domain, the log, the checkpoint),
    // and a caller that gives up first (a Claude Code hook timeout) lets the tool run.
    deadlineMs: Number.isFinite(opts.deadlineMs) ? Math.max(100, opts.deadlineMs) : 30000,
    userAgent: `trooth-guard/${VERSION}`,
  };
  // A guard's failMode can only make the policy stricter, never looser.
  const effective = failMode === 'deny' && policy.source_unreachable !== 'deny' ? Object.freeze({ ...policy, source_unreachable: 'deny' }) : policy;

  function applies(toolName) { return toolCovered(policy, toolName); }

  function targetHost(toolCall) {
    const t = targetHosts(policy, toolCall);
    return t.hosts.length === 1 && !t.ambiguous ? t.hosts[0] : null;
  }

  const actionOf = (tool, host, args, fields) => {
    let a = args;
    if (typeof a === 'string') { try { a = JSON.parse(a); } catch { a = undefined; } }
    const names = a && typeof a === 'object' && !Array.isArray(a) ? Object.keys(a).slice(0, 64) : [];
    const out = { tool: asText(tool), host: host ?? null, argument_names: names, stored: 'local only; never sent to Trooth' };
    if (fields) out.host_fields = fields;
    return out;
  };

  async function decideInternal(tool, host, args, target, fields) {
    const n = now();
    const action = actionOf(tool, host, args, fields);
    if (target !== 'ok') {
      return decideFrom({ now: n, host: null, target, source: 'network', record: false, subject: '', claims: {}, detail: {}, action }, effective);
    }
    let facts;
    let timer;
    try {
      const run = { ...ctx, deadline: Date.now() + ctx.deadlineMs };
      const late = new Promise((_, reject) => { timer = setTimeout(() => reject(new Unreachable(`no decision within the ${ctx.deadlineMs} ms deadline`)), ctx.deadlineMs); });
      facts = await Promise.race([gatherFacts(run, host), late]);
    } catch (e) {
      // Anything the guard did not plan for: fail toward hold (or deny), never open.
      facts = { now: n, host, target: 'ok', source: 'unreachable', record: false, subject: '', claims: {}, detail: { source: `the guard could not complete its checks: ${e && e.message ? e.message : e}` } };
      return decideFrom({ ...facts, action }, failMode === 'deny' ? Object.freeze({ ...effective, source_unreachable: 'deny' }) : effective);
    } finally { clearTimeout(timer); }
    return decideFrom({ ...facts, action }, effective);
  }

  /** Decide for a tool and a host the caller already extracted. host null means none was found: hold. */
  async function decide(input = {}) {
    const raw = input.host;
    if (raw === null || raw === undefined || raw === '') return decideInternal(input.tool, null, input.args, 'none');
    const host = hostOfValue(asText(raw)) ?? normalizeHost(asText(raw));
    if (!host) return decideInternal(input.tool, asText(raw), input.args, 'non_record');
    return decideInternal(input.tool, host, input.args, 'ok');
  }

  /** Decide for a framework tool call; null when the policy does not cover the tool. */
  async function decideToolCall(toolCall) {
    const name = toolCall?.name;
    if (!applies(name)) return null;
    const t = targetHosts(policy, toolCall);
    if (t.hosts.length !== 1 || t.ambiguous) return decideInternal(name, null, toolCall?.arguments, t.ambiguous ? 'ambiguous' : 'none', t.fields);
    return decideInternal(name, t.hosts[0], toolCall?.arguments, 'ok', t.fields);
  }

  /** Read one domain's signed bundle from the network and save it in the cache (trooth guard cache). */
  async function saveBundle(domain) {
    if (!cache) throw new Error('saveBundle needs cache: { dir }.');
    if (offline) throw new Error('saveBundle reads the network; the guard is offline.');
    const d = normalizeHost(String(domain));
    let got;
    try { got = await fetchBundle(ctx, d); }
    catch (e) { if (e instanceof Unreachable) return { domain: d, saved: false, reason: e.message }; throw e; }
    if (got.kind === 'absent') return { domain: d, saved: false, reason: `no Trooth record for ${d}` };
    const path = writeCached(cache.dir, got.bundle);
    const facts = factsFromBundle(got.bundle, { domain: d, host: d, vkeys, witnesses, now: now() });
    return { domain: d, saved: true, path, witness_statement: !!got.bundle.witness, public_record: !!got.bundle.public_record, signature: facts.signature, key_status: facts.key_status, log: facts.log, witnesses: facts.witnesses };
  }

  return Object.freeze({ policy, applies, targetHost, decide, decideToolCall, saveBundle, readCached: (d) => (cache ? readCached(cache.dir, d) : null) });
}
