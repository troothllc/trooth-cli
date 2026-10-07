// common.mjs - shared harness for the Trooth-run guard pilots (JavaScript).
// Builds guards against the live Trooth API and against the local fixture
// server, times every decision, and records each observed step. The guard is
// imported from this repository (bin/lib), not from npm.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { loadPolicy, createGuard } from '../../bin/lib/guard.mjs';

const here = new URL('..', import.meta.url);
export const POLICIES = new URL('policies/', here);
export const LOGS = new URL('logs/', here);

export function fixtureInfo() {
  return JSON.parse(readFileSync(new URL('fixture-info.json', LOGS), 'utf8'));
}

const timings = [];
const steps = [];

/** Wrap a guard so every decide/decideToolCall is timed and logged. */
export function timed(guard, source) {
  const wrap = (fn, kind) => async (...a) => {
    const t0 = performance.now();
    let d;
    try { d = await fn(...a); } finally {
      const ms = performance.now() - t0;
      if (d !== null) timings.push({ source, kind, ms: Math.round(ms * 10) / 10, decision: d?.decision ?? 'error', host: d?.action?.host ?? null, codes: (d?.reasons ?? []).map((r) => r.code) });
    }
    return d;
  };
  // The guard object is frozen, so wrap it in a plain object with the same members.
  const out = {};
  for (const k of Object.keys(guard)) out[k] = typeof guard[k] === 'function' ? guard[k].bind(guard) : guard[k];
  out.decide = wrap(guard.decide.bind(guard), 'decide');
  out.decideToolCall = wrap(guard.decideToolCall.bind(guard), 'decideToolCall');
  return Object.freeze(out);
}

export async function liveGuard(policyFile) {
  const policy = await loadPolicy(new URL(policyFile, POLICIES).pathname);
  return timed(createGuard({ policy }), 'live');
}

export async function fixtureGuard(policyFile, world = 'main') {
  const info = fixtureInfo();
  const policy = await loadPolicy(new URL(policyFile, POLICIES).pathname);
  return timed(createGuard({ policy, api: info.worlds[world].api, web: info.worlds[world].web, vkeys: [info.vkey], witnesses: info.witnesses }), `fixture:${world}`);
}

/** Record a step: what ran, what was expected, what was observed. */
export function step(pilot, name, { expected, observed, pass, detail }) {
  steps.push({ pilot, name, expected, observed, pass: !!pass, detail: detail ?? null });
  console.log(`${pass ? 'PASS' : 'FAIL'}  [${pilot}] ${name}: expected ${expected}; observed ${observed}${detail ? ` (${detail})` : ''}`);
}

export function codesOf(d) {
  return (d?.reasons ?? []).filter((r) => r.code !== 'RULE_PASSED').map((r) => r.code);
}

/** Write steps and timings for this pilot to logs/<name>.json. */
export const GUARD_VERSION = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;

export function save(name, extra = {}) {
  mkdirSync(LOGS, { recursive: true });
  writeFileSync(new URL(`${name}.json`, LOGS), JSON.stringify({ name, ran_at: new Date().toISOString(), node: process.version, trooth: GUARD_VERSION, steps, timings, ...extra }, null, 2));
  const failed = steps.filter((s) => !s.pass).length;
  console.log(`\n${steps.length} steps, ${failed} failed; ${timings.length} decisions timed. Wrote logs/${name}.json`);
  return failed;
}

export function pkgVersion(name) {
  return JSON.parse(readFileSync(new URL(`../js/node_modules/${name}/package.json`, import.meta.url), 'utf8')).version;
}
