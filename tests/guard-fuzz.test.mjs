// tests/guard-fuzz.test.mjs - malformed-input testing of the guard (the internal review gate,
// docs/GUARD-THREAT-MODEL.md). A seeded, deterministic generator (no
// dependency) produces malformed and mutated policies, facts, tool calls, hook
// input and cached bundles, and checks the invariants that must hold for every
// one of them:
//
//   1. parsePolicy returns a policy whose document validates against
//      schemas/guard-policy.v1.schema.json, or throws PolicyError; never
//      another error type, and never slower than the per-case bound.
//   2. decideFrom never returns allow for facts that lack evidence the policy
//      requires (checked here by an independent, strict reading of the facts).
//   3. A guard that is offline with no cached bundle never allows, whatever
//      tool call or host it is given; a cached bundle whose signed bytes were
//      changed never allows.
//   4. `trooth guard hook` exits 0 or 2 and nothing else, and exits 0 silently
//      (the action runs) only for a tool the policy does not cover.
//
// The seed is fixed so a failure reproduces; TROOTH_FUZZ_SEED=<n> runs another
// sequence. Network-free. Prints "# fuzz: ..." lines that scripts/guard-results.mjs
// copies into docs/GUARD-RESULTS.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createGuard, parsePolicy, PolicyError, decideFrom } from '../bin/lib/guard.mjs';
import { toolCovered } from '../bin/lib/guard-policy.mjs';
import { TRUSTED, FUTURE_SKEW_MS } from '../bin/lib/guard-decide.mjs';
import { loadSchemas, makeValidator } from './lib/mini-schema.mjs';
import { makeWorld, POLICY_YAML, NOW } from './lib/guard-fixtures.mjs';

const validate = makeValidator(loadSchemas(new URL('../schemas/', import.meta.url)));
const root = new URL('../', import.meta.url);
const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const SEED = Number.parseInt(process.env.TROOTH_FUZZ_SEED ?? '20261007', 10) >>> 0;
/** No single case may take longer than this. A hang or a super-linear blow-up shows up here. */
const CASE_BOUND_MS = 2000;
const DAY = 86400000;
const started = performance.now();
const counts = {};
const count = (k, n = 1) => { counts[k] = (counts[k] ?? 0) + n; };

/* ------------------------------------------------------------ generator -- */

/** mulberry32: a small seeded generator. Deterministic for a given seed. */
function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n) => Math.floor(next() * n);
  const pick = (arr) => arr[int(arr.length)];
  const chance = (p) => next() < p;
  return { next, int, pick, chance };
}
const R = rng(SEED);

// Look-alikes: Cyrillic and Greek letters that render like Latin ones, fullwidth
// forms, and invisible characters that change bytes but not what a reader sees.
const HOMOGLYPHS = { a: ['а', 'ɑ', 'ａ'], c: ['с', 'ϲ', 'ｃ'], e: ['е', 'ｅ'], i: ['і', 'ｉ'], o: ['о', 'ο', 'ｏ', '0'], p: ['р', 'ｐ'], s: ['ѕ', 'ｓ'], x: ['х', 'ｘ'], y: ['у', 'ｙ'], l: ['ӏ', '1', 'ｌ'], d: ['ԁ', 'ｄ'], h: ['һ', 'ｈ'], n: ['ո', 'ｎ'], t: ['ｔ'], r: ['г', 'ｒ'], u: ['ս', 'ｕ'], w: ['ԝ', 'ｗ'], '_': ['＿', '‗'], '.': ['．', '。'], ':': ['：', '꞉'], '-': ['‐', '‑', '−'] };
const INVISIBLE = ['​', '‌', '‍', '⁠', '﻿', '­', '‮', '‭'];
const WORDS = ['allow', 'hold', 'deny', 'valid', 'active', 'retired_before_use', 'revoked', 'compromised', 'true', 'false', 'null', 'trooth_reading', 'legal_entity_registry_record', 'no_sanctions_name_match', 'check:S1', 'mcp__bank__*', 'stripe.create_payout', '*', '**', '*.com', 'failMode', '__proto__', 'constructor', 'prototype'];

function lookalike(s) {
  const chars = [...s];
  if (!chars.length) return INVISIBLE[R.int(INVISIBLE.length)];
  const n = 1 + R.int(Math.min(3, chars.length));
  for (let k = 0; k < n; k++) {
    const i = R.int(chars.length);
    const opts = HOMOGLYPHS[chars[i].toLowerCase()];
    if (opts && R.chance(0.7)) chars[i] = R.pick(opts);
    else chars.splice(i, 0, R.pick(INVISIBLE));
  }
  return chars.join('');
}

function randomString() {
  switch (R.int(7)) {
    case 0: return '';
    case 1: return R.pick(WORDS);
    case 2: return lookalike(R.pick(WORDS));
    case 3: { let s = ''; const n = R.int(40); for (let i = 0; i < n; i++) s += String.fromCharCode(32 + R.int(95)); return s; }
    case 4: { let s = ''; const n = R.int(20); for (let i = 0; i < n; i++) s += String.fromCodePoint(R.chance(0.1) ? 0xd800 + R.int(0x800) : R.int(0x2ffff)); return s; }
    case 5: return R.pick(['https://acme.com/pay', 'http://10.0.0.1/', 'acme.com', 'a@acme.com', 'https://a.com\\@b.com', 'mailto:x@acme.com', 'ftp://acme.com', 'https://user:pw@acme.com', 'https://xn--80ak6aa92e.com/', 'ACME.COM.', '[::1]', 'localhost', '*.acme.com']);
    default: return 'x'.repeat(R.pick([1, 64, 129, 300, 5000]));
  }
}

function randomValue(depth = 0) {
  switch (R.int(depth > 3 ? 6 : 9)) {
    case 0: return null;
    case 1: return R.chance(0.5);
    case 2: return R.pick([0, 1, -1, 2, 7, 36500, 36501, 2 ** 53 - 1, 2 ** 53, 1.5, -0, 1e21]);
    case 3: case 4: case 5: return randomString();
    case 6: { const a = []; const n = R.int(4); for (let i = 0; i < n; i++) a.push(randomValue(depth + 1)); return a; }
    default: { const o = {}; const n = R.int(4); for (let i = 0; i < n; i++) o[R.chance(0.5) ? R.pick(WORDS) : randomString()] = randomValue(depth + 1); return o; }
  }
}

/* -------------------------------------------------------------- serializers */

const PLAIN_KEY = /^[A-Za-z0-9_][A-Za-z0-9_.\-/]*$/;
const yKey = (k) => (PLAIN_KEY.test(k) ? k : JSON.stringify(k));
const yFlow = (v) => JSON.stringify(v) ?? 'null';
/** Block YAML for the top level and for rules, flow (JSON) for everything deeper: the subset yaml-lite reads. */
function toYaml(doc) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return yFlow(doc);
  const lines = [];
  for (const k of Object.keys(doc)) {
    const v = doc[k];
    if (k === 'rules' && Array.isArray(v) && v.length && v.every((r) => r && typeof r === 'object' && !Array.isArray(r) && Object.keys(r).length)) {
      lines.push(`${yKey(k)}:`);
      for (const r of v) Object.keys(r).forEach((rk, i) => lines.push(`${i === 0 ? '  - ' : '    '}${yKey(rk)}: ${yFlow(r[rk])}`));
    } else lines.push(`${yKey(k)}: ${yFlow(v)}`);
  }
  return lines.join('\n') + '\n';
}

/* ----------------------------------------------------------------- seeds -- */

const SEED_YAML = [
  POLICY_YAML,
  'policy: minimal\nversion: 1\napplies_to:\n  tools: ["x"]\nrules:\n  - id: r\n    require: { claim: trooth_reading }\n',
  `policy: http-only.v2
version: 12
description: "an http-only policy with a check claim"
applies_to:
  http:
    - { method: post, host: "*.example-bank.com" }
    - method: "*"
      host: pay.example.org
host_from: [url, request.host, to]
log: { required: false, min_witnesses: 0 }
rules:
  - id: reading-check
    require: { claim: "check:S1", max_age_days: 30 }
  - id: keys
    require: { signature: valid }
    absolute: true
destinations: { allowed: ["api.stripe.com", "*.example.org"], watch: ["*"] }
unknown_counterparty: deny
source_unreachable: deny
`,
];
for (const f of ['.trooth/guard-policy.yaml']) if (existsSync(new URL(f, root))) SEED_YAML.push(readFileSync(new URL(f, root), 'utf8'));
const pilotDir = new URL('pilots/policies/', root);
if (existsSync(pilotDir)) for (const f of readdirSync(pilotDir).sort()) if (f.endsWith('.yaml')) SEED_YAML.push(readFileSync(new URL(f, pilotDir), 'utf8'));
const SEED_DOCS = SEED_YAML.map((t) => parsePolicy(t, 'yaml').document);
const SEED_TEXTS = [...SEED_YAML.map((t) => [t, 'yaml']), ...SEED_DOCS.map((d) => [JSON.stringify(d, null, 2), 'json'])];
const VALID_POLICIES = SEED_YAML.map((t) => parsePolicy(t, 'yaml'));

/* ------------------------------------------------- invariant 1: policies -- */

const policyFailures = [];
const parsedPool = [];
function policyCase(text, format, kind) {
  count(`policy:${kind}`);
  count('policy:total');
  const t0 = performance.now();
  let policy, err;
  try { policy = parsePolicy(text, format); } catch (e) { err = e; }
  const ms = performance.now() - t0;
  const show = () => JSON.stringify(typeof text === 'string' && text.length > 300 ? `${text.slice(0, 300)}...(${text.length} chars)` : text);
  if (ms > CASE_BOUND_MS) policyFailures.push(`${kind}: ${ms.toFixed(0)} ms (bound ${CASE_BOUND_MS}) for ${show()}`);
  if (err) {
    if (!(err instanceof PolicyError)) policyFailures.push(`${kind}: ${err?.constructor?.name} ${err?.message} for ${show()}`);
    else count('policy:refused');
    return;
  }
  count('policy:accepted');
  const errs = validate('guard-policy.v1.schema.json', policy.document);
  if (errs.length) policyFailures.push(`${kind}: accepted a document outside the schema (${errs.slice(0, 3).join('; ')}) for ${show()}`);
  if (!/^[0-9a-f]{64}$/.test(policy.sha256) || !policy.rules.length) policyFailures.push(`${kind}: accepted without a hash or rules for ${show()}`);
  if (parsedPool.length < 400) parsedPool.push(policy);
}

function mutateDoc(doc) {
  const d = structuredClone(doc);
  // Walk to a random container.
  let parent = d;
  for (let steps = R.int(4); steps > 0; steps--) {
    const keys = Object.keys(parent);
    if (!keys.length) break;
    const k = R.pick(keys);
    if (parent[k] && typeof parent[k] === 'object') parent = parent[k]; else break;
  }
  const keys = Object.keys(parent);
  const k = keys.length ? R.pick(keys) : (Array.isArray(parent) ? 0 : 'k');
  switch (R.int(9)) {
    case 0: parent[k] = randomValue(); break; // wrong type or wrong value
    case 1: if (Array.isArray(parent)) parent.splice(Number(k), 1); else delete parent[k]; break;
    case 2: if (!Array.isArray(parent)) parent[R.pick(['unknown', 'failMode', 'fail_mode', 'Policy', 'rules ', lookalike('rules')])] = R.pick(['allow', randomValue()]); else parent.push(randomValue()); break;
    case 3: if (!Array.isArray(parent)) Object.defineProperty(parent, R.pick(['__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString']), { value: R.chance(0.5) ? { rules: [], policy: 'x', version: 1 } : randomValue(), enumerable: true, configurable: true, writable: true }); break;
    case 4: if (typeof parent[k] === 'string') parent[k] = lookalike(parent[k]); else parent[k] = lookalike(JSON.stringify(parent[k]) ?? "x"); break;
    case 5: parent[k] = [parent[k]]; break;
    case 6: if (typeof parent[k] === 'number') parent[k] = R.pick([String(parent[k]), -parent[k], parent[k] + 0.5, 2 ** 60]); else parent[k] = R.pick([1, 0, true]); break;
    case 7: if (typeof parent[k] === 'string') parent[k] = parent[k].toUpperCase(); else parent[k] = null; break;
    default: { const ks = Object.keys(parent); if (ks.length > 1 && !Array.isArray(parent)) { const a = R.pick(ks), b = R.pick(ks); const t = parent[a]; parent[a] = parent[b]; parent[b] = t; } }
  }
  return d;
}

/** Repeat one top-level line, or one key inside a flow map, so a key appears twice. */
function duplicateKeyText(text, format) {
  if (format === 'json') {
    const m = [...text.matchAll(/\n(\s+)("[^"]+": [^\n]*?),?\n/g)];
    if (!m.length) return text;
    const x = R.pick(m);
    return text.replace(x[0], `\n${x[1]}${x[2]},\n${x[1]}${x[2].replace(/,$/, '')},\n`);
  }
  const lines = text.split('\n');
  const idx = lines.map((l, i) => [l, i]).filter(([l]) => /^[ ]*[A-Za-z_"][^:]*:/.test(l) && !/^\s*#/.test(l));
  if (!idx.length) return text;
  const [line, i] = R.pick(idx);
  if (/\{[^}]*:/.test(line) && R.chance(0.5)) return lines.map((l, j) => (j === i ? l.replace(/\{\s*([^,}]+),?/, (all, kv) => `{ ${kv}, ${kv},`) : l)).join('\n');
  lines.splice(i + 1, 0, line);
  return lines.join('\n');
}

function nested(depth, format, open = '[', close = ']') {
  if (format === 'json') return `{"policy": "nest", "version": 1, "applies_to": {"tools": ${open.repeat(depth)}${close.repeat(depth)}}, "rules": []}`;
  if (R.chance(0.5)) return `policy: nest\nversion: 1\napplies_to:\n  tools: ${open.repeat(depth)}${close.repeat(depth)}\nrules: []\n`;
  let s = 'policy: nest\nversion: 1\nrules:\n'; // block nesting, one level per line
  for (let i = 0; i < Math.min(depth, 3000); i++) s += `${' '.repeat(2 + i * 2)}k${i}:\n`;
  return s;
}

test('invariant 1: every malformed or mutated policy is refused with PolicyError, or accepted and inside the schema', { timeout: 120000 }, () => {
  for (const [text, fmt] of SEED_TEXTS) policyCase(text, fmt, 'seed');
  assert.deepEqual(policyFailures, [], 'every seed parses');
  // Every valid policy with one byte flipped (one random bit of every byte, in turn).
  for (const [text, fmt] of SEED_TEXTS) {
    const buf = Buffer.from(text, 'utf8');
    for (let i = 0; i < buf.length; i++) {
      const b = Buffer.from(buf);
      b[i] ^= 1 << R.int(8);
      policyCase(b.toString('utf8'), R.chance(0.8) ? fmt : undefined, 'byte-flip');
    }
  }
  // Every truncation of every valid policy.
  for (const [text, fmt] of SEED_TEXTS) for (let n = 0; n < text.length; n++) policyCase(text.slice(0, n), fmt, 'truncation');
  // Random bytes.
  for (let k = 0; k < 2500; k++) {
    const b = Buffer.alloc(R.int(600));
    for (let i = 0; i < b.length; i++) b[i] = R.int(256);
    policyCase(R.chance(0.5) ? b.toString('utf8') : b.toString('latin1'), R.pick(['yaml', 'json', undefined]), 'random-bytes');
  }
  // Wrong types, unknown keys, prototype keys, look-alikes, swapped values, through both serializers.
  for (let k = 0; k < 4000; k++) {
    let d = R.pick(SEED_DOCS);
    for (let m = 1 + R.int(3); m > 0; m--) d = mutateDoc(d);
    policyCase(JSON.stringify(d), 'json', 'structural');
    policyCase(toYaml(d), 'yaml', 'structural');
  }
  // Duplicate keys, in text (a parser that keeps the last value would change the meaning).
  for (let k = 0; k < 1000; k++) {
    const [text, fmt] = R.pick(SEED_TEXTS);
    const t = duplicateKeyText(text, fmt);
    if (t !== text) policyCase(t, fmt, 'duplicate-key');
  }
  // Prototype keys at the top and inside each mapping, in text.
  for (const [text, fmt] of SEED_TEXTS) {
    for (const key of ['__proto__', 'constructor', 'prototype']) {
      if (fmt === 'json') {
        policyCase(text.replace('{', `{"${key}": {"rules": [], "policy": "x"},`), fmt, 'prototype-key');
        policyCase(text.replace('"applies_to": {', `"applies_to": {"${key}": {"tools": ["*"]},`), fmt, 'prototype-key');
      } else {
        policyCase(`${key}:\n  rules: []\n${text}`, fmt, 'prototype-key');
        policyCase(text.replace(/^applies_to:\n/m, `applies_to:\n  ${key}: { tools: ["*"] }\n`), fmt, 'prototype-key');
        policyCase(text.replace(/require: \{ /g, `require: { ${key}: 1, `), fmt, 'prototype-key');
      }
    }
  }
  // Unicode look-alikes and invisible characters in keys and values.
  for (let k = 0; k < 2500; k++) {
    const [text, fmt] = R.pick(SEED_TEXTS);
    const words = [...new Set(text.match(/[A-Za-z_][A-Za-z0-9_.:*-]{2,}/g) ?? [])];
    const w = R.pick(words);
    policyCase(text.split(w).join(lookalike(w)), fmt, 'lookalike');
  }
  // Deep nesting, in JSON, YAML flow and YAML block form.
  for (let depth = 1; depth <= 200; depth++) {
    policyCase(nested(depth, 'json', R.pick(['[', '{"a":']), ''), 'json', 'deep-nesting');
    policyCase(nested(depth, 'json'), 'json', 'deep-nesting');
    policyCase(nested(depth, 'yaml'), 'yaml', 'deep-nesting');
  }
  for (const depth of [1000, 10000, 100000]) for (const f of ['json', 'yaml']) policyCase(nested(depth, f), f, 'deep-nesting');
  // Huge strings: in a value, in a key, in a list.
  for (const n of [1 << 16, 1 << 20, 4 << 20]) {
    const big = 'a'.repeat(n);
    policyCase(POLICY_YAML.replace('vendor-payments', big), 'yaml', 'huge-string');
    policyCase(POLICY_YAML.replace('policy: vendor-payments', `${big}: 1\npolicy: vendor-payments`), 'yaml', 'huge-string');
    policyCase(JSON.stringify({ ...SEED_DOCS[0], description: big }), 'json', 'huge-string');
    policyCase(JSON.stringify({ ...SEED_DOCS[0], applies_to: { tools: Array.from({ length: Math.min(n / 64, 50000) }, (_, i) => `t${i}`) } }), 'json', 'huge-string');
  }
  // Text that is not text.
  for (const v of [undefined, null, 0, {}, [], Buffer.from('policy: x'), Symbol('s')]) {
    count('policy:total'); count('policy:not-text');
    assert.throws(() => parsePolicy(v), PolicyError);
  }
  console.log(`# fuzz: policies ${counts['policy:total']} cases (seed ${SEED}): ${counts['policy:accepted']} accepted and inside the schema, ${counts['policy:refused']} refused with PolicyError; by kind ${Object.entries(counts).filter(([k]) => /^policy:/.test(k) && !/total|accepted|refused/.test(k)).map(([k, v]) => `${k.slice(7)} ${v}`).join(', ')}`);
  assert.ok(counts['policy:total'] >= 20000, `at least 20,000 policy cases (ran ${counts['policy:total']})`);
  assert.deepEqual(policyFailures.slice(0, 10), [], `${policyFailures.length} policy cases broke an invariant`);
});

/* ---------------------------------------------------- invariant 2: facts -- */

/** An independent, strict reading: does every piece of evidence the policy requires stand in these facts? */
function evidenceComplete(f, policy) {
  if (!f || typeof f !== 'object') return false;
  if (!Number.isFinite(f.now)) return false;
  if (f.target !== 'ok' || typeof f.host !== 'string' || !f.host) return false;
  if (f.source === 'unreachable') return false;
  if (f.record !== true || f.schema_supported !== true || f.subject_match !== true) return false;
  if (f.signature !== 'valid' || !TRUSTED.includes(f.key_status)) return false;
  if (f.log === 'proof_invalid') return false;
  if (policy.log.required && (f.log !== 'included' || typeof f.witnesses !== 'number' || !(f.witnesses >= policy.log.min_witnesses))) return false;
  for (const rule of policy.rules) {
    if (rule.require.claim) {
      const c = f.claims && typeof f.claims === 'object' && Object.prototype.hasOwnProperty.call(f.claims, rule.require.claim) ? f.claims[rule.require.claim] : undefined;
      if (!c || typeof c !== 'object' || c.disputed) return false;
      const observed = Date.parse(c.observed_at);
      if (!Number.isFinite(observed) || observed > f.now + FUTURE_SKEW_MS) return false;
      const limit = rule.require.max_age_days ? observed + rule.require.max_age_days * DAY : Date.parse(c.stale_after);
      if (!Number.isFinite(limit) || f.now > limit) return false;
    } else if (!rule.require.key_status.includes(f.key_status)) return false;
  }
  return true;
}

const ALL_CLAIMS = ['trooth_reading', 'legal_entity_registry_record', 'no_sanctions_name_match', 'no_sam_exclusion_name_match', 'domain_registration_record', 'security_txt_published', 'domain_control_confirmed', 'check:S1', 'check:S2'];
const odd = () => R.pick([undefined, null, '', 'true', 'false', 1, 0, NaN, Infinity, -1, {}, [], 'valid', 'included', 'yes']);
function randomClaim(now) {
  if (R.chance(0.08)) return odd();
  const age = R.pick([0, DAY, 6 * DAY, 8 * DAY, 29 * DAY, 31 * DAY, 400 * DAY, -10 * 60000, -DAY]);
  const c = { fact_id: 'f', statement_sha256: 'a'.repeat(64), log_index: 1, observed_at: new Date(now - age).toISOString(), stale_after: new Date(now - age + R.pick([7, 30, 365]) * DAY).toISOString(), disputed: false };
  if (R.chance(0.1)) c.observed_at = odd();
  if (R.chance(0.1)) c.stale_after = odd();
  if (R.chance(0.08)) c.disputed = R.pick([true, 'false', 1, 'withheld']);
  if (R.chance(0.03)) delete c.observed_at;
  return c;
}
function randomFacts() {
  const now = R.chance(0.97) ? NOW : odd();
  const n = Number.isFinite(now) ? now : NOW;
  const f = {
    now, host: 'acme.com', target: 'ok', source: R.pick(['network', 'cache']), record: true, subject: 'trooth:domain:acme.com',
    schema_supported: true, signature: 'valid', key_status: 'active', subject_match: true, log: 'included', witnesses: R.pick([0, 1, 2, Infinity]), claims: {}, detail: {},
  };
  for (const c of ALL_CLAIMS) if (R.chance(0.85)) f.claims[c] = randomClaim(n);
  // Perturb a few fields: a wrong value, a wrong type, or the field gone.
  const fields = ['host', 'target', 'source', 'record', 'schema_supported', 'signature', 'key_status', 'subject_match', 'log', 'witnesses', 'claims', 'detail', 'subject'];
  const values = { target: ['ok', 'none', 'ambiguous', 'non_record'], source: ['network', 'cache', 'unreachable'], signature: ['valid', 'invalid', 'absent'], key_status: ['active', 'retired_before_use', 'retired_after_use', 'revoked', 'compromised', 'unknown'], log: ['included', 'not_logged', 'unavailable', 'proof_invalid'], witnesses: [0, 1, 2, 3] };
  for (let k = R.int(4); k > 0; k--) {
    const field = R.pick(fields);
    if (R.chance(0.5) && values[field]) f[field] = R.pick(values[field]);
    else if (R.chance(0.15)) delete f[field];
    else f[field] = odd();
  }
  if (R.chance(0.03)) f.claims = Object.create(f.claims && typeof f.claims === 'object' ? f.claims : {}); // claims only inherited
  return f;
}

test('invariant 2: decideFrom never allows facts that lack evidence the policy requires', { timeout: 60000 }, () => {
  const policies = [...VALID_POLICIES, ...parsedPool];
  const failures = [];
  let allows = 0, holds = 0, denies = 0, throws = 0;
  for (let k = 0; k < 30000; k++) {
    const policy = R.pick(policies);
    const f = randomFacts();
    count('facts:total');
    let d;
    try { d = decideFrom(f, policy); } catch (e) { throws++; if (Number.isFinite(f.now)) failures.push(`threw with a valid clock: ${e.message}`); continue; }
    const errs = validate('guard-decision.v1.schema.json', d);
    if (errs.length) failures.push(`decision outside its schema: ${errs[0]}`);
    if (d.decision === 'allow') {
      allows++;
      if (!evidenceComplete(f, policy)) failures.push(`allow without the evidence: policy ${policy.id}, facts ${JSON.stringify(f, (key, v) => (typeof v === 'number' && !Number.isFinite(v) ? String(v) : v)).slice(0, 400)}`);
    } else if (d.decision === 'hold') holds++; else denies++;
    if (f.source === 'unreachable' && d.decision === 'allow') failures.push('source unreachable allowed');
    let again;
    try { again = decideFrom(structuredClone(f), policy); } catch { again = null; }
    if (again && again.decision !== d.decision) failures.push('the same facts gave two decisions');
  }
  console.log(`# fuzz: facts ${counts['facts:total']} cases: ${allows} allow (each with every required piece of evidence), ${holds} hold, ${denies} deny, ${throws} refused with an error (malformed now); no allow without the evidence: ${failures.length === 0}`);
  assert.ok(allows > 100, `the generator reaches allow (${allows})`);
  assert.deepEqual(failures.slice(0, 10), [], `${failures.length} facts cases broke an invariant`);
});

/* -------------------------------------- invariant 3: offline guard, bundles -- */

const COVERED = ['stripe.create_payout', 'mcp__bank__transfer', 'mcp__bank__', 'STRIPE.create_payout', 'ｓtripe.create_payout', 'stripe.create_payout​', 'mcp__bank__‮transfer'];
function randomToolCall() {
  const name = R.chance(0.6) ? R.pick(COVERED) : R.chance(0.5) ? randomString() : randomValue();
  let args;
  switch (R.int(6)) {
    case 0: args = randomValue(); break;
    case 1: args = JSON.stringify({ url: randomString(), memo: randomString() }); break;
    case 2: args = R.pick(['{', '{"url": "https://acme.com/', 'null', '[]', '"https://acme.com"', '{"url": "https://acme.com", "url": "https://evil.com"}']); break;
    case 3: { args = {}; for (const k of ['url', 'endpoint', 'host', 'domain', 'base_url', 'webhook_url', 'email', 'to']) if (R.chance(0.3)) args[k] = R.chance(0.7) ? randomString() : randomValue(); break; }
    case 4: { args = JSON.parse(`{"__proto__": {"url": "https://acme.com"}, "domain": ${JSON.stringify(randomString())}}`); break; }
    default: { let v = { url: 'https://acme.com/pay' }; for (let i = R.int(2000); i > 0; i--) v = { a: v }; args = R.chance(0.5) ? v : { url: 'https://acme.com/pay', nested: v }; }
  }
  return { name, arguments: args };
}

test('invariant 3a: offline with no cached bundle, no tool call and no host is ever allowed', { timeout: 60000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-fuzz-empty-'));
  const failures = [];
  let nulls = 0, holds = 0, denies = 0;
  for (const policy of [...VALID_POLICIES, ...parsedPool.slice(0, 40)]) {
    for (const failMode of ['hold', 'deny']) {
      const g = createGuard({ policy, offline: true, cache: { dir }, failMode });
      for (let k = 0; k < 60; k++) {
        const call = randomToolCall();
        count('offline:total');
        let d;
        try { d = await g.decideToolCall(call); } catch (e) { failures.push(`decideToolCall threw ${e?.constructor?.name}: ${e?.message}`); continue; }
        if (d === null) { nulls++; if (g.applies(call.name)) failures.push(`null for a covered tool ${JSON.stringify(call.name)}`); continue; }
        if (validate('guard-decision.v1.schema.json', d).length) failures.push('decision outside its schema');
        if (d.decision === 'allow') failures.push(`offline allow for ${JSON.stringify(call).slice(0, 200)}`);
        d.decision === 'hold' ? holds++ : denies++;
        const host = R.chance(0.7) ? randomString() : randomValue();
        count('offline:total');
        try { d = await g.decide({ tool: R.pick(COVERED), host, args: call.arguments }); } catch (e) { failures.push(`decide threw ${e?.message}`); continue; }
        if (d.decision === 'allow') failures.push(`offline allow for host ${JSON.stringify(host)}`);
      }
    }
  }
  rmSync(dir, { recursive: true, force: true });
  console.log(`# fuzz: offline guard, empty cache: ${counts['offline:total']} tool calls and hosts: ${nulls} not covered (null), ${holds} hold, ${denies} deny, 0 allow expected; failures ${failures.length}`);
  assert.deepEqual(failures.slice(0, 10), [], `${failures.length} offline cases broke an invariant`);
});

/** Every path to a leaf in a JSON value. */
function leaves(v, path = []) {
  if (v && typeof v === 'object') return Object.keys(v).flatMap((k) => leaves(v[k], [...path, k]));
  return [path];
}
const getAt = (o, p) => p.reduce((x, k) => x?.[k], o);
const setAt = (o, p, val) => { const parent = getAt(o, p.slice(0, -1)); if (parent && typeof parent === 'object') parent[p.at(-1)] = val; };
const SIGNED = (p) => {
  const s = p.join('.');
  return /^witness\.statement\.(payload|signature)$/.test(s) || /^public_record\.signed\.statement\.(payload|signature)$/.test(s) || (/^public_record\./.test(s) && !/^public_record\.signed\./.test(s));
};

test('invariant 3b: a cached bundle with any field changed gives a decision inside the schema; with its signed bytes changed, never allow', { timeout: 60000 }, async () => {
  const world = makeWorld({ domains: { 'acme.com': { witness: {}, public: {} } } });
  const seedDir = mkdtempSync(join(tmpdir(), 'trooth-fuzz-seed-'));
  const policy = parsePolicy(POLICY_YAML);
  const base = { policy, now: world.now, vkeys: world.vkeys, witnesses: world.witnesses };
  const saved = await createGuard({ ...base, fetch: world.fetch, api: world.api, web: world.web, cache: { dir: seedDir } }).saveBundle('acme.com');
  assert.equal(saved.saved, true);
  const original = JSON.parse(readFileSync(saved.path, 'utf8'));
  const call = { name: 'stripe.create_payout', arguments: { url: 'https://acme.com/pay' } };
  const dir = mkdtempSync(join(tmpdir(), 'trooth-fuzz-bundle-'));
  const g = createGuard({ ...base, offline: true, cache: { dir } });
  writeFileSync(join(dir, 'acme.com.trooth-guard.json'), JSON.stringify(original));
  assert.equal((await g.decideToolCall(call)).decision, 'allow', 'the unchanged bundle allows, so a change is what the cases test');
  const paths = leaves(original);
  const signedPaths = paths.filter(SIGNED);
  const failures = [];
  let signedCases = 0, allows = 0;
  for (let k = 0; k < 800; k++) {
    const b = structuredClone(original);
    const signedOnly = k % 3 === 0;
    const p = R.pick(signedOnly ? signedPaths : paths);
    const cur = getAt(b, p);
    let changed;
    if (typeof cur === 'string' && cur.length && R.chance(0.7)) {
      const i = R.int(cur.length);
      const ch = cur.charCodeAt(i);
      changed = cur.slice(0, i) + String.fromCharCode(ch === 0x41 ? 0x42 : ch ^ 1) + cur.slice(i + 1);
    } else {
      changed = randomValue();
      if (JSON.stringify(changed) === JSON.stringify(cur)) changed = cur === null ? 0 : null;
    }
    setAt(b, p, changed);
    if (R.chance(0.1) && !signedOnly) { const q = R.pick(paths); setAt(b, q.slice(0, -1), randomValue()); }
    const text = R.chance(0.03) ? JSON.stringify(b).slice(0, R.int(2000)) : JSON.stringify(b);
    writeFileSync(join(dir, 'acme.com.trooth-guard.json'), text);
    count('bundle:total');
    let d;
    try { d = await g.decideToolCall(call); } catch (e) { failures.push(`threw ${e?.message} at ${p.join('.')}`); continue; }
    if (validate('guard-decision.v1.schema.json', d).length) failures.push(`decision outside its schema at ${p.join('.')}`);
    if (d.decision === 'allow') allows++;
    if (SIGNED(p)) { signedCases++; if (d.decision === 'allow') failures.push(`allow with a signed byte changed at ${p.join('.')}`); }
  }
  rmSync(dir, { recursive: true, force: true }); rmSync(seedDir, { recursive: true, force: true });
  console.log(`# fuzz: cached bundles ${counts['bundle:total']} cases: ${signedCases} with signed bytes changed (none allowed), ${allows} allowed with only unsigned fields changed; failures ${failures.length}`);
  assert.deepEqual(failures.slice(0, 10), [], `${failures.length} bundle cases broke an invariant`);
});

/* ------------------------------------------------------ invariant 4: hook -- */

function hook(policyPath, stdin, extra = []) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, 'guard', 'hook', '--policy', policyPath, ...extra], { env: { ...process.env, TROOTH_API: 'http://127.0.0.1:9', TROOTH_WEB: 'http://127.0.0.1:9', NO_COLOR: '1', NODE_NO_WARNINGS: '1' } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.stdin.on('error', () => {});
    p.on('close', (code, signal) => resolve({ code, signal, out, err }));
    p.stdin.end(stdin);
  });
}

test('invariant 4: the hook exits 0 or 2 for any input, and exits 0 silently only for a tool the policy does not cover', { timeout: 120000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-fuzz-hook-'));
  const cache = join(dir, 'cache');
  const policies = [];
  for (let i = 0; i < 6; i++) {
    let text, fmt = 'yaml';
    if (i < 2) text = SEED_YAML[i];
    else if (i === 2) text = SEED_YAML[0].slice(0, 200);
    else if (i === 3) { text = JSON.stringify(mutateDoc(SEED_DOCS[0])); fmt = 'json'; }
    else if (i === 4) text = `${'['.repeat(50000)}`;
    else text = '\u0000ÿ policy';
    const path = join(dir, `p${i}.${fmt}`);
    writeFileSync(path, text);
    let policy = null;
    try { policy = parsePolicy(text, fmt); } catch {}
    policies.push({ path, policy });
  }
  const inputs = [];
  for (let k = 0; k < 64; k++) {
    let stdin;
    switch (R.int(7)) {
      case 0: { const b = Buffer.alloc(R.int(300)); for (let i = 0; i < b.length; i++) b[i] = R.int(256); stdin = b; break; }
      case 1: { const s = JSON.stringify({ session_id: 's', hook_event_name: 'PreToolUse', tool_name: R.pick(COVERED), tool_input: { url: 'https://acme.com/x' } }); stdin = s.slice(0, R.int(s.length)); break; }
      case 2: stdin = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: randomValue(), tool_input: randomValue() }); break;
      case 3: stdin = JSON.stringify({ tool_name: R.pick([...COVERED, 'Read', 'Bash', 'WebFetch']), tool_input: randomToolCall().arguments }); break;
      case 4: stdin = R.pick(['', 'null', '[]', '"x"', '{}', '{"tool_name": null}', '{"__proto__": {"tool_name": "stripe.create_payout"}}', `{"tool_name": "stripe.create_payout", "tool_input": ${'['.repeat(20000)}${']'.repeat(20000)}}`]); break;
      case 5: stdin = JSON.stringify({ tool_name: 'stripe.create_payout', tool_input: { url: 'https://acme.com/' }, pad: 'x'.repeat(R.pick([1000, 1100000])) }); break;
      default: stdin = JSON.stringify({ tool_name: R.pick(COVERED), tool_input: { url: randomString(), to: randomString() } });
    }
    const pol = R.chance(0.75) ? policies[R.int(2)] : R.pick(policies);
    const extra = R.chance(0.5) ? ['--offline', '--cache', cache] : [];
    inputs.push({ stdin, pol, extra });
  }
  const failures = [];
  const tally = { 0: 0, 2: 0, silent: 0 };
  let next = 0;
  async function worker() {
    while (next < inputs.length) {
      const c = inputs[next++];
      const r = await hook(c.pol.path, c.stdin, c.extra);
      count('hook:total');
      if (r.code !== 0 && r.code !== 2) { failures.push(`exit ${r.code} (signal ${r.signal}) for ${String(c.stdin).slice(0, 120)}: ${r.err.slice(0, 200)}`); continue; }
      tally[r.code]++;
      if (r.code === 0 && r.out.trim() === '') {
        tally.silent++;
        let toolName;
        try { toolName = JSON.parse(c.stdin.toString()).tool_name; } catch {}
        if (!c.pol.policy || typeof toolName !== 'string' || toolCovered(c.pol.policy, toolName)) failures.push(`a silent exit 0 (the action runs) for a covered tool or a bad policy or input: ${String(c.stdin).slice(0, 160)}`);
      }
      if (r.code === 0 && r.out.trim()) {
        let o;
        try { o = JSON.parse(r.out); } catch { failures.push(`exit 0 with output that is not JSON: ${r.out.slice(0, 100)}`); continue; }
        if (o?.hookSpecificOutput?.permissionDecision !== 'ask') failures.push(`exit 0 with output that is not an ask: ${r.out.slice(0, 100)}`);
      }
    }
  }
  await Promise.all([worker(), worker(), worker(), worker()]);
  rmSync(dir, { recursive: true, force: true });
  console.log(`# fuzz: hook ${counts['hook:total']} runs: exit 0 ${tally[0]} (${tally.silent} silent, each for a tool the policy does not cover; the rest ask), exit 2 ${tally[2]}, any other exit 0`);
  assert.deepEqual(failures.slice(0, 10), [], `${failures.length} hook runs broke an invariant`);
});

/* ------------------------------------------- regressions for what it found -- */

test('FUZZ-REG-1 deep nesting is refused with PolicyError, not a RangeError (found by this file, fixed in 0.15.0)', () => {
  for (const depth of [65, 10000, 100000]) {
    assert.throws(() => parsePolicy('['.repeat(depth) + ']'.repeat(depth), 'json'), PolicyError);
    assert.throws(() => parsePolicy(`{"policy": ${'['.repeat(depth)}${']'.repeat(depth)}}`, 'json'), PolicyError);
    assert.throws(() => parsePolicy(`policy: ${'['.repeat(depth)}${']'.repeat(depth)}`, 'yaml'), PolicyError);
    assert.throws(() => parsePolicy(`policy: ${'{a: '.repeat(depth)}1${'}'.repeat(depth)}`, 'yaml'), PolicyError);
  }
  let block = 'policy: nest\n';
  for (let i = 0; i < 100; i++) block += `${' '.repeat(i * 2)}k${i}:\n`;
  assert.throws(() => parsePolicy(block, 'yaml'), /nested deeper than 64/);
  // A policy at ordinary depth still parses.
  assert.equal(parsePolicy(POLICY_YAML).id, 'vendor-payments');
  assert.equal(parsePolicy(JSON.stringify(parsePolicy(POLICY_YAML).document)).id, 'vendor-payments');
});

test('FUZZ-REG-2 decideFrom reads facts strictly: a field that is not exactly the value that shows the evidence is the evidence missing (found by this file, fixed in 0.15.0)', () => {
  const P = parsePolicy(POLICY_YAML);
  const fresh = { observed_at: new Date(NOW - DAY).toISOString(), stale_after: new Date(NOW + DAY).toISOString(), fact_id: 'f', statement_sha256: 'a'.repeat(64), log_index: 1, disputed: false };
  const good = { now: NOW, host: 'acme.com', target: 'ok', source: 'network', record: true, subject: 'trooth:domain:acme.com', schema_supported: true, signature: 'valid', key_status: 'active', subject_match: true, log: 'included', witnesses: 2, claims: { legal_entity_registry_record: fresh, no_sanctions_name_match: fresh } };
  assert.equal(decideFrom(good, P).decision, 'allow');
  const cases = [
    [{ witnesses: undefined }, 'hold', 'NOT_IN_LOG'],
    [{ witnesses: 'x' }, 'hold', 'NOT_IN_LOG'],
    [{ witnesses: '5' }, 'hold', 'NOT_IN_LOG'],
    [{ witnesses: NaN }, 'hold', 'NOT_IN_LOG'],
    [{ record: 'false' }, 'hold', 'NO_RECORD'],
    [{ record: 1 }, 'hold', 'NO_RECORD'],
    [{ schema_supported: 1 }, 'hold', 'SCHEMA_UNSUPPORTED'],
    [{ subject_match: 'no' }, 'deny', 'SUBJECT_MISMATCH'],
    [{ subject_match: undefined }, 'deny', 'SUBJECT_MISMATCH'],
    [{ claims: Object.create(good.claims) }, 'hold', 'EVIDENCE_MISSING'],
    [{ claims: { legal_entity_registry_record: 'present', no_sanctions_name_match: fresh } }, 'hold', 'EVIDENCE_MISSING'],
    [{ claims: { legal_entity_registry_record: { ...fresh, observed_at: Date.now() }, no_sanctions_name_match: fresh } }, 'hold', 'EVIDENCE_MISSING'],
    [{ claims: { legal_entity_registry_record: { ...fresh, fact_id: undefined }, no_sanctions_name_match: fresh } }, 'hold', 'EVIDENCE_MISSING'],
    [{ target: 'valid' }, 'hold', 'EVIDENCE_MISSING'],
    [{ target: undefined }, 'hold', 'EVIDENCE_MISSING'],
    [{ host: 1 }, 'hold', 'EVIDENCE_MISSING'],
    [{ host: {} }, 'hold', 'EVIDENCE_MISSING'],
    [{ source: 'xyz' }, 'hold', 'SOURCE_UNREACHABLE'],
    [{ source: undefined }, 'hold', 'SOURCE_UNREACHABLE'],
  ];
  for (const [change, decision, code] of cases) {
    const d = decideFrom({ ...good, ...change }, P);
    assert.equal(d.decision, decision, JSON.stringify(change));
    assert.ok(d.reasons.some((r) => r.code === code), `${code} for ${JSON.stringify(change)}`);
    assert.deepEqual(validate('guard-decision.v1.schema.json', d), []);
  }
  assert.match(decideFrom({ ...good, witnesses: undefined }, P).reasons.find((r) => r.code === 'NOT_IN_LOG').detail, /not known/);
  // A subject or an action of the wrong type does not make the decision fall outside its schema.
  for (const change of [{ subject: 1 }, { subject: {} }, { action: 'x' }, { action: [] }, { detail: 'x' }]) {
    const d = decideFrom({ ...good, ...change }, P);
    assert.equal(d.decision, 'allow');
    assert.deepEqual(validate('guard-decision.v1.schema.json', d), [], JSON.stringify(change));
  }
});

test('FUZZ-REG-3 an http method that is not a string is refused, not read through String() (found by this file with seed 1, fixed in 0.15.0)', () => {
  const doc = parsePolicy(POLICY_YAML).document;
  for (const method of [['POST'], ['post'], { 0: 'POST' }, 1, true]) {
    const bad = { ...doc, applies_to: { ...doc.applies_to, http: [{ method, host: '*.example-bank.com' }] } };
    assert.throws(() => parsePolicy(JSON.stringify(bad), 'json'), /method must be a string/);
  }
  assert.throws(() => parsePolicy(POLICY_YAML.replace('method: "POST"', 'method: ["POST"]')), /method must be a string/);
  assert.equal(parsePolicy(POLICY_YAML.replace('method: "POST"', 'method: post')).applies_to.http[0].method, 'POST');
});

test('FUZZ-REG-4 a tool name or host with no String form (an object with no prototype) is decided, not thrown (found by this file, fixed in 0.15.0)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-fuzz-reg4-'));
  const g = createGuard({ policy: parsePolicy(POLICY_YAML), offline: true, cache: { dir } });
  const bare = Object.create(null);
  const d1 = await g.decideToolCall({ name: bare, arguments: { url: 'https://acme.com/' } });
  assert.equal(d1.decision, 'hold');
  assert.equal(d1.action.tool, '');
  const d2 = await g.decide({ tool: 'stripe.create_payout', host: bare });
  assert.equal(d2.decision, 'hold');
  assert.ok(d2.reasons.some((r) => r.code === 'NO_RECORD'));
  assert.equal(g.applies(bare), true, 'a name the guard cannot read as text is covered, toward checking');
  rmSync(dir, { recursive: true, force: true });
});

test('the whole file stays inside its time budget', () => {
  const seconds = (performance.now() - started) / 1000;
  console.log(`# fuzz: total ${Object.entries(counts).filter(([k]) => /:total$/.test(k)).reduce((a, [, v]) => a + v, 0)} cases in ${seconds.toFixed(1)} s`);
  assert.ok(seconds < 20, `${seconds.toFixed(1)} s, budget 20 s`);
});
