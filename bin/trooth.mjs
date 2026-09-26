#!/usr/bin/env node
// Trooth CLI. Command name: `trooth`
// Copyright 2025-2026 Trooth, LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file in this
// repository, or http://www.apache.org/licenses/LICENSE-2.0
//
// The Trooth Network is one public record per company: identity, products and demos,
// domain and marketing links, people, documents, security and privacy posture,
// procurement terms, relationships and sub-processors. Each fact is labeled with where
// it came from: witnessed, public record, attested or declared. Trooth signs one
// object, the witness statement for a reading it took; the rest of the profile is not
// signed. This CLI is the terminal interface to that record.
//
// Commands:
//   trooth check <domain>   Read a company's record from the public Trooth Network.
//                           Read-only. No key, no account. It sends one request to
//                           api.trooth.co with the domain you ask about in the URL,
//                           plus what every HTTPS request carries: your IP address and
//                           a user agent naming this CLI and its version.
//   trooth lint [path]      Read the infrastructure THIS repository declares and print
//                           the declared facts plus an aggregate digest of them.
//                           Fully local. Offline. Your source never leaves the machine.
//   trooth --help           Show help.   trooth --version  Show version.
//
// WHAT THIS TOOL DOES NOT DO, ON PURPOSE:
//   It does not grade, rate or rank a company or a repository.
//   It does not check anything against a named standard, framework or regulation.
//   It does not produce a verdict, a threshold result or a percentage.
//   It publishes facts and counts, reported apart, and never adds them into one number.
//
// Exit codes (stable, for scripts; 4 and 5 are new in 0.5.0):
//   0  ok                      (check: listed, and Trooth witnessed a reading;
//                               lint: a complete read of at least one declaration)
//   1  finding                 (check: not listed, or revoked; lint: nothing to read)
//   2  usage error             (missing argument, unknown flag or command, bad domain,
//                               path not found)
//   3  service or contract error (Trooth unreachable or too slow, a non-2xx other than
//                               the documented not-listed 404, a body that is not JSON
//                               or not the record asked for). Never an answer about a
//                               company.
//   4  incomplete read         (lint: a file was skipped, invalid or unreadable, or the
//                               walk was truncated; --allow-incomplete exits 0 instead)
//   5  listed, not witnessed   (check: the record is listed, but it carries no reading
//                               this CLI can confirm was witnessed)
//
// With --json, stdout carries exactly one JSON document and nothing else. Every
// diagnostic goes to stderr.

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { unitsOf, InvalidDeclaration, ENCRYPTION, encryptionState, regionsIn, credentialLiterals, opensToAnyAddress, markedPublic, referenceText } from './lib/declarations.mjs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { join, relative, extname, basename } from 'node:path';

const API = process.env.TROOTH_API || 'https://api.trooth.co';
const require = createRequire(import.meta.url);
let VERSION = '0.5.0';
try { VERSION = require('../package.json').version; } catch {}

const EXIT = { OK: 0, FINDING: 1, USAGE: 2, UPSTREAM: 3, INCOMPLETE: 4, NOT_WITNESSED: 5 };

// Color only when stdout is a TTY and NO_COLOR is unset, so piped output is clean.
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (useColor ? code : '');
const J = c('\x1b[32m'), D = c('\x1b[2m'), B = c('\x1b[1m'), R = c('\x1b[31m'), A = c('\x1b[33m'), C = c('\x1b[36m'), X = c('\x1b[0m');

const argv = process.argv.slice(2);
const cmd = argv[0];
const asJson = argv.includes('--json');

/* ------------------------------------------------------------- output ---- */

function out(s) { process.stdout.write(s + '\n'); }
function diag(s) { process.stderr.write(s + '\n'); }
function emitJson(obj) { out(JSON.stringify(obj, null, 2)); }

function fail(code, message, extra = {}) {
  diag(`${R}error${X} ${message}`);
  if (asJson) emitJson({ ok: false, error: message, exit: code, ...extra });
  process.exit(code);
}

/** Keys that would carry a score, tier, grade, rank, rating or percentage. Nothing
 *  under these names is ever printed, in any mode, no matter what an upstream feed
 *  sends. `rate` is matched only as a whole key so keys like generatedAt survive. */
const BANNED_KEY = /score|tier|grade|rank|rating|level|percent|^rate$/i;

function scrub(value) {
  if (Array.isArray(value)) return value.map(scrub);
  if (value && typeof value === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(value)) {
      if (BANNED_KEY.test(k)) continue;
      clean[k] = scrub(v);
    }
    return clean;
  }
  return value;
}

/* --------------------------------------------------------------- args ---- */

const FLAGS = {
  check: { bool: ['--json'], value: [] },
  lint:  { bool: ['--json', '--allow-incomplete'], value: [] },
};

/** Commands that existed in an earlier release and are gone. Naming them explicitly
 *  means an old README, an old CI job or an old blog post gets a sentence that says
 *  what happened, instead of "unknown command". */
const RETIRED = {
  scan: 'Trooth does not check infrastructure against a standard and does not issue a verdict. `trooth lint` reads what your infrastructure declares and prints those facts, locally.',
  eu:   'Trooth does not ingest regulation-specific evidence. Publish evidence on your company record at https://trooth.co/dashboard.',
  preflight: 'Retired. `trooth lint` reads declared infrastructure facts locally instead.',
};

function parseArgs(command) {
  const spec = FLAGS[command];
  const flags = {};
  const positional = [];
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { positional.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const [name, inlineVal] = a.split('=', 2);
      if (spec.bool.includes(name)) { flags[name] = true; continue; }
      if (spec.value.includes(name)) {
        const v = inlineVal !== undefined ? inlineVal : argv[++i];
        if (v === undefined || v.startsWith('--')) fail(EXIT.USAGE, `${name} needs a value.`);
        flags[name] = v; continue;
      }
      const known = [...spec.bool, ...spec.value];
      fail(EXIT.USAGE, `unknown flag ${name} for \`trooth ${command}\`. ` +
        (known.length ? `Known flags: ${known.join(', ')}.` : `\`trooth ${command}\` takes no flags.`) +
        ` Run \`trooth --help\`.`);
    } else if (a.startsWith('-') && a.length > 1) {
      fail(EXIT.USAGE, `unknown flag ${a} for \`trooth ${command}\`. Run \`trooth --help\`.`);
    } else {
      positional.push(a);
    }
  }
  return { flags, positional };
}

/* --------------------------------------------------------------- help ---- */

function helpText() {
  return `
${J}${B}trooth${X} ${D}v${VERSION} · the terminal interface to the Trooth Network${X}

${B}Usage${X}
  trooth check <domain>     Read a company's record on the Trooth Network
  trooth lint [path]        Read what your infrastructure declares, locally. Offline.
  trooth --help | --version

${B}Examples${X}
  trooth check stripe.com                ${D}# read a company's record${X}
  trooth check trooth.co --json          ${D}# one JSON document on stdout, for scripting${X}
  trooth lint ./infra                    ${D}# read declared facts, with a coverage report${X}
  trooth lint --json > trooth-lint.json  ${D}# the same facts as one JSON document, for a CI artifact${X}

${B}Flags${X}
  --json                    machine-readable JSON on stdout; diagnostics on stderr
  --allow-incomplete        lint: exit 0 even when a file was skipped, invalid or unreadable

${B}Exit codes${X}
  0 ok   1 not listed, or nothing declared   2 usage error   3 service or contract error
  4 lint read incomplete   5 listed, but no witnessed reading in the record

${D}check reads only public, already-published records. No key, no account. It sends
the domain you ask about to api.trooth.co in the request URL, with your IP address
and a user agent naming this CLI; see https://trooth.co/privacy for what is kept.
It does not check the record's signature.
lint is entirely local: it opens files, and opens no sockets. Your source never leaves.
Trooth publishes facts and counts, never one number that sums a company up.
Trooth signs what it witnessed. It never signs on a company's behalf.${X}
`;
}

/* -------------------------------------------------------------- fetch ---- */

// Every request is bounded: a deadline, a maximum body size, a JSON content
// type, and at most one retry, only for a connection failure or a 502, 503 or
// 504. Nothing here turns a failure into an answer about a company.
const TIMEOUT_MS = Math.max(1000, Number(process.env.TROOTH_TIMEOUT_MS) || 15000);
const MAX_BODY = 1024 * 1024;
const RETRYABLE = new Set([502, 503, 504]);

class Upstream extends Error {
  constructor(message, extra = {}) { super(message); this.extra = extra; }
}

async function readBounded(res) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > MAX_BODY) throw new Upstream(`the response is ${len} bytes, over the ${MAX_BODY}-byte limit`);
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY) { try { await reader.cancel(); } catch {} throw new Upstream(`the response passed the ${MAX_BODY}-byte limit`); }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/** GET one path. Returns { status, contentType, text }. Throws Upstream when the
 *  API cannot be reached, answers too slowly, or sends too much. */
async function getTrooth(path) {
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const res = await fetch(`${API}${path}`, {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { accept: 'application/json', 'user-agent': `trooth-cli/${VERSION}` },
      });
      if (RETRYABLE.has(res.status) && attempt === 1) { try { await res.body?.cancel(); } catch {} await new Promise((r) => setTimeout(r, 500)); continue; }
      const text = await readBounded(res);
      return { status: res.status, contentType: (res.headers.get('content-type') || '').toLowerCase(), text };
    } catch (e) {
      if (e instanceof Upstream) throw e;
      lastErr = e;
      const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
      if (timedOut) throw new Upstream(`the Trooth Network at ${API} did not answer within ${TIMEOUT_MS} ms`);
      if (attempt === 1) { await new Promise((r) => setTimeout(r, 500)); continue; }
    }
  }
  throw new Upstream(`could not reach the Trooth Network at ${API}: ${lastErr && lastErr.message ? lastErr.message : lastErr}`);
}

function parseJsonBody(r) {
  if (!/\bjson\b/.test(r.contentType)) throw new Upstream(`the Trooth Network answered HTTP ${r.status} with ${r.contentType || 'no content type'}, not JSON`, { http_status: r.status });
  try { return JSON.parse(r.text); }
  catch { throw new Upstream(`the Trooth Network answered HTTP ${r.status} with a body that is not valid JSON`, { http_status: r.status }); }
}

/* --------------------------------------------------------------- check ---- */

/**
 * The domain a user typed, as the one form the Trooth Network keys records by.
 * Accepts a bare domain or a URL. Parsed with the WHATWG URL parser, so case,
 * a trailing dot, the default port (80 or 443), a path, a query and an
 * internationalized name (to its ASCII form) all normalize the same way, and a
 * leading "www." is dropped. Returns { domain } or { error } for input that is
 * not one domain: credentials in a URL, a non-default port, an IP address, a
 * scheme other than http or https, or a name with no dot.
 */
function normalizeDomain(input) {
  const s = String(input || '').trim();
  if (!s) return { error: 'missing <domain>. Try: trooth check stripe.com' };
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`); }
  catch { return { error: `not a domain or URL: ${s}` }; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return { error: `not a web address: ${s}` };
  if (u.username || u.password) return { error: 'a URL with a user name or password is not accepted; pass the domain alone' };
  if (u.port) return { error: `port ${u.port} is not a default port; pass the domain alone` };
  let host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (/^\[.*\]$/.test(host) || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return { error: 'an IP address is not a company domain' };
  host = host.replace(/^www\./, '');
  if (!host.includes('.') || !/^[a-z0-9.-]+$/.test(host) || host.split('.').some((l) => !l || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) {
    return { error: `not a domain: ${s}` };
  }
  return { domain: host };
}
const sameDomain = (a, b) => { const x = normalizeDomain(a); return !!x.domain && x.domain === b; };

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return d.toISOString().slice(0, 10);
}

function count(obj) {
  if (!obj || typeof obj !== 'object') return null;
  const { passed, total } = obj;
  if (!Number.isInteger(passed) || !Number.isInteger(total) || passed < 0 || total < 0 || passed > total) return null;
  return { passed, total };
}

/** The two count lines, in the website's form ("65 read; 63 as expected"). */
function countLines(rec) {
  const lines = [];
  if (rec.probes) lines.push(`${B}Live probes:${X} ${rec.probes.total} read; ${rec.probes.passed} as expected`);
  if (rec.attested) lines.push(`${B}Self-attestations:${X} ${rec.attested.total} asked; ${rec.attested.passed} attested`);
  return lines;
}

/** The feed keeps the ledger oldest first. This returns the `n` most recent
 *  events, newest first, ordered by timestamp; events with the same timestamp,
 *  or none, keep the feed's order, later entries first. */
function latestEvents(events, n) {
  const t = (e) => { const v = Date.parse(e.at); return Number.isNaN(v) ? -Infinity : v; };
  return events
    .map((e, i) => ({ e, i }))
    .sort((a, b) => (t(b.e) - t(a.e)) || (b.i - a.i))
    .slice(0, n)
    .map(({ e }) => e);
}

/** Display names for the feed's event types. The type strings themselves are
 *  identifiers and are printed unchanged in --json. */
const EVENT_LABELS = {
  scan_completed: 'reading completed',
  standing_published: 'record published to the Trooth Network',
  rewitnessed: 'live probes re-read',
};
function eventLabel(type) {
  return Object.prototype.hasOwnProperty.call(EVENT_LABELS, type) ? EVENT_LABELS[type] : type.replace(/_/g, ' ');
}

/**
 * THE EVIDENCE STATE, decided from the record's own fields and never from a
 * matching name. A record that is listed is not therefore witnessed.
 *   listed_witnessed      a dated reading with at least one live probe read
 *   listed_not_witnessed  the record says so, or its reading read no probe
 *   listed_evidence_unknown  listed, with no reading this CLI can interpret
 *   revoked               the record says it was revoked or withdrawn
 * An explicit state in the record (`standing` or `evidence_state`) wins over
 * anything inferred from counts, and can only lower the state, never raise it.
 */
const STATE = Object.freeze({
  NOT_LISTED: 'not_listed',
  WITNESSED: 'listed_witnessed',
  NOT_WITNESSED: 'listed_not_witnessed',
  UNKNOWN: 'listed_evidence_unknown',
  REVOKED: 'revoked',
});
function evidenceState(v, probes) {
  const explicit = String(v.evidence_state ?? v.standing ?? v.state ?? '').toLowerCase();
  if (/revoked|withdrawn/.test(explicit)) return STATE.REVOKED;
  if (/not[_ -]?witnessed|unwitnessed|none/.test(explicit)) return STATE.NOT_WITNESSED;
  const dated = !!fmtDate(v.passed_at);
  if (probes && probes.total === 0) return STATE.NOT_WITNESSED;
  if (probes && probes.total > 0 && dated) return STATE.WITNESSED;
  return STATE.UNKNOWN;
}

/** A record, checked field by field. Throws Upstream when the body is not a
 *  directory record for this domain. */
function projectRecord(v, domain) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Upstream('the Trooth Network answered with something that is not a record');
  if (typeof v.error === 'string' && !v.domain) throw new Upstream(`the Trooth Network answered with an error: ${v.error.slice(0, 200)}`);
  if (typeof v.domain !== 'string' || !sameDomain(v.domain, domain)) throw new Upstream(`the Trooth Network answered with a record that is not the record for ${domain}`);
  const events = Array.isArray(v.events)
    ? v.events.filter((e) => e && typeof e.type === 'string').map((e) => ({ type: e.type, at: e.at, detail: e.detail }))
    : [];
  const probes = count(v.probes);
  const state = evidenceState(v, probes);
  const rec = {
    domain,
    listed: state !== STATE.REVOKED,
    state,
    company_name: typeof v.company_name === 'string' && v.company_name ? v.company_name : domain,
    witnessed_at: state === STATE.WITNESSED ? v.passed_at : null,
    first_published_at: fmtDate(v.first_published_at) ? v.first_published_at : null,
    badge_id: typeof v.badge_id === 'string' ? v.badge_id : null,
    probes,
    attested: count(v.attested),
    events,
    receipt_signature: typeof v.receipt_signature === 'string' ? v.receipt_signature : null,
    authority_key_id: typeof v.authority_key_id === 'string' ? v.authority_key_id : null,
    signature_checked: false,
    verify_keys: `${API}/public/keys`,
    verify_how: 'https://trooth.co/docs/verifiable-evidence',
    record_url: `https://trooth.co/network/${encodeURIComponent(domain)}`,
  };
  if (typeof v.category === 'string') rec.category = v.category;
  if (typeof v.description === 'string') rec.description = v.description;
  return scrub(rec);
}

/**
 * One company's record, from /directory/api/vendors/<domain>. That route
 * answers a domain it does not carry with a JSON 404 whose body says
 * `listed: false`; that is the only answer this CLI reads as "not listed".
 * Any other 404, any other status and any body that is not the record is a
 * service or contract error (exit 3), never a statement about the company.
 * 0.4.4 fell back to downloading the whole list on a plain-text 404; the
 * route has been served since 2026-09-26, and the fallback is gone.
 */
async function readVendor(domain) {
  const r = await getTrooth(`/directory/api/vendors/${encodeURIComponent(domain)}`);
  if (r.status === 404) {
    let body = null;
    try { body = JSON.parse(r.text); } catch {}
    if (body && typeof body === 'object' && body.listed === false && /\bjson\b/.test(r.contentType)) return null;
    throw new Upstream('the Trooth Network answered 404 without saying whether the domain is listed; this is a service error, not an answer about the company', { http_status: 404 });
  }
  if (r.status < 200 || r.status > 299) {
    throw new Upstream(`the Trooth Network answered HTTP ${r.status}.${r.text ? ' ' + r.text.slice(0, 200).replace(/\s+/g, ' ') : ''}`, { http_status: r.status });
  }
  return parseJsonBody(r);
}

const STATE_TEXT = {
  [STATE.WITNESSED]: `${J}listed; Trooth witnessed a reading${X}`,
  [STATE.NOT_WITNESSED]: `${A}listed; no reading witnessed${X}`,
  [STATE.UNKNOWN]: `${A}listed; the reading could not be read from this record${X}`,
  [STATE.REVOKED]: `${A}revoked${X}`,
};

async function check() {
  const { positional } = parseArgs('check');
  if (positional.length > 1) fail(EXIT.USAGE, `check takes one <domain>, got: ${positional.join(' ')}`);
  const norm = normalizeDomain(positional[0]);
  if (norm.error) fail(EXIT.USAGE, norm.error);
  const domain = norm.domain;

  let vendor, rec;
  try {
    vendor = await readVendor(domain);
    rec = vendor ? projectRecord(vendor, domain) : null;
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', ...e.extra });
    throw e;
  }

  if (!rec) {
    if (asJson) {
      emitJson({ domain, listed: false, state: STATE.NOT_LISTED, record_url: `https://trooth.co/network/${encodeURIComponent(domain)}` });
    } else {
      out(`\n${B}${domain}${X} ${D}//${X} ${A}not listed in the Trooth Network's public feed${X}`);
      out(`\n${D}The public feed carries no record for this domain. That says nothing about the`);
      out(`company: a domain that never listed, a listing Trooth has not published, and a`);
      out(`record that was revoked all read this way. A company gets a record by listing at`);
      out(`${X}${C}https://trooth.co/get-started${X}${D}: Trooth reads its public surface and publishes`);
      out(`a dated record that anyone, or any agent, can read.${X}\n`);
    }
    process.exit(EXIT.FINDING);
  }

  const code = rec.state === STATE.WITNESSED ? EXIT.OK : rec.state === STATE.REVOKED ? EXIT.FINDING : EXIT.NOT_WITNESSED;
  if (asJson) { emitJson(rec); process.exit(code); }

  const when = fmtDate(rec.witnessed_at);
  const since = fmtDate(rec.first_published_at);
  out(`\n${J}${B}Trooth Network${X} ${D}// public record · read-only //${X}`);
  out(`${B}${rec.company_name}${X}   ${C}${domain}${X}`);
  out(`Listing state: ${STATE_TEXT[rec.state]}` +
      (when ? `   ${D}reading dated ${when}${X}` : '') +
      (since ? `   ${D}first published ${since}${X}` : ''));

  // Two counts, never a ratio, in the form the website's record page uses.
  const counts = countLines(rec);
  if (counts.length) {
    out('');
    for (const l of counts) out(l);
    out(`${D}Live probes are readings Trooth took itself, from the company's public surface.`);
    out(`Self-attestations are what the company attested about itself; Trooth records them`);
    out(`and did not witness them. The two are reported apart and never added into one number.${X}`);
  }

  const ids = [];
  if (rec.badge_id) ids.push(`${D}Badge ${rec.badge_id}${X}`);
  if (rec.authority_key_id) ids.push(`${D}Key ${rec.authority_key_id}${X}`);
  if (ids.length) out(ids.join('   '));

  const latest = latestEvents(rec.events, 3);
  if (latest.length) {
    out(`\n${B}Latest ledger events, newest first${X}`);
    for (const e of latest) out(`  ${J}•${X} ${D}${fmtDate(e.at) || 'undated'}${X}  ${eventLabel(e.type)}`);
    out(`${D}  --json carries the whole ledger, with the feed's own wording for each event.${X}`);
  }

  out(`\n${D}This command did not check the record's signature. The signature covers the`);
  out(`reading, not every fact on the company's profile. To check it yourself:${X} ${C}${rec.verify_how}${X}`);
  out(`${D}A dated, point-in-time record. Trooth issues no verdict and no single number.`);
  out(`Full record: ${X}${C}${rec.record_url}${X}${D}   ·   Signing keys: ${rec.verify_keys}${X}\n`);
  process.exit(code);
}

/* ---------------------------------------------------------------- lint ---- */
/* WHAT lint IS, AND WHAT IT IS CAREFULLY NOT.
 *
 * It reads the infrastructure a repository DECLARES and reports those
 * declarations as counts: how many storage resources declare encryption, which
 * regions appear, how many rules declare exposure to the whole internet. It
 * does not judge them. There is no verdict, no threshold, no severity and no
 * rating, and nothing is checked against a named standard or regulation.
 * Declaring public ingress is not a failing; a load balancer is supposed to be
 * public. What the facts mean is the reader's decision.
 *
 * It opens files and opens no sockets. Nothing about the repository leaves the
 * machine.
 *
 * HOW EACH SOURCE IS READ. Every format is PARSED, and a file that does not
 * parse is reported as invalid, never as read:
 *   .tf                 HCL native syntax, by ./lib/hcl.mjs (comments dropped)
 *   .tf.json            JSON; each resource is one unit
 *   plan JSON           JSON (`terraform show -json`); each planned managed
 *                       resource is one unit
 *   Kubernetes YAML     YAML, by the `yaml` package; one unit per document
 *   Dockerfile          ENV and ARG settings only
 * Nothing is evaluated: variables, locals, modules and functions are not
 * resolved, and a setting that depends on one is reported as UNRESOLVED.
 *
 * COMPLETENESS. Every file the walk selects ends in exactly one bucket: read,
 * not applicable (a JSON or YAML file that is not a plan or a manifest),
 * excluded by a stated rule (a templated manifest), skipped (over the size
 * limit), invalid (did not parse) or unreadable (a permission or I/O error).
 * The walk itself can be truncated at MAX_FILES. A read with anything skipped,
 * invalid, unreadable or truncated is INCOMPLETE and exits 4 unless the caller
 * passes --allow-incomplete. */

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.terraform', '.next', 'dist', 'build', 'vendor',
  '.venv', 'venv', '__pycache__', '.cache', 'coverage', '.turbo',
]);
const MAX_FILES = Number(process.env.TROOTH_LINT_MAX_FILES) > 0 ? Number(process.env.TROOTH_LINT_MAX_FILES) : 5000;
const MAX_BYTES = 4 * 1024 * 1024;
const LIST_CAP = 50;

function selectedName(n) {
  const ext = extname(n);
  return ext === '.tf' || n.endsWith('.tf.json') || ext === '.yaml' || ext === '.yml' || ext === '.json' ||
    n === 'dockerfile' || n.startsWith('dockerfile.');
}

/** Depth first, entries sorted by name, so two runs over one tree visit files
 *  in the same order. */
function walk(root, cov) {
  const found = [];
  let st;
  try { st = statSync(root); } catch (e) { cov.unreadable.push({ path: root, reason: e.code || 'stat failed' }); return found; }
  if (st.isFile()) { cov.discovered++; if (selectedName(basename(root).toLowerCase())) found.push(root); else cov.not_applicable++; return found; }
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); }
    catch (e) { cov.unreadable.push({ path: dir, reason: e.code || 'directory could not be listed' }); continue; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const subdirs = [];
    for (const e of entries) {
      if (e.isDirectory()) { if (SKIP_DIRS.has(e.name)) cov.excluded_directories++; else subdirs.push(join(dir, e.name)); continue; }
      if (!e.isFile()) continue;
      cov.discovered++;
      if (!selectedName(e.name.toLowerCase())) continue;
      if (found.length >= MAX_FILES) { cov.truncated = true; return found; }
      found.push(join(dir, e.name));
    }
    for (let k = subdirs.length - 1; k >= 0; k--) stack.push(subdirs[k]);
  }
  return found;
}

function classify(file, text) {
  const n = basename(file).toLowerCase();
  if (n.endsWith('.tf.json')) return 'terraform-json';
  if (n.endsWith('.tf')) return 'terraform';
  if (n === 'dockerfile' || n.startsWith('dockerfile.')) return 'container';
  if (n.endsWith('.yaml') || n.endsWith('.yml')) {
    if (!(/^\s*apiVersion\s*:/m.test(text) && /^\s*kind\s*:/m.test(text))) return null;
    if (/\{\{[\s\S]*?\}\}/.test(text)) return 'templated';
    return 'kubernetes';
  }
  if (n.endsWith('.json')) {
    return /"terraform_version"\s*:/.test(text) &&
      (/"planned_values"\s*:/.test(text) || /"resource_changes"\s*:/.test(text)) ? 'terraform-plan' : null;
  }
  return null;
}

/** Canonical JSON: object keys sorted at every depth, so the digest depends on
 *  the facts and not on the order a walk happened to produce them. */
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v === undefined ? null : v);
}

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** A Terraform address (aws_s3_bucket.logs) inside another resource's values,
 *  and not inside a longer address such as aws_s3_bucket.logs2. */
const addressRef = (address) => new RegExp(`(?:^|[^\\w.])${escRe(address)}(?![\\w-])`);

// Classification runs on the resource type or kind, never on the text around it.
const STORAGE_TYPE = /(bucket|storage|blob|disk|volume|filestore|_db|database|rds|dynamodb|_sql|redis|memcache|elasticache|efs|fileshare|cosmos|bigtable|spanner)/i;
const LOGGING_TYPE = /(log|trail|audit|monitor|insight|diagnostic)/i;
const IDENTITY_TYPE = /(iam|role|policy|service_account|serviceaccount|rbac|identity|access_key|keyring|secret)/i;
// A storage-matching Terraform type that names a SETTING on a store rather than
// a store. A setting that declares encryption and refers to a store credits it.
const STORAGE_SETTING = /_(?:configuration|policy|acl|versioning|notification|public_access_block|ownership_controls|attachment|object|item|logging|iam_member|iam_binding|access_point|mount_target|snapshot|subnet_group|parameter_group|option_group)$/;
const isStorageSetting = (type) => type.includes('_') && STORAGE_SETTING.test(type);
const rel = (p) => { const r = relative(process.cwd(), p); return !r ? '.' : r.startsWith('..') ? p : r; };

function lint() {
  const { flags, positional } = parseArgs('lint');
  if (positional.length > 1) fail(EXIT.USAGE, `lint takes one optional [path], got: ${positional.join(' ')}`);
  const target = positional[0] || '.';
  if (!existsSync(target)) fail(EXIT.USAGE, `path not found: ${target}`);

  const cov = { discovered: 0, excluded_directories: 0, truncated: false, not_applicable: 0, excluded: [], skipped: [], invalid: [], unreadable: [] };
  const files = walk(target, cov);
  const byKind = { terraform: 0, 'terraform-plan': 0, kubernetes: 0, container: 0 };
  const regions = new Set();
  const resourceTypes = new Map();
  const stores = [];             // { address, planIds, state }
  const encryptingSettings = []; // reference text of settings that declare encryption
  let read = 0, logging = 0, identity = 0;
  let openIngress = 0, publicAccess = 0, inlineCredentials = 0;

  for (const f of files) {
    let text;
    try {
      const size = statSync(f).size;
      if (size > MAX_BYTES) { cov.skipped.push({ path: rel(f), reason: `larger than ${MAX_BYTES} bytes (${size})` }); continue; }
      text = readFileSync(f, 'utf8');
    } catch (e) { cov.unreadable.push({ path: rel(f), reason: e.code || 'read failed' }); continue; }
    const kind = classify(f, text);
    if (!kind) { cov.not_applicable++; continue; }
    if (kind === 'templated') { cov.excluded.push({ path: rel(f), reason: 'a templated manifest ({{ }}); render it first to read it' }); continue; }

    let units;
    try { units = unitsOf(kind, text); }
    catch (e) {
      if (e instanceof InvalidDeclaration) { cov.invalid.push({ path: rel(f), reason: e.message.slice(0, 200) }); continue; }
      throw e;
    }
    byKind[kind === 'terraform-json' ? 'terraform' : kind]++;
    read++;

    for (const u of units) {
      for (const r of regionsIn(u.tree)) regions.add(r);
      inlineCredentials += credentialLiterals(u.tree);
      if (opensToAnyAddress(u.tree)) openIngress++;
      if (markedPublic(u.tree)) publicAccess++;
      const t = u.type;
      if (!t) continue;
      if (u.typed) resourceTypes.set(t, (resourceTypes.get(t) || 0) + 1);
      if (STORAGE_TYPE.test(t)) {
        const state = encryptionState(u.tree);
        if (isStorageSetting(t)) { if (state === ENCRYPTION.TRUE) encryptingSettings.push(referenceText(u.tree)); }
        else {
          const planIds = u.plan ? ['bucket', 'id'].map((k) => u.tree && u.tree[k]).filter((x) => typeof x === 'string' && x.length >= 3) : [];
          stores.push({ address: u.address, planIds, state });
        }
      }
      if (LOGGING_TYPE.test(t)) logging++;
      if (IDENTITY_TYPE.test(t)) identity++;
    }
  }

  // A store with nothing declared in its own body is credited by a setting
  // resource, anywhere in the tree, that declares encryption and refers to it.
  for (const s of stores) {
    if (s.state !== ENCRYPTION.ABSENT) continue;
    const refs = [];
    if (s.address) refs.push(addressRef(s.address));
    for (const id of s.planIds) refs.push(new RegExp(`(?:^|\\n)${escRe(id)}(?:$|\\n)`));
    if (refs.some((re) => encryptingSettings.some((b) => re.test(b)))) s.state = ENCRYPTION.TRUE;
  }
  const byState = (st) => stores.filter((s) => s.state === st).length;

  const incomplete = cov.truncated || cov.skipped.length > 0 || cov.invalid.length > 0 || cov.unreadable.length > 0;
  const coverage = {
    completeness: incomplete ? 'incomplete' : 'complete',
    traversal: 'depth first, entries sorted by name',
    files_discovered: cov.discovered,
    files_selected: files.length,
    files_read: read,
    files_not_applicable: cov.not_applicable,
    files_excluded: cov.excluded.length,
    files_skipped: cov.skipped.length,
    files_invalid: cov.invalid.length,
    files_unreadable: cov.unreadable.length,
    directories_excluded: cov.excluded_directories,
    traversal_truncated: cov.truncated,
    limits: { max_files: MAX_FILES, max_bytes_per_file: MAX_BYTES },
  };
  const listed = (arr) => ({ entries: arr.slice(0, LIST_CAP), truncated: arr.length > LIST_CAP });
  const details = { excluded: listed(cov.excluded), skipped: listed(cov.skipped), invalid: listed(cov.invalid), unreadable: listed(cov.unreadable) };

  const exitFor = () => {
    if (incomplete && !flags['--allow-incomplete']) return EXIT.INCOMPLETE;
    return read === 0 ? EXIT.FINDING : EXIT.OK;
  };

  if (read === 0 && !incomplete) {
    const msg = `no infrastructure declarations found under ${target}.`;
    diag(`${A}nothing to read${X} ${msg}`);
    diag(`${D}  lint reads .tf, .tf.json, Kubernetes YAML (apiVersion + kind), terraform plan`);
    diag(`  JSON and Dockerfiles. ${files.length} file(s) were selected and none held a declaration.${X}`);
    if (asJson) emitJson({ ok: false, error: msg, exit: EXIT.FINDING, root: rel(target), files_opened: files.length, coverage, coverage_details: details });
    process.exit(EXIT.FINDING);
  }

  const topTypes = [...resourceTypes.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 12)
    .map(([type, n]) => ({ type, count: n }));

  const facts = {
    declarations_read: read,
    sources: Object.fromEntries(Object.entries(byKind).filter(([, n]) => n > 0)),
    regions_and_zones_declared: [...regions].sort(),
    resource_types: topTypes,
    storage_declarations: stores.length,
    storage_declaring_encryption: byState(ENCRYPTION.TRUE),
    storage_declaring_encryption_off: byState(ENCRYPTION.FALSE),
    storage_encryption_not_declared: byState(ENCRYPTION.ABSENT),
    storage_encryption_unresolved: byState(ENCRYPTION.UNRESOLVED),
    storage_encryption_unsupported: byState(ENCRYPTION.UNSUPPORTED),
    logging_declarations: logging,
    identity_declarations: identity,
    declarations_open_to_any_address: openIngress,
    declarations_marked_public: publicAccess,
    inline_credential_literals: inlineCredentials,
    completeness: coverage.completeness,
    files_selected: files.length,
    files_not_read: files.length - read - cov.not_applicable - cov.excluded.length,
  };

  const digest = `sha256:${createHash('sha256').update(canonical(facts)).digest('hex')}`;
  const doc = {
    tool: 'trooth-lint',
    schema: 'trooth-lint/2',
    cli_version: VERSION,
    observed_at: new Date().toISOString(),
    root: rel(target),
    facts,
    coverage,
    coverage_details: details,
    facts_digest: digest,
    digest,
    digest_scope: 'A SHA-256 over the facts object only, in canonical form. It is an aggregate: two different trees with the same counts share it. It does not identify file contents, a repository, a commit or a deployment. `digest` is the same value under its 0.4 name and will be removed in 0.6.',
    note: 'Declared facts only. Read locally; nothing was transmitted. No verdict and no assessment against any standard.',
  };

  const code = exitFor();
  if (asJson) { emitJson(doc); process.exit(code); }

  out(`\n${J}${B}trooth lint${X} ${D}// local · offline · declarations only //${X}`);
  out(`${D}${doc.root}   ${read} declaration file(s) read${X}`);
  const src = Object.entries(facts.sources).map(([k, n]) => `${k} ${n}`).join(' · ');
  if (src) out(`${D}${src}${X}`);

  out(`\n${B}Declared${X}`);
  const row = (label, value) => out(`  ${label.padEnd(40)} ${value}`);
  row('Regions and zones', facts.regions_and_zones_declared.length ? facts.regions_and_zones_declared.join(', ') : `${D}none declared${X}`);
  row('Storage declarations', `${facts.storage_declarations}`);
  row('  declaring encryption', `${facts.storage_declaring_encryption}`);
  row('  declaring encryption off', `${facts.storage_declaring_encryption_off}`);
  row('  declaring nothing about encryption', `${facts.storage_encryption_not_declared}`);
  row('  set by an unresolved expression', `${facts.storage_encryption_unresolved}`);
  if (facts.storage_encryption_unsupported) row('  set to a value lint does not read', `${facts.storage_encryption_unsupported}`);
  row('Logging declarations', `${facts.logging_declarations}`);
  row('Identity declarations', `${facts.identity_declarations}`);
  row('Open to any address (0.0.0.0/0, ::/0)', `${facts.declarations_open_to_any_address}`);
  row('Marked public', `${facts.declarations_marked_public}`);
  row('Inline credential literals', `${facts.inline_credential_literals}`);

  if (topTypes.length) {
    out(`\n${B}Most declared resource types${X}`);
    for (const t of topTypes.slice(0, 6)) out(`  ${String(t.count).padStart(4)}  ${D}${t.type}${X}`);
  }

  out(`\n${B}Coverage${X}  ${incomplete ? `${A}incomplete${X}` : `${J}complete${X}`}`);
  out(`${D}  ${coverage.files_selected} selected: ${read} read, ${coverage.files_not_applicable} not declarations, ${coverage.files_excluded} excluded, ${coverage.files_skipped} skipped, ${coverage.files_invalid} invalid, ${coverage.files_unreadable} unreadable${cov.truncated ? `; the walk stopped at ${MAX_FILES} files` : ''}.${X}`);
  for (const [label, arr] of [['skipped', cov.skipped], ['invalid', cov.invalid], ['unreadable', cov.unreadable], ['excluded', cov.excluded]]) {
    for (const e of arr.slice(0, 5)) out(`${D}  ${label}: ${e.path} (${e.reason})${X}`);
    if (arr.length > 5) out(`${D}  and ${arr.length - 5} more ${label}; --json lists up to ${LIST_CAP}.${X}`);
  }
  if (incomplete) out(`${D}  Exit code 4 says the read was incomplete. --allow-incomplete reports the same and exits 0.${X}`);

  out(`\n${B}Facts digest${X}  ${C}${doc.facts_digest}${X}`);
  out(`${D}A SHA-256 over the counts above, in canonical form. It is an aggregate: two different`);
  out(`trees with the same counts share it. It does not identify your files, your repository`);
  out(`or a deployment.${X}`);

  out(`\n${B}How this was read${X}`);
  out(`${D}  Every file is parsed; a file that does not parse is reported as invalid, not read.`);
  out(`  Comments count for nothing. Nothing is evaluated: a setting that depends on a variable,`);
  out(`  a local, a module or a function is reported as unresolved. Dockerfiles: ENV and ARG only.${X}`);

  out(`\n${D}Counts of what the files declare. Not a judgment: a public load balancer is`);
  out(`supposed to be public. Trooth issues no verdict here and checks nothing against`);
  out(`any standard. Nothing left this machine: lint opens files and opens no sockets.`);
  out(`Publish what you choose on your record at ${X}${C}https://trooth.co/dashboard${X}${D}.${X}\n`);
  process.exit(code);
}

/* ---------------------------------------------------------------- main ---- */

(async () => {
  if (cmd === '--version' || cmd === '-v' || cmd === 'version') { out(VERSION); return; }
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { out(helpText()); return; }
  if (cmd === 'check') return check();
  if (cmd === 'lint') return lint();
  if (Object.prototype.hasOwnProperty.call(RETIRED, cmd)) {
    fail(EXIT.USAGE, `\`trooth ${cmd}\` is retired. ${RETIRED[cmd]} Run \`trooth --help\`.`);
  }
  if (cmd.startsWith('-')) fail(EXIT.USAGE, `unknown flag ${cmd}. Run \`trooth --help\`.`);
  diag(helpText());
  fail(EXIT.USAGE, `unknown command: ${cmd}. Commands: check, lint.`);
})().catch((e) => {
  fail(EXIT.UPSTREAM, `unexpected failure: ${e && e.message ? e.message : e}`);
});
