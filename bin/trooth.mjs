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
//                           Read-only. No key, no account. It sends one request,
//                           GET https://trooth.co/api/network/profile?q=<domain>&contract=2,
//                           the one record projection the website, the REST API, the
//                           MCP connector and the llms.txt twin read, with the domain
//                           you ask about in the URL, plus what every HTTPS request
//                           carries: your IP address and a user agent naming this CLI
//                           and its version. Only when that projection cannot be
//                           reached does it send a second request, to api.trooth.co's
//                           directory route, and it labels that answer a fallback.
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
// Exit codes (stable, for scripts; 4 and 5 are new in 0.5.0, 6 in 0.6.0, 7 in 0.6.1):
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
//   6  withheld                (check: the record exists and is withheld while a report
//                               about it is reviewed; neither an absence nor a finding)
//   7  output not delivered    (new in 0.6.1: stdout or stderr failed or was closed, for
//                               example EPIPE from a reader that stopped early, before
//                               everything was written; the result was not delivered,
//                               whatever it would have been)
//
// With --json, stdout carries exactly one JSON document and nothing else. Every
// diagnostic goes to stderr.

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { unitsOf, InvalidDeclaration, ENCRYPTION, encryptionState, regionsIn, credentialLiterals, opensToAnyAddress, markedPublic, referenceText } from './lib/declarations.mjs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { join, relative, extname, basename, dirname } from 'node:path';

// The record projection, GET /api/network/profile, is served by the website:
// the same route the web page's machine twin, the REST API, the MCP connector
// and the llms.txt twin read. The directory route on api.trooth.co is read only
// as a labelled fallback when the projection cannot be reached.
const WEB = (process.env.TROOTH_WEB || 'https://trooth.co').replace(/\/+$/, '');
const API = (process.env.TROOTH_API || 'https://api.trooth.co').replace(/\/+$/, '');
/** The /api/network/profile contract this CLI is written to, pinned in every
 *  request so a deployment that stops serving it refuses with 400 instead of
 *  handing over a shape this code would misread. */
const PROJECTION_CONTRACT = 2;
const PROJECTION_SCHEMA = 'https://trooth.co/schemas/network-profile.v2.schema.json';
const require = createRequire(import.meta.url);
let VERSION = '0.6.1';
try { VERSION = require('../package.json').version; } catch {}

const EXIT = { OK: 0, FINDING: 1, USAGE: 2, UPSTREAM: 3, INCOMPLETE: 4, NOT_WITNESSED: 5, WITHHELD: 6, OUTPUT: 7 };

// Color only when stdout is a TTY and NO_COLOR is unset, so piped output is clean.
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (useColor ? code : '');
const J = c('\x1b[32m'), D = c('\x1b[2m'), B = c('\x1b[1m'), R = c('\x1b[31m'), A = c('\x1b[33m'), C = c('\x1b[36m'), X = c('\x1b[0m');

const argv = process.argv.slice(2);
const cmd = argv[0];
const asJson = argv.includes('--json');

/* ------------------------------------------------------------- output ---- */

// THE OUTPUT BOUNDARY (O04). Up to 0.6.0 a command wrote its document and
// called process.exit at once. When stdout is a pipe the write is queued, and
// a forced exit drops whatever is still queued, so a reader could get the
// first 64 KiB of a JSON document with exit 0. Now nothing calls
// process.exit. A command RETURNS its exit code (fail() throws one) to the
// dispatcher at the bottom of this file, which waits until every write has
// been handed to the operating system, then sets process.exitCode and lets
// Node end on its own.
//
// A write that fails (EPIPE when the reader stopped early, EBADF, ENOSPC)
// is caught here: nothing more is written to that stream, a short note goes to
// the other stream when it still works, and the exit code is 7, never the
// command's own code, so a partial document can never pass for a delivered one.
const pendingWrites = new Set();
let outputFailure = null;
function noteOutputFailure(name, err) {
  if (outputFailure) return;
  outputFailure = { stream: name, code: (err && err.code) || 'write failed' };
}
for (const [name, stream] of [['stdout', process.stdout], ['stderr', process.stderr]]) {
  stream.on('error', (err) => noteOutputFailure(name, err));
}
function write(name, stream, s) {
  if (outputFailure) return;
  const done = new Promise((resolve) => {
    try {
      stream.write(s, (err) => { if (err) noteOutputFailure(name, err); resolve(); });
    } catch (err) { noteOutputFailure(name, err); resolve(); }
  });
  pendingWrites.add(done);
  done.then(() => pendingWrites.delete(done));
}
/** Resolves when every write so far has been flushed or has failed. A failed
 *  or closed stream also resolves it, so a reader that went away cannot hold
 *  the process open. */
async function drainOutput() {
  while (pendingWrites.size && !outputFailure) {
    const closed = new Promise((resolve) => {
      const fire = () => resolve();
      for (const st of [process.stdout, process.stderr]) { st.once('close', fire); st.once('error', fire); }
    });
    await Promise.race([Promise.all([...pendingWrites]), closed]);
  }
}
function out(s) { write('stdout', process.stdout, s + '\n'); }
function diag(s) { write('stderr', process.stderr, s + '\n'); }
function emitJson(obj) { out(JSON.stringify(obj, null, 2)); }

/** Thrown to end a command with an exit code; caught only by the dispatcher. */
class ExitWith {
  constructor(code) { this.code = code; }
}

function fail(code, message, extra = {}) {
  diag(`${R}error${X} ${message}`);
  if (asJson) emitJson({ ok: false, error: message, exit: code, ...extra });
  throw new ExitWith(code);
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
  check: { bool: ['--json', '--no-fallback'], value: [] },
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
  --no-fallback             check: exit 3 when the record projection cannot be reached,
                            instead of reading the directory feed as a labelled fallback

${B}Exit codes${X}
  0 ok   1 not listed, or nothing declared   2 usage error   3 service or contract error
  4 lint read incomplete   5 listed, but no witnessed reading in the record   6 withheld
  7 output not delivered: stdout or stderr failed or closed before everything was written

${D}check reads only public, already-published records. No key, no account. It reads
the one record projection, trooth.co/api/network/profile, the same body the website,
the API and the MCP connector read, and sends the domain you ask about in the request
URL, with your IP address and a user agent naming this CLI; see
https://trooth.co/privacy for what is kept. When that projection cannot be reached it
reads api.trooth.co's directory feed instead and says so. It checks no signature.
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
// The record projection is bounded at 2 MiB by the server before it is sent
// (PROFILE_RESPONSE_MAX_BYTES in the web route's output guard), so the CLI
// accepts exactly that much from it. The directory route keeps 1 MiB.
const MAX_BODY_PROJECTION = 2 * 1024 * 1024;
const MAX_BODY_DIRECTORY = 1024 * 1024;
const RETRYABLE = new Set([502, 503, 504]);

class Upstream extends Error {
  /** `unreachable` is set only when no answer came back at all (a connection
   *  failure or the deadline), or the answer was a 5xx: the cases in which
   *  `check` may fall back from the record projection to the directory route. */
  constructor(message, extra = {}, unreachable = false) { super(message); this.extra = extra; this.unreachable = unreachable; }
}

async function readBounded(res, maxBody) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > maxBody) throw new Upstream(`the response is ${len} bytes, over the ${maxBody}-byte limit`);
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBody) { try { await reader.cancel(); } catch {} throw new Upstream(`the response passed the ${maxBody}-byte limit`); }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/** GET one path from one base. Returns { status, contentType, headers, text }.
 *  Throws Upstream when the server cannot be reached, answers too slowly, or
 *  sends too much. */
async function getFrom(base, path, maxBody) {
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const res = await fetch(`${base}${path}`, {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { accept: 'application/json', 'user-agent': `trooth-cli/${VERSION}` },
      });
      if (RETRYABLE.has(res.status) && attempt === 1) { try { await res.body?.cancel(); } catch {} await new Promise((r) => setTimeout(r, 500)); continue; }
      const text = await readBounded(res, maxBody);
      return { status: res.status, contentType: (res.headers.get('content-type') || '').toLowerCase(), headers: res.headers, text };
    } catch (e) {
      if (e instanceof Upstream) throw e;
      lastErr = e;
      const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
      if (timedOut) throw new Upstream(`the Trooth Network at ${base} did not answer within ${TIMEOUT_MS} ms`, {}, true);
      if (attempt === 1) { await new Promise((r) => setTimeout(r, 500)); continue; }
    }
  }
  throw new Upstream(`could not reach the Trooth Network at ${base}: ${lastErr && lastErr.message ? lastErr.message : lastErr}`, {}, true);
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
  WITHHELD: 'withheld',
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
 * FALLBACK ONLY. One company's entry in the directory feed, from
 * /directory/api/vendors/<domain> on api.trooth.co. Up to 0.5.1 this was the
 * only thing `check` read. Since 0.6.0 it is read only when the record
 * projection could not be reached, and everything printed from it says so.
 * That route answers a domain it does not carry with a JSON 404 whose body
 * says `listed: false`; that is the only answer read as "not listed". Any
 * other 404, any other status and any body that is not the record is a
 * service or contract error (exit 3), never a statement about the company.
 */
async function readDirectory(domain) {
  const r = await getFrom(API, `/directory/api/vendors/${encodeURIComponent(domain)}`, MAX_BODY_DIRECTORY);
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

/* ------------------------------------------------------ the projection ---- */

/**
 * THE ONE PUBLIC RECORD PROJECTION. GET {TROOTH_WEB}/api/network/profile
 * ?q=<domain>&contract=2 is the evidence envelope the website, the REST API,
 * the MCP connector and the llms.txt twin all read: one body, shaped in one
 * place, validated against the published schema before it is sent. `check`
 * reads that body and carries it whole under `record` in --json, so a script
 * reading the CLI sees the same facts, the same provenance on each fact and
 * the same record version as a script reading the API.
 *
 * Answers, and what each means here:
 *   200 found:true, contract 2, this domain   the record (exit 0 or 5)
 *   200 found:true, withheld:true             withheld pending review (exit 6)
 *   200 found:false                           no published record (exit 1)
 *   200 found:false, ambiguous:true           not possible for a domain; a
 *                                             contract error (exit 3)
 *   5xx, a connection failure, the deadline   unreachable: the labelled
 *                                             fallback to the directory route,
 *                                             unless --no-fallback (exit 3)
 *   any other status or body                  a contract error (exit 3)
 */
async function readProjection(domain) {
  const url = `${WEB}/api/network/profile?q=${encodeURIComponent(domain)}&contract=${PROJECTION_CONTRACT}`;
  const r = await getFrom(WEB, `/api/network/profile?q=${encodeURIComponent(domain)}&contract=${PROJECTION_CONTRACT}`, MAX_BODY_PROJECTION);
  if (r.status >= 500) {
    throw new Upstream(`the record projection answered HTTP ${r.status}.${r.text ? ' ' + r.text.slice(0, 200).replace(/\s+/g, ' ') : ''}`, { http_status: r.status }, true);
  }
  if (r.status < 200 || r.status > 299) {
    throw new Upstream(`the record projection answered HTTP ${r.status}.${r.text ? ' ' + r.text.slice(0, 200).replace(/\s+/g, ' ') : ''}`, { http_status: r.status });
  }
  const body = parseJsonBody(r);
  const header = (n) => String(r.headers.get(n) || '');
  const versionHeader = Number(header('trooth-record-version'));
  const digest = (v) => (/^sha-256=[0-9a-f]{64}$/.test(v) ? v : null);
  const source = {
    surface: 'record_projection',
    fallback: false,
    url,
    contract_version: null,
    contract_schema: null,
    // WHICH VERSION OF THE RECORD THIS IS, exactly as the projection states
    // it in Trooth-Record-Version and Trooth-Record-Digest, the same two
    // values the MCP connector copies into evidence.record_version and
    // evidence.record_digest. null when the server did not state one; never
    // guessed.
    record_version: Number.isInteger(versionHeader) && versionHeader >= 1 ? versionHeader : null,
    record_digest: digest(header('trooth-record-digest')),
    record_previous_digest: digest(header('trooth-record-previous-digest')),
    // The record's own version stamp, the value every fact's
    // record.recordVersion carries.
    record_updated_at: null,
  };
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Upstream('the record projection answered with something that is not a record');
  if (body.found === false && body.ambiguous === true) throw new Upstream('the record projection answered a domain as an ambiguous name; a domain names one record, so this is a contract error');
  if (body.found === false) return { kind: 'absent', source };
  if (body.found !== true) throw new Upstream('the record projection answered without saying whether a record was found');
  if (body.withheld === true) {
    return { kind: 'withheld', source, slug: typeof body.slug === 'string' ? body.slug : null, name: typeof body.name === 'string' ? body.name : null, reason: String(body.reason ?? '').slice(0, 400), since: typeof body.since === 'string' ? body.since : null };
  }
  if (Number(body.contractVersion) !== PROJECTION_CONTRACT) throw new Upstream(`the record projection answered contract ${body.contractVersion}; this CLI reads contract ${PROJECTION_CONTRACT}`);
  if (typeof body.slug !== 'string' || !body.slug) throw new Upstream('the record projection answered a record with no slug');
  if (typeof body.domain !== 'string' || !sameDomain(body.domain, domain)) throw new Upstream(`the record projection answered with a record that is not the record for ${domain}`);
  if (!Array.isArray(body.facts)) throw new Upstream('the record projection answered a record with no facts list');
  source.contract_version = PROJECTION_CONTRACT;
  source.contract_schema = typeof body.contractSchema === 'string' ? body.contractSchema : PROJECTION_SCHEMA;
  source.record_updated_at = typeof body.updatedAt === 'string' ? body.updatedAt : null;
  return { kind: 'found', source, body };
}

/** The projection's coverage block, read field by field, or null. */
function projectionCoverage(cov) {
  if (!cov || typeof cov !== 'object') return null;
  const n = (v) => (Number.isInteger(v) && v >= 0 ? v : null);
  const run = n(cov.checksRun), passed = n(cov.checksPassed);
  if (run === null || passed === null || passed > run) return null;
  return {
    source: cov.source === 'witness_statement' ? 'witness_statement' : 'result_tally',
    checks_run: run,
    checks_as_expected: passed,
    checks_not_read: n(cov.checksNotRead),
    checks_in_reading: n(cov.checksInReading),
  };
}

/** The CLI's summary of a projection body, with the body itself under
 *  `record`. The summary is derived; `record` is the projection verbatim
 *  (less any key the scrub drops, of which contract 2 has none). */
function fromProjection(read, domain) {
  const p = read.body;
  const w = p.witnessed && typeof p.witnessed === 'object' ? p.witnessed : {};
  const witnessed = w.standing === 'witnessed';
  const coverage = witnessed ? projectionCoverage(w.coverage) : null;
  const signing = p.signing && typeof p.signing === 'object' ? p.signing : {};
  const keyId = typeof signing.keyId === 'string' ? signing.keyId : null;
  return scrub({
    domain,
    listed: true,
    state: witnessed ? STATE.WITNESSED : STATE.NOT_WITNESSED,
    company_name: typeof p.name === 'string' && p.name ? p.name : domain,
    slug: p.slug,
    witnessed_at: witnessed && fmtDate(w.lastWitnessed) ? w.lastWitnessed : null,
    first_witnessed_at: witnessed && fmtDate(w.firstWitnessedAt) ? w.firstWitnessedAt : null,
    coverage,
    // 0.5 field names, kept for scripts: `probes` is the same reading's counts
    // in the directory feed's form, and `authority_key_id` the signing key.
    probes: coverage ? { passed: coverage.checks_as_expected, total: coverage.checks_run } : null,
    authority_key_id: keyId,
    facts_published: p.facts.length,
    facts_contested: Array.isArray(p.conflicts) ? p.conflicts.length : 0,
    signature_checked: false,
    verify_keys: typeof signing.keys === 'string' ? signing.keys : `${API}/public/keys`,
    verify_how: typeof signing.verify === 'string' ? signing.verify : 'https://trooth.co/docs/verifiable-evidence',
    record_url: typeof p.canonicalUrl === 'string' ? p.canonicalUrl : `https://trooth.co/network/company/${encodeURIComponent(p.slug)}`,
    source: read.source,
    record: p,
  });
}

const STATE_TEXT = {
  [STATE.WITNESSED]: `${J}listed; Trooth witnessed a reading${X}`,
  [STATE.NOT_WITNESSED]: `${A}listed; no reading witnessed${X}`,
  [STATE.UNKNOWN]: `${A}listed; the reading could not be read from this record${X}`,
  [STATE.REVOKED]: `${A}revoked${X}`,
};

function printNotListed(domain, source) {
  if (asJson) {
    emitJson({ domain, listed: false, state: STATE.NOT_LISTED, record_url: `https://trooth.co/network/${encodeURIComponent(domain)}`, source });
    return;
  }
  if (source.fallback) for (const l of fallbackLines(source)) out(l);
  const where = source.fallback ? "in the Trooth Network's directory feed (fallback read)" : 'on the Trooth Network';
  out(`\n${B}${domain}${X} ${D}//${X} ${A}no published record ${where}${X}`);
  out(`\n${D}${source.fallback ? 'The directory feed carries no record for this domain.' : 'The record projection carries no published record for this domain.'}`);
  out(`That says nothing about the company: a domain that never listed, a record not yet`);
  out(`published, and a record that was revoked all read this way. A company gets a record`);
  out(`by listing at ${X}${C}https://trooth.co/get-started${X}${D}: Trooth reads its public surface and`);
  out(`publishes a dated record that anyone, or any agent, can read.${X}\n`);
}

/** The fallback label, printed before anything read from the directory route. */
function fallbackLines(source) {
  return [
    `${A}${B}FALLBACK READ.${X} ${A}The record projection at ${WEB} could not be reached: ${source.projection_error}${X}`,
    `${D}What follows is the directory feed at ${API}, not the record. It carries the listing and`,
    `witness fields only: no facts, no per-fact provenance and no record version.`,
    `Run with --no-fallback to treat an unreachable projection as an error (exit 3).${X}`,
  ];
}

function printProjection(rec) {
  const p = rec.record;
  const when = fmtDate(rec.witnessed_at);
  const since = fmtDate(rec.first_witnessed_at);
  out(`\n${J}${B}Trooth Network${X} ${D}// public record · read-only //${X}`);
  out(`${B}${rec.company_name}${X}   ${C}${rec.domain}${X}`);
  out(`Listing state: ${STATE_TEXT[rec.state]}` +
      (when ? `   ${D}last witnessed ${when}${X}` : '') +
      (since ? `   ${D}first witnessed ${since}${X}` : ''));
  const s = rec.source;
  out(`${D}Record version: ${s.record_version !== null ? `${s.record_version}${s.record_digest ? ` (${s.record_digest})` : ''}` : 'not stated on this read'}` +
      `${s.record_updated_at ? `   updated ${fmtDate(s.record_updated_at)}` : ''}   contract ${s.contract_version}${X}`);
  out(`${D}Read from the record projection: ${s.url}${X}`);

  if (rec.state === STATE.WITNESSED) {
    const cov = rec.coverage;
    out('');
    if (cov && cov.source === 'witness_statement' && cov.checks_not_read !== null) {
      out(`${B}Last reading:${X} ${cov.checks_run} checks read; ${cov.checks_as_expected} as expected; ${cov.checks_not_read} listed but not read` +
          (cov.checks_in_reading !== null ? ` (${cov.checks_in_reading} in all)` : ''));
      out(`${D}From Trooth's signed witness statement for that reading. Coverage of a public surface, not an audit opinion.${X}`);
    } else if (cov) {
      out(`${B}Last reading:${X} its own tally records ${cov.checks_as_expected} of ${cov.checks_run} entries as expected`);
      out(`${D}This reading carries no signed witness statement. The tally includes self-attestations and`);
      out(`outcomes carried from earlier readings, so it is not a count of checks read.${X}`);
    } else {
      out(`${D}Witnessed by Trooth. The reading's counts were not published on this read.${X}`);
    }
    const c = p.witnessed && p.witnessed.continuity;
    if (c && c.unbrokenSince) {
      out(`${D}Readings unbroken since ${fmtDate(c.unbrokenSince)}: ${Number(c.unbrokenReadings) || 0} in the unbroken run, ${Number(c.totalReadings) || 0} on record.${X}`);
    }
  } else {
    out(`\n${D}Nothing witnessed by Trooth is published on this record yet. What it carries is the`);
    out(`company's own declaration; the missing witnessed evidence is an absence, not a finding.${X}`);
  }

  // Every fact the record publishes, under its category, each with the label
  // of who stated or observed it: the same rows the record page renders.
  const facts = Array.isArray(p.facts) ? p.facts : [];
  if (facts.length) {
    out(`\n${B}Facts published: ${facts.length}${X}${D}, each labelled with who stated or observed it${X}`);
    let cat = null;
    for (const f of facts) {
      if (f.category !== cat) { cat = f.category; out(`${B}${cat}${X}`); }
      out(`  ${f.label}: ${f.value}   ${D}[${f.origin}]${X}`);
    }
    if (rec.facts_contested) out(`${D}${rec.facts_contested} with more than one account on record. No account is preferred; --json carries each one.${X}`);
  }

  const ws = p.witnessStatement && typeof p.witnessStatement.payload === 'string' ? p.witnessStatement : null;
  out('');
  out(ws
    ? `${D}What is signed: only the witness statement for the last reading (key ${ws.key_id}). It covers that`
      + `\nreading's checks and counts. The profile, its facts and the company's text are not signed.${X}`
    : `${D}What is signed: nothing in this record. The profile is not signed, and the last reading`
      + `\ncarries no witness statement.${X}`);
  out(`${D}This command did not check any signature. To check it yourself:${X} ${C}${rec.verify_how}${X}`);
  out(`${D}A dated, point-in-time record. Trooth issues no verdict and no single number.`);
  out(`Full record: ${X}${C}${rec.record_url}${X}${D}   ·   Signing keys: ${rec.verify_keys}${X}\n`);
}

function printDirectory(rec) {
  for (const l of fallbackLines(rec.source)) out(l);
  const when = fmtDate(rec.witnessed_at);
  const since = fmtDate(rec.first_published_at);
  out(`\n${J}${B}Trooth Network${X} ${D}// directory feed, fallback · read-only //${X}`);
  out(`${B}${rec.company_name}${X}   ${C}${rec.domain}${X}`);
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
}

async function check() {
  const { flags, positional } = parseArgs('check');
  if (positional.length > 1) fail(EXIT.USAGE, `check takes one <domain>, got: ${positional.join(' ')}`);
  const norm = normalizeDomain(positional[0]);
  if (norm.error) fail(EXIT.USAGE, norm.error);
  const domain = norm.domain;

  let read;
  try {
    read = await readProjection(domain);
  } catch (e) {
    if (!(e instanceof Upstream)) throw e;
    if (!e.unreachable || flags['--no-fallback']) {
      fail(EXIT.UPSTREAM, e.message, { state: 'service_error', source: { surface: 'record_projection', fallback: false }, ...e.extra });
    }
    diag(`${A}fallback${X} the record projection at ${WEB} could not be reached (${e.message}); reading the directory feed at ${API} instead. It carries no facts and no record version.`);
    read = { kind: 'fallback', projectionError: e.message };
  }

  if (read.kind === 'absent') { printNotListed(domain, read.source); return EXIT.FINDING; }

  if (read.kind === 'withheld') {
    const doc = { domain, listed: true, state: STATE.WITHHELD, company_name: read.name || domain, slug: read.slug, reason: read.reason, since: read.since, source: read.source };
    if (asJson) emitJson(scrub(doc));
    else {
      out(`\n${B}${doc.company_name}${X}   ${C}${domain}${X}`);
      out(`Listing state: ${A}withheld${X}${read.since ? `   ${D}since ${fmtDate(read.since)}${X}` : ''}`);
      out(`\n${D}The record exists and is withheld while a report about it is reviewed. That is not`);
      out(`an absence and not a finding. Trooth's own words:${X} ${read.reason}\n`);
    }
    return EXIT.WITHHELD;
  }

  if (read.kind === 'found') {
    const rec = fromProjection(read, domain);
    const code = rec.state === STATE.WITNESSED ? EXIT.OK : EXIT.NOT_WITNESSED;
    if (asJson) emitJson(rec); else printProjection(rec);
    return code;
  }

  // The labelled fallback: the directory route, which carries no record version.
  const source = {
    surface: 'directory_fallback',
    fallback: true,
    url: `${API}/directory/api/vendors/${encodeURIComponent(domain)}`,
    projection_error: read.projectionError,
    contract_version: null,
    contract_schema: null,
    record_version: null,
    record_digest: null,
    record_previous_digest: null,
    record_updated_at: null,
  };
  let rec;
  try {
    const vendor = await readDirectory(domain);
    if (!vendor) { printNotListed(domain, source); return EXIT.FINDING; }
    rec = { ...projectRecord(vendor, domain), source };
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', source, ...e.extra });
    throw e;
  }
  const code = rec.state === STATE.WITNESSED ? EXIT.OK : rec.state === STATE.REVOKED ? EXIT.FINDING : EXIT.NOT_WITNESSED;
  if (asJson) { emitJson(rec); return code; }
  printDirectory(rec);
  return code;
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
 *   Dockerfile          ENV and ARG settings only, from logical lines formed
 *                       as the build forms them (continuations, comments,
 *                       the escape directive)
 * Nothing is evaluated: variables, locals, modules and functions are not
 * resolved, and a setting that depends on one is reported as UNRESOLVED. A
 * plan value Terraform marks unknown until apply is UNRESOLVED too. A shape
 * the format does not allow at a declaration boundary (a List without an
 * items array, a resource that is not an object, a repeated attribute) makes
 * the file invalid, never an empty or complete read.
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
    // Recognition happens after parsing (lib/declarations.mjs), so flow style
    // and quoted keys are read like block style. Here only the cheap test: a
    // file that never mentions apiVersion and kind in any spelling is not a
    // manifest, and a templated manifest is excluded with its reason.
    if (!(/apiVersion/.test(text) && /kind/.test(text))) return null;
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

/** The scope a reference resolves in (T15). A Terraform module is a folder, so
 *  a .tf or .tf.json resource is resolved only against resources in its own
 *  folder; two roots that both name aws_s3_bucket.shared are two buckets. A
 *  plan is one scope per file and module path (module.a.module.b). Nothing is
 *  resolved across a module output or between roots. */
function scopeOf(kind, file, address) {
  if (kind === 'terraform' || kind === 'terraform-json') return `dir:${dirname(rel(file))}`;
  if (kind === 'terraform-plan') {
    const mod = String(address || '').match(/^((?:module\.[^.[\]]+(?:\[[^\]]*\])?\.)*)/);
    return `plan:${rel(file)}:${mod ? mod[1] : ''}`;
  }
  return `file:${rel(file)}`;
}
/** A plan address without its module path, for matching inside that scope. */
const localAddress = (a) => String(a || '').replace(/^(?:module\.[^.[\]]+(?:\[[^\]]*\])?\.)+/, '');

function lint() {
  const { flags, positional } = parseArgs('lint');
  if (positional.length > 1) fail(EXIT.USAGE, `lint takes one optional [path], got: ${positional.join(' ')}`);
  const target = positional[0] || '.';
  if (!existsSync(target)) fail(EXIT.USAGE, `path not found: ${target}`);

  const cov = { discovered: 0, excluded_directories: 0, truncated: false, not_applicable: 0, excluded: [], skipped: [], invalid: [], unreadable: [], list_members_not_read: [] };
  const files = walk(target, cov);
  const byKind = { terraform: 0, 'terraform-plan': 0, kubernetes: 0, container: 0 };
  const regions = new Set();
  const resourceTypes = new Map();
  const stores = [];             // { address, planIds, state, scope }
  const encryptingSettings = []; // { scope, text } of settings that declare encryption
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
      // Every parser failure, including a safely refused YAML alias expansion,
      // is reported against its own file and the read continues (T19). Only a
      // fault in lint itself escapes, and that is exit 3, not a coverage fact.
      if (e instanceof InvalidDeclaration) { cov.invalid.push({ path: rel(f), reason: e.message.slice(0, 200) }); continue; }
      throw e;
    }
    if (units.notApplicable) { cov.not_applicable++; continue; }
    if (units.membersNotRead) cov.list_members_not_read.push({ path: rel(f), reason: `${units.membersNotRead} List member(s) with no apiVersion and kind were not read` });
    byKind[kind === 'terraform-json' ? 'terraform' : kind]++;
    read++;

    for (const u of units) {
      for (const r of regionsIn(u.tree)) regions.add(r);
      inlineCredentials += credentialLiterals(u);
      if (opensToAnyAddress(u.tree)) openIngress++;
      if (markedPublic(u.tree)) publicAccess++;
      const t = u.type;
      if (!t) continue;
      if (u.typed) resourceTypes.set(t, (resourceTypes.get(t) || 0) + 1);
      if (STORAGE_TYPE.test(t)) {
        const state = encryptionState(u.tree);
        const scope = scopeOf(kind, f, u.address);
        if (isStorageSetting(t)) { if (state === ENCRYPTION.TRUE) encryptingSettings.push({ scope, text: referenceText(u.tree) }); }
        else {
          const planIds = u.plan ? ['bucket', 'id'].map((k) => u.tree && u.tree[k]).filter((x) => typeof x === 'string' && x.length >= 3) : [];
          stores.push({ address: u.plan ? localAddress(u.address) : u.address, planIds, state, scope });
        }
      }
      if (LOGGING_TYPE.test(t)) logging++;
      if (IDENTITY_TYPE.test(t)) identity++;
    }
  }

  // A store with nothing declared in its own body is credited by a setting
  // resource IN ITS OWN SCOPE that declares encryption and refers to it (T15).
  for (const s of stores) {
    if (s.state !== ENCRYPTION.ABSENT) continue;
    const refs = [];
    if (s.address) refs.push(addressRef(s.address));
    for (const id of s.planIds) refs.push(new RegExp(`(?:^|\\n)${escRe(id)}(?:$|\\n)`));
    const settings = encryptingSettings.filter((b) => b.scope === s.scope);
    if (refs.some((re) => settings.some((b) => re.test(b.text)))) s.state = ENCRYPTION.TRUE;
  }
  const byState = (st) => stores.filter((s) => s.state === st).length;

  const incomplete = cov.truncated || cov.skipped.length > 0 || cov.invalid.length > 0 || cov.unreadable.length > 0 || cov.list_members_not_read.length > 0;
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
    list_members_not_read: cov.list_members_not_read.reduce((a, x) => a + Number(x.reason.match(/^\d+/)[0]), 0),
    directories_excluded: cov.excluded_directories,
    traversal_truncated: cov.truncated,
    limits: { max_files: MAX_FILES, max_bytes_per_file: MAX_BYTES },
  };
  const listed = (arr) => ({ entries: arr.slice(0, LIST_CAP), truncated: arr.length > LIST_CAP });
  const details = { excluded: listed(cov.excluded), skipped: listed(cov.skipped), invalid: listed(cov.invalid), unreadable: listed(cov.unreadable), list_members_not_read: listed(cov.list_members_not_read) };

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
    return EXIT.FINDING;
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
    digest_scope: 'A SHA-256 over the facts object only, in canonical form. It is an aggregate: two different trees with the same counts share it. It does not identify file contents, a repository, a commit or a deployment. `digest` is the same value under its 0.4 name and will be removed in 0.7.',
    note: 'Declared facts only. Read locally; nothing was transmitted. No verdict and no assessment against any standard.',
  };

  const code = exitFor();
  if (asJson) { emitJson(doc); return code; }

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
  return code;
}

/* ---------------------------------------------------------------- main ---- */

async function main() {
  if (cmd === '--version' || cmd === '-v' || cmd === 'version') { out(VERSION); return EXIT.OK; }
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { out(helpText()); return EXIT.OK; }
  if (cmd === 'check') return check();
  if (cmd === 'lint') return lint();
  if (Object.prototype.hasOwnProperty.call(RETIRED, cmd)) {
    fail(EXIT.USAGE, `\`trooth ${cmd}\` is retired. ${RETIRED[cmd]} Run \`trooth --help\`.`);
  }
  if (cmd.startsWith('-')) fail(EXIT.USAGE, `unknown flag ${cmd}. Run \`trooth --help\`.`);
  diag(helpText());
  fail(EXIT.USAGE, `unknown command: ${cmd}. Commands: check, lint.`);
}

/** The one place the exit status is decided. The command's code stands only
 *  when every byte it wrote was delivered; otherwise the status is 7. */
async function dispatch() {
  let code;
  try {
    code = await main();
  } catch (e) {
    if (e instanceof ExitWith) code = e.code;
    else {
      try { fail(EXIT.UPSTREAM, `unexpected failure: ${e && e.message ? e.message : e}`); }
      catch (x) { code = x instanceof ExitWith ? x.code : EXIT.UPSTREAM; }
    }
  }
  if (!Number.isInteger(code)) code = EXIT.UPSTREAM;
  await drainOutput();
  if (outputFailure) {
    // Best effort, on the stream that did not fail; never retried.
    const other = outputFailure.stream === 'stdout' ? process.stderr : process.stdout;
    if (!other.destroyed && other.writable) {
      try { other.write(`error output not delivered: ${outputFailure.stream} failed (${outputFailure.code}) before everything was written. Exit 7.\n`, () => {}); } catch {}
    }
    process.exitCode = EXIT.OUTPUT;
    return;
  }
  process.exitCode = code;
}

dispatch();
