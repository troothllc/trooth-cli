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
//   trooth verify <domain>  Check the record's signed witness statement yourself: the
//                           Ed25519 signature over the exact payload bytes, the key's
//                           lifecycle on api.trooth.co/public/keys, the domain it was
//                           signed for, the count identities, and for v2 the sha256 of
//                           the exact check mapping and of the evidence manifest. It
//                           trusts no summary from Trooth. --file reads a saved
//                           statement; --offline with --keys sends nothing at all.
//                           --save-bundle writes every input to one portable file;
//                           --bundle checks such a file with no network at all.
//                           Statements v1, v2 and v3 (RFC 8785 bytes) are checked.
//                           The rules are in docs/VERIFY.md; tests/vectors/ holds the
//                           cases any other implementation must agree on.
//   trooth log checkpoint   Read and check the signed checkpoint of Trooth's witness
//                           statement log (docs/LOG.md). trooth log monitor --state
//                           <file> checks the log only grew since the checkpoint saved
//                           in <file>, and saves the new one. Anyone can run a monitor.
//                           Both count the cosignatures of the pinned witnesses;
//                           --witnesses <n> requires n of them. trooth log receipt
//                           <index> fetches and checks an entry's RFC 9942 COSE receipt.
//   trooth public-record <domain>
//                           What the company has published outside its own site,
//                           read by Trooth from the authorities that hold it: its SEC
//                           filer record, filings (10-K, 10-Q, 8-K items, proxy),
//                           annual XBRL values, its LEI record, DNS mail
//                           authentication, certificates in CT logs, security.txt,
//                           the OFAC list, and the evidence tying each identifier to
//                           the domain. The statement naming the reading's SHA-256 is
//                           checked: its signature, its key, and its log entry.
//                           docs/EVIDENCE.md. --cik, --lei, --ticker name the
//                           identifier when the site does not.
//   trooth guard decide|hook|ci|cache
//                           The pre-execution guardrail (docs/GUARD.md): allow, hold or
//                           deny one action an agent is about to take, under the
//                           customer's written policy, from Trooth's signed and logged
//                           artifacts checked on this machine. Only the domain is sent
//                           to Trooth; the action never is. `hook` is a Claude Code
//                           PreToolUse hook; `ci` fails a build that adds a destination
//                           the policy does not list; `cache` saves bundles for offline use.
//   trooth declare init|sign|check
//                           The domain-signed declaration (docs/DECLARATION.md): make
//                           an Ed25519 key kept on this machine, sign the document a
//                           company publishes at https://<domain>/.well-known/trooth.json
//                           (its key, products, APIs and repositories), and check one,
//                           read from the site (no redirects, 64 KB at most) or a file,
//                           with the optional key pin at _trooth-key.<domain> read over
//                           DNS over HTTPS. Nothing secret is printed.
//   trooth --help           Show help.   trooth --version  Show version.
//
// WHAT THIS TOOL DOES NOT DO, ON PURPOSE:
//   It does not grade, rate or rank a company or a repository.
//   It does not check anything against a named standard, framework or regulation.
//   It does not produce a verdict, a threshold result or a percentage.
//   It publishes facts and counts, reported apart, and never adds them into one number.
//
// Exit codes (stable, for scripts; 4 and 5 are new in 0.5.0, 6 in 0.6.0, 7 in 0.6.1, 8 and 9 in 0.7.0, 10 in 0.9.0):
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
//   8  not trusted             (new in 0.7.0, verify: the statement is malformed, its
//                               signature does not check, or its key is not trusted)
//   9  mismatch                (new in 0.7.0, verify: the signature checks, but the domain,
//                               the check mapping, the evidence manifest or the signed
//                               counts do not match what was signed; since 0.9.0 also a
//                               log receipt that does not check, and `log monitor` when
//                               the log is not an extension of the saved checkpoint)
//  10  superseded              (new in 0.9.0, verify: everything held, and a correction
//                               Trooth signed and logged withdraws or replaces the statement)
//  11  expired                 (new in 0.14.0, declare check: the declaration checks in every
//                               other way, and its expires_at has passed)
//   declare check also uses 0 (it checks), 1 (the site answers 404 or 410: no declaration),
//   3 (the site or DNS could not be read), 8 (the signature does not check, or its kid is
//   not one of the keys) and 9 (any other rule fails: wrong domain, a URL on another host,
//   more than 400 days, oversize, not JSON, a redirect; or the DNS pin names another key).
//   declare init and sign use 0 and 2 (including a refusal to overwrite a file).
//   verify also uses 4 (a mapping or manifest was not supplied, so the binding is only
//   partially checked) and 5 (the record carries no signed statement).
//  20  guard hold              (new with trooth guard, guard decide: route the action to a person)
//  21  guard deny              (new with trooth guard, guard decide: a proof or an absolute rule failed)
//  22  guard ci finding        (new with trooth guard, guard ci: the change adds a destination host the
//                               policy's destinations.allowed does not list)
//   guard hook uses Claude Code's codes instead: 0 (allow, or ask with the hook JSON on stdout),
//   2 (deny, or any failure: the hook never fails open). guard cache uses 0, 1 and 3.
//
// With --json, stdout carries exactly one JSON document and nothing else. Every
// diagnostic goes to stderr.

import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync } from 'node:fs';
import { unitsOf, InvalidDeclaration, ENCRYPTION, encryptionState, regionsIn, credentialLiterals, opensToAnyAddress, markedPublic, referenceText } from './lib/declarations.mjs';
import { createHash } from 'node:crypto';
import { verifyStatement, bundleInputs, makeBundle, BundleError } from './lib/verify.mjs';
import { openCheckpoint, verifyConsistency, verifyNote, fromB64, toB64, parseVkey, checkReceipt, LOG_ORIGIN } from './lib/tlog.mjs';
import { PINNED_LOG_VKEYS, PINNED_WITNESSES, HARDWARE_LOG_VKEY } from './lib/log-trust.mjs';
import { checkCosignatures } from './lib/witness.mjs';
import { checkCoseReceipt, keysFromKeySet } from './lib/cose.mjs';
import { canonicalize, canonicalizeRecord, isCanonical } from './lib/jcs.mjs';
import { keyTrust, keyBytes } from './lib/verify.mjs';
import { statementId } from './lib/ids.mjs';
import { hashTool, manifestOf, diffTools, listTools } from './lib/mcp-tools.mjs';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { loadPolicy as loadGuardPolicy, createGuard, PolicyError } from './lib/guard.mjs';
import { addedLines, scanLines } from './lib/guard-ci.mjs';
import { generateDeclarationKey, readPrivateJwk, publicJwkOf, buildDeclaration, checkDeclaration, fetchDeclaration, readKeyPin, pinStatus, pinLine, isSignatureProblem, DeclarationError, DECLARATION_PATH, MAX_VALIDITY_DAYS, DEFAULT_VALIDITY_DAYS, DOH_URL, keyIdFor, jwkThumbprint } from './lib/declaration.mjs';
import { ID_TYPES } from './lib/ids.mjs';
import { homedir } from 'node:os';
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
let VERSION = '0.11.0';
try { VERSION = require('../package.json').version; } catch {}

const EXIT = { OK: 0, FINDING: 1, USAGE: 2, UPSTREAM: 3, INCOMPLETE: 4, NOT_WITNESSED: 5, WITHHELD: 6, OUTPUT: 7, NOT_TRUSTED: 8, MISMATCH: 9, SUPERSEDED: 10, EXPIRED: 11, GUARD_HOLD: 20, GUARD_DENY: 21, GUARD_CI_FOUND: 22 };

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
  verify: { bool: ['--json', '--offline', '--no-log'], value: ['--file', '--keys', '--mapping', '--manifest', '--bundle', '--save-bundle', '--log-vkey'] },
  log: { bool: ['--json'], value: ['--state', '--log-vkey', '--witnesses', '--out'] },
  'public-record': { bool: ['--json'], value: ['--cik', '--lei', '--ticker', '--log-vkey'] },
  'mcp-tools': { bool: ['--json', '--live'], value: ['--log-vkey'] },
  declare: { bool: ['--json', '--no-dns'], value: ['--domain', '--key', '--record', '--days', '--out', '--file'], multi: ['--product', '--api', '--repo', '--add-key'] },
  guard: { bool: ['--json', '--offline'], value: ['--policy', '--tool', '--host', '--args', '--cache', '--max-age', '--base', '--log-vkey', '--timeout-ms'], multi: ['--witness'] },
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
      if (spec.value.includes(name) || (spec.multi || []).includes(name)) {
        const v = inlineVal !== undefined ? inlineVal : argv[++i];
        if (v === undefined || v.startsWith('--')) fail(EXIT.USAGE, `${name} needs a value.`);
        if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
        else flags[name] = v;
        continue;
      }
      const known = [...spec.bool, ...spec.value, ...(spec.multi || [])];
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
  trooth verify <domain>    Check the record's signed witness statement yourself
  trooth log checkpoint     Read and check the witness statement log's signed checkpoint
  trooth log monitor --state <file>   Check the log only grew since the checkpoint in <file>
  trooth log receipt <index>  Fetch and check the COSE receipt (RFC 9942) for one log entry
  trooth public-record <domain>  What the company published to regulators and registries, signed
  trooth mcp-tools [endpoint]  The MCP servers whose tool lists Trooth logs, or one server's tool hashes
  trooth guard decide --policy <file> --tool <name> [--host <host>] [--args <json>]
                            Allow, hold or deny one action under your policy, checked locally
  trooth guard hook --policy <file>   Claude Code PreToolUse hook (reads the hook JSON on stdin)
  trooth guard ci --policy <file> [--base <ref>] [paths...]   Fail a build that adds an unlisted destination
  trooth guard cache --policy <file> --cache <dir> <domain>...   Save signed bundles for offline decisions
  trooth declare init --domain <d> [--key <path>]   Make the Ed25519 key for your domain's declaration
  trooth declare sign --domain <d> --key <path> --out <file>   Sign /.well-known/trooth.json
  trooth declare check <domain> | --file <path>   Check a domain's signed declaration and its DNS pin
  trooth --help | --version

${B}Examples${X}
  trooth check stripe.com                ${D}# read a company's record${X}
  trooth check trooth.co --json          ${D}# one JSON document on stdout, for scripting${X}
  trooth lint ./infra                    ${D}# read declared facts, with a coverage report${X}
  trooth lint --json > trooth-lint.json  ${D}# the same facts as one JSON document, for a CI artifact${X}
  trooth verify trooth.co                ${D}# check the signature, key, domain and bindings locally${X}
  trooth verify --file saved.json --offline --keys keys.json --mapping 1.0.1.json
  trooth verify trooth.co --save-bundle trooth.co.bundle.json   ${D}# keep every input in one file${X}
  trooth verify --bundle trooth.co.bundle.json                  ${D}# check it later, with no network${X}
  trooth mcp-tools https://api.trooth.co/public/mcp --live      ${D}# has the server changed its tools since Trooth logged them?${X}

${B}Flags${X}
  --json                    machine-readable JSON on stdout; diagnostics on stderr
  --allow-incomplete        lint: exit 0 even when a file was skipped, invalid or unreadable
  --no-fallback             check: exit 3 when the record projection cannot be reached,
                            instead of reading the directory feed as a labelled fallback
  --file <path>             verify: a saved profile, statement, or {statement, manifest}
  --keys <path>             verify: a saved copy of api.trooth.co/public/keys
  --mapping <path>          verify: the exact check mapping document the statement names
  --manifest <path>         verify: the evidence manifest (a JSON list)
  --offline                 verify: send nothing; needs --file and --keys
  --save-bundle <path>      verify: also write the statement, manifest, key list and exact
                            mapping bytes to one file (refuses to overwrite)
  --bundle <path>           verify: check a saved bundle; sends nothing
  --no-log                  verify: do not ask the witness statement log
  --log-vkey <key>          verify, log, public-record, mcp-tools: check checkpoints against this log key, not the pinned one
  --state <path>            log monitor: the last checkpoint seen; written when the log only grew
  --witnesses <n>           log checkpoint, log monitor: require cosignatures from n pinned witnesses
  --out <path>              log receipt: write the COSE receipt bytes to a new file
  --cik, --lei, --ticker    public-record: name the SEC filer or LEI to read for the domain
  --live                    mcp-tools: also read the server's tool list from this machine and compare
  --policy <file>           guard: the policy (YAML subset or JSON; docs/GUARD.md)
  --tool, --host, --args    guard decide: the tool name, the target host, the typed arguments as JSON
                            (with --args and no --host, the host is read from the policy's host_from fields)
  --cache <dir>             guard: the bundle cache; --max-age <seconds> its freshness (default 900)
  --offline                 guard decide, hook: read only cached bundles; none means hold
  --base <ref>              guard ci: compare HEAD with this ref (default origin/main)
  --witness <vkey>          guard: a witness cosigner key to count, in place of the pinned ones (repeatable)
  --domain, --key           declare: the domain, and the private JWK (init default ~/.trooth/declaration-key/<domain>.jwk)
  --product id=name=url     declare sign: a product (repeatable); --api base_url[,mcp_url,manifest_sha256],
                            --repo <url>, --add-key <jwk> (a second key, for rotation) repeat too
  --record <url>, --days N  declare sign: the company's Trooth record; validity in days (default 365, at most 400)
  --file <path>, --no-dns   declare check: check a saved file; do not read the _trooth-key TXT pin

${B}Exit codes${X}
  0 ok   1 not listed, or nothing declared   2 usage error   3 service or contract error
  4 lint read incomplete; mcp-tools --live: the server could not be read   5 listed, but no witnessed reading in the record   6 withheld
  7 output not delivered: stdout or stderr failed or closed before everything was written
  8 verify: signature does not check, or the key is not trusted
  9 verify: signature checks, but the domain, mapping, manifest, counts or log proof do not match
    log monitor: the log is not an extension of the checkpoint in --state
    log: fewer pinned witnesses cosigned than --witnesses asks; a COSE receipt does not check
    public-record: the record is not the one its statement names, or its log receipt does not check
    mcp-tools: a hash, the statement or its receipt does not match; with --live, the server lists other tools now
  8 also: public-record, mcp-tools: the statement's signature or key does not hold
  10 verify: a correction Trooth signed and logged withdraws or replaces the statement
  11 declare check: the declaration expired; 8 its signature or key does not hold; 9 another rule fails
     or the DNS pin names another key; 1 the site publishes none; 3 the site or DNS could not be read
  20 guard decide: hold (route the action to a person)   21 guard decide: deny
  22 guard ci: the change adds a destination host the policy does not list
     guard hook follows Claude Code instead: 0 allow or ask (the JSON on stdout says which), 2 deny
     or any failure, with the reason on stderr. guard cache: 0 all saved, 1 a domain has no record, 3 unreachable.

${D}check reads only public, already-published records. No key, no account. It reads
the one record projection, trooth.co/api/network/profile, the same body the website,
the API and the MCP connector read, and sends the domain you ask about in the request
URL, with your IP address and a user agent naming this CLI; see
https://trooth.co/privacy for what is kept. When that projection cannot be reached it
reads api.trooth.co's directory feed instead and says so. check reads; verify checks
the witness statement Trooth signed, on your machine; public-record checks the
signed statement that names its reading, the same way.
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
  out(`${D}This command did not check any signature. To check it yourself:${X} ${C}trooth verify ${rec.domain}${X}${D} (how it works: ${rec.verify_how})${X}`);
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
  out(`reading, not every fact on the company's profile. To check it yourself:${X} ${C}trooth verify ${rec.domain}${X}${D} (how it works: ${rec.verify_how})${X}`);
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

/* -------------------------------------------------------------- verify ---- */

/** GET exact bytes (a mapping document must be hashed as published, not re-encoded). */
async function getBytes(url, maxBody) {
  let res;
  try {
    res = await fetch(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(TIMEOUT_MS), headers: { 'user-agent': `trooth-cli/${VERSION}` } });
  } catch (e) {
    throw new Upstream(`could not read ${url}: ${e && e.message ? e.message : e}`, {}, true);
  }
  if (res.status < 200 || res.status > 299) throw new Upstream(`${url} answered HTTP ${res.status}`, { http_status: res.status });
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > maxBody) throw new Upstream(`${url} is ${len} bytes, over the ${maxBody}-byte limit`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBody) throw new Upstream(`${url} passed the ${maxBody}-byte limit`);
  return buf;
}

function readJsonFile(path, what) {
  if (!existsSync(path)) fail(EXIT.USAGE, `${what} not found: ${path}`);
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (e) { fail(EXIT.USAGE, `${what} is not valid JSON: ${path}`); }
}

/** A saved file may be a whole profile, {statement, manifest}, or a bare statement. */
function statementFrom(doc) {
  if (doc && typeof doc === 'object') {
    if (doc.witnessStatement) return { statement: doc.witnessStatement, manifest: Array.isArray(doc.witnessEvidenceManifest) ? doc.witnessEvidenceManifest : undefined, domain: typeof doc.domain === 'string' ? doc.domain : undefined };
    if (doc.statement && typeof doc.statement === 'object') return { statement: doc.statement, manifest: Array.isArray(doc.manifest) ? doc.manifest : undefined, domain: undefined };
    if (typeof doc.payload === 'string') return { statement: doc, manifest: undefined, domain: undefined };
  }
  return null;
}

const MAPPING_PREFIX = `${WEB}/standard/check-mapping/`;
const MAX_BODY_SMALL = 1024 * 1024;

async function verifyCmd() {
  const { flags, positional } = parseArgs('verify');
  if (positional.length > 1) fail(EXIT.USAGE, `verify takes at most one <domain>, got: ${positional.join(' ')}`);
  if (flags['--log-vkey']) { try { parseVkey(flags['--log-vkey']); } catch (e) { fail(EXIT.USAGE, `--log-vkey: ${e.message}`); } }
  if (flags['--bundle']) {
    for (const f of ['--file', '--keys', '--mapping', '--manifest', '--save-bundle']) if (flags[f]) fail(EXIT.USAGE, `--bundle carries every input; it cannot be combined with ${f}.`);
  }
  if (flags['--save-bundle'] && existsSync(flags['--save-bundle'])) fail(EXIT.USAGE, `--save-bundle will not overwrite ${flags['--save-bundle']}; choose a new path.`);
  const offline = !!flags['--offline'] || !!flags['--bundle'];
  if (offline && !flags['--file'] && !flags['--bundle']) fail(EXIT.USAGE, '--offline needs --file: with no network there is no record to read.');
  if (offline && !flags['--bundle'] && !flags['--keys']) fail(EXIT.USAGE, '--offline needs --keys: a saved copy of https://api.trooth.co/public/keys.');
  let domain;
  if (positional[0]) {
    const norm = normalizeDomain(positional[0]);
    if (norm.error) fail(EXIT.USAGE, norm.error.replace('trooth check', 'trooth verify'));
    domain = norm.domain;
  }
  if (!domain && !flags['--file'] && !flags['--bundle']) fail(EXIT.USAGE, 'missing <domain>. Try: trooth verify trooth.co');

  if (flags['--bundle']) {
    let i;
    try { i = bundleInputs(readJsonFile(flags['--bundle'], 'the bundle')); }
    catch (e) { if (e instanceof BundleError) fail(EXIT.USAGE, `${flags['--bundle']}: ${e.message}.`); throw e; }
    if (!domain && i.domain) domain = normalizeDomain(i.domain).domain;
    const p = flags['--bundle'];
    let log;
    if (i.log && !flags['--no-log']) {
      const pinned = logVkeys(flags);
      log = { ...i.log, vkeys: pinned.vkeys.length ? pinned.vkeys : i.log.vkeys, vkey_source: pinned.vkeys.length ? pinned.source : 'carried in the bundle (not pinned)' };
    }
    return reportVerify({ statement: i.statement, keys: i.keys, keysReadAt: i.keysReadAt, mappingBytes: i.mappingBytes, manifest: i.manifest, domain, log, sources: { statement: p, keys: p, mapping: i.mappingBytes === undefined ? null : p, manifest: i.manifest ? p : null, log: log ? p : null } });
  }

  const sources = { statement: null, keys: null, mapping: null, manifest: null };
  let found;
  try {
    if (flags['--file']) {
      found = statementFrom(readJsonFile(flags['--file'], 'the statement file'));
      if (!found) fail(EXIT.USAGE, `${flags['--file']} holds no witness statement (expected a profile, {statement, manifest} or a statement with a payload).`);
      sources.statement = flags['--file'];
      if (!domain && found.domain) domain = normalizeDomain(found.domain).domain;
    } else {
      const read = await readProjection(domain);
      if (read.kind === 'absent') { printNotListed(domain, read.source); return EXIT.FINDING; }
      if (read.kind === 'withheld') fail(EXIT.WITHHELD, `the record for ${domain} is withheld while a report about it is reviewed.`, { state: 'withheld' });
      if (!read.body.witnessStatement) {
        const doc = { domain, verdict: 'no_statement', note: 'The record is listed but carries no signed witness statement; there is nothing to check.' };
        if (asJson) emitJson(doc); else out(`${B}${domain}${X}  ${A}no signed witness statement in this record${X}\n${D}Nothing to check: the record is listed, but Trooth has not published a signed reading for it.${X}`);
        return EXIT.NOT_WITNESSED;
      }
      found = { statement: read.body.witnessStatement, manifest: Array.isArray(read.body.witnessEvidenceManifest) ? read.body.witnessEvidenceManifest : undefined };
      sources.statement = read.source.url;
    }

    let keys, keysReadAt = null;
    if (flags['--keys']) {
      const k = readJsonFile(flags['--keys'], 'the key list');
      keys = Array.isArray(k) ? k : k.keys;
      keysReadAt = Array.isArray(k) ? null : (k.list_read_at || null);
      sources.keys = flags['--keys'];
    } else {
      const r = await getFrom(API, '/public/keys', MAX_BODY_SMALL);
      if (r.status !== 200) throw new Upstream(`api.trooth.co/public/keys answered HTTP ${r.status}`, { http_status: r.status });
      const k = parseJsonBody(r);
      keys = k.keys; keysReadAt = k.list_read_at || new Date().toISOString();
      sources.keys = `${API}/public/keys`;
    }
    if (!Array.isArray(keys)) fail(EXIT.USAGE, 'the key list has no keys array.');

    let manifest = found.manifest;
    if (flags['--manifest']) { manifest = readJsonFile(flags['--manifest'], 'the manifest'); sources.manifest = flags['--manifest']; }
    else if (manifest) sources.manifest = sources.statement;

    let mappingBytes;
    let payload = null;
    try { payload = JSON.parse(String(found.statement.payload)); } catch {}
    const mappingUrl = payload?.methodology?.mapping_url;
    if (flags['--mapping']) {
      if (!existsSync(flags['--mapping'])) fail(EXIT.USAGE, `the mapping file not found: ${flags['--mapping']}`);
      mappingBytes = readFileSync(flags['--mapping']);
      sources.mapping = flags['--mapping'];
    } else if (!offline && typeof mappingUrl === 'string' && mappingUrl.startsWith(MAPPING_PREFIX) && /\.json$/.test(mappingUrl)) {
      mappingBytes = await getBytes(mappingUrl, MAX_BODY_SMALL);
      sources.mapping = mappingUrl;
    }

    let log;
    if (!offline && !flags['--no-log'] && typeof found.statement?.payload === 'string') {
      log = await readLog(found.statement.payload, flags);
      sources.log = `${LOG_BASE}/lookup`;
    }

    if (flags['--save-bundle']) {
      const b = makeBundle({ domain, statement: found.statement, manifest, keys, keysReadAt, keysSource: sources.keys, mappingUrl: sources.mapping, mappingBytes, log: log && !log.unavailable ? { vkey: log.vkeys[0], receipt: log.receipt, corrections: log.corrections } : undefined });
      try { writeFileSync(flags['--save-bundle'], JSON.stringify(b, null, 2) + '\n', { flag: 'wx' }); }
      catch (e) { fail(EXIT.USAGE, `could not write the bundle to ${flags['--save-bundle']}: ${e && e.code ? e.code : e}`); }
      sources.bundle_written = flags['--save-bundle'];
    }
    return reportVerify({ statement: found.statement, keys, keysReadAt, mappingBytes, manifest, domain, log, sources });
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', ...e.extra });
    throw e;
  }
}

function reportVerify({ statement, keys, keysReadAt, mappingBytes, manifest, domain, log, sources }) {
  let payload = null;
  try { payload = JSON.parse(String(statement.payload)); } catch {}
  const r = verifyStatement({ statement, keys, mappingBytes, manifest, domain, log });
  const doc = { domain: domain ?? r.subject.signed, verdict: r.verdict, version: r.version, read_at: r.read_at, reading_id: r.reading_id, statement_id: r.statement_id, signature: r.signature, key: r.key, subject: r.subject, binding: r.binding, counts: r.counts, ...(r.log ? { log: { ...r.log, vkey_source: log?.vkey_source ?? null } } : {}), assurance: r.assurance, keys_read_at: keysReadAt, sources };
  if (asJson) emitJson(doc);
  else printVerify(doc, payload);
  return { checked: EXIT.OK, checked_v1: EXIT.OK, partially_checked: EXIT.INCOMPLETE, signature_not_trusted: EXIT.NOT_TRUSTED, mismatch: EXIT.MISMATCH, superseded: EXIT.SUPERSEDED }[r.verdict] ?? EXIT.UPSTREAM;
}

/* -------------------------------------------------------- public-record ---- */

const PUBLIC_RECORD_STATEMENT = 'trooth.public-record.v1';

async function publicRecordCmd() {
  const { flags, positional } = parseArgs('public-record');
  if (positional.length !== 1) fail(EXIT.USAGE, 'trooth public-record takes one <domain>. Try: trooth public-record apple.com');
  const norm = normalizeDomain(positional[0]);
  if (norm.error) fail(EXIT.USAGE, norm.error.replace('trooth check', 'trooth public-record'));
  const domain = norm.domain;
  const q = new URLSearchParams();
  if (flags['--cik'] !== undefined) { if (!/^\d{1,10}$/.test(flags['--cik'])) fail(EXIT.USAGE, '--cik is the SEC Central Index Key, 1 to 10 digits.'); q.set('cik', flags['--cik']); }
  if (flags['--lei'] !== undefined) { if (!/^[A-Za-z0-9]{20}$/.test(flags['--lei'])) fail(EXIT.USAGE, '--lei is a 20-character Legal Entity Identifier.'); q.set('lei', flags['--lei'].toUpperCase()); }
  if (flags['--ticker'] !== undefined) { if (!/^[A-Za-z][A-Za-z0-9.-]{0,9}$/.test(flags['--ticker'])) fail(EXIT.USAGE, '--ticker is 1 to 10 letters, digits, dots or dashes.'); q.set('ticker', flags['--ticker'].toUpperCase()); }
  try {
    const qs = q.toString();
    const r = await getFrom(API, `/scan/public-record/${encodeURIComponent(domain)}${qs ? `?${qs}` : ''}`, MAX_BODY_SMALL);
    if (r.status === 429 || r.status === 400) {
      let why = `HTTP ${r.status}`; try { why = JSON.parse(r.text).error || why; } catch {}
      fail(r.status === 400 ? EXIT.USAGE : EXIT.UPSTREAM, why, { http_status: r.status });
    }
    if (r.status !== 200) throw new Upstream(`the public-record reading answered HTTP ${r.status}`, { http_status: r.status });
    const d = parseJsonBody(r);
    if (d?.format !== 'trooth.public-record.v1' || d.domain !== domain) throw new Upstream('the answer is not a public-record reading of the domain asked about');
    const sig = await checkPublicRecordSignature(d, flags);
    if (asJson) emitJson({ ...d, cli_check: sig }); else printPublicRecord(d, sig);
    if (sig.status === 'not_trusted') return EXIT.NOT_TRUSTED;
    if (sig.status === 'mismatch') return EXIT.MISMATCH;
    return d.bindings.length ? EXIT.OK : EXIT.FINDING;
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', ...e.extra });
    throw e;
  }
}

/**
 * Check what the answer says about its own signature (docs/EVIDENCE.md
 * section 5): the record's RFC 8785 SHA-256 is the one the statement names,
 * the statement is signed by a key on the key list that was trusted when it
 * was issued, and the statement is an entry of the log. Returns
 * {status, reason, key, statement_id, log}. status: signed (all hold),
 * unsigned (the answer says it is not signed), not_trusted (the signature or
 * key does not hold), mismatch (the record or the log proof does not match).
 */
async function checkPublicRecordSignature(d, flags) {
  const res = { status: 'unsigned', reason: null, key: null, statement_id: null, log: null };
  const s = d.signed;
  if (!s || typeof s !== 'object') return { ...res, reason: 'the answer carries no signed block (a reading from before trooth 0.11.0)' };
  const { signed, ...record } = d;
  void signed;
  let sha;
  try { sha = createHash('sha256').update(canonicalizeRecord(record), 'utf8').digest('hex'); }
  catch (e) { return { ...res, status: 'mismatch', reason: `the record has no RFC 8785 form: ${e.message}` }; }
  if (sha !== s.record_sha256) return { ...res, status: 'mismatch', reason: 'the record is not the one the statement names: its SHA-256 differs' };
  const st = s.statement;
  if (!st) return { ...res, reason: s.problem || 'the reading was not signed' };
  let p;
  try { p = JSON.parse(String(st.payload)); } catch { return { ...res, status: 'not_trusted', reason: 'the statement payload is not JSON' }; }
  res.statement_id = statementId(st.payload);
  if (p?.statement !== PUBLIC_RECORD_STATEMENT) return { ...res, status: 'not_trusted', reason: `the payload is not a ${PUBLIC_RECORD_STATEMENT} statement` };
  if (st.alg !== 'Ed25519' || st.canonicalization !== 'RFC8785' || !isCanonical(st.payload)) return { ...res, status: 'not_trusted', reason: 'the statement is not RFC 8785 bytes signed with Ed25519' };
  if (p.signer?.key_id !== st.key_id || p.signer?.issuer !== 'trooth.co') return { ...res, status: 'not_trusted', reason: 'the signer inside the statement is not the envelope key' };
  if (p.record_sha256 !== sha || p.domain !== d.domain || p.read_at !== d.read_at || p.subject_id !== d.subject_id) return { ...res, status: 'mismatch', reason: 'the statement names another reading' };
  res.key = st.key_id;
  let keys;
  try {
    const kr = await getFrom(API, '/public/keys', MAX_BODY_SMALL);
    if (kr.status !== 200) throw new Error(`HTTP ${kr.status}`);
    keys = parseJsonBody(kr).keys;
  } catch (e) { return { ...res, status: 'unsigned', reason: `the key list could not be read, so the signature was not checked: ${e.message}` }; }
  const published = (Array.isArray(keys) ? keys : []).find((k) => k && k.kid === st.key_id);
  const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(st.signature));
  const { createPublicKey, verify: edVerify } = await import('node:crypto');
  let valid = false;
  try { valid = !!(m && published && edVerify(null, Buffer.from(st.payload, 'utf8'), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: keyBytes(published).toString('base64url') }, format: 'jwk' }), Buffer.from(m[1], 'base64'))); } catch { valid = false; }
  if (!valid) return { ...res, status: 'not_trusted', reason: 'the signature does not check against the published key' };
  const kt = keyTrust(st.key_id, keys, typeof p.issued_at === 'string' ? p.issued_at : null);
  if (!kt.trusted) return { ...res, status: 'not_trusted', reason: kt.reason };
  if (s.log) {
    let { vkeys, source } = logVkeys(flags);
    if (!vkeys.length) {
      const v = await getFrom(LOG_BASE, '/vkey', 4096);
      vkeys = v.status === 200 ? [v.text.trim()] : [];
      source = 'served by the log (not pinned in this release)';
    }
    const r = checkReceipt({ kind: 'public_record', statement: st, receipt: s.log, vkeys });
    res.log = { ...r, vkey_source: source };
    if (r.status !== 'included') return { ...res, status: 'mismatch', reason: `the log receipt does not check: ${r.reason}` };
  }
  return { ...res, status: 'signed', reason: s.log ? `signed by ${st.key_id}, and entry ${s.log.index} of the log` : `signed by ${st.key_id}; ${s.problem || 'not logged'}` };
}

function printPublicRecord(d, sig) {
  const ok = (t) => `${J}${t}${X}`, bad = (t) => `${R}${t}${X}`, warn = (t) => `${A}${t}${X}`;
  const st = (s) => (s === 'corroborated' ? ok(s) : s === 'contradicted' || s === 'not_found' ? bad(s.replace('_', ' ')) : warn(s.replace(/_/g, ' ')));
  const fact = (list, k) => (list || []).find((x) => x.key === k)?.value;
  const num = (n) => Number(n).toLocaleString('en-US');
  out(`${B}${d.domain}${X}  ${D}public record, read ${fmtDate(d.read_at)}${X}`);
  out(`  site names   ${d.site.legal_names.length ? d.site.legal_names.map((x) => `${x.name} ${D}(${x.source})${X}`).join('; ') : warn(d.site.reason || 'no legal name stated')}`);
  if (d.entity) out(`  entity       ${ok(d.entity.id)}${d.entity.name ? ` ${d.entity.name}` : ''} ${D}(${d.entity.basis})${X}`);
  for (const b of d.bindings) {
    const label = b.identifier === 'cik' ? 'SEC filer ' : 'LEI       ';
    const best = b.for.find((x) => ['filing_namespace_names_domain', 'registry_lists_domain', 'through_corroborated_filer'].includes(x.kind)) || b.against[0] || b.for[0];
    out(`  ${label}   ${b.identifier === 'cik' ? `CIK ${b.value}` : b.value}  ${st(b.status)}${b.proof_method ? ` ${D}[${b.proof_method.replace(/_/g, ' ')}]${X}` : ''}${best ? ` ${D}${best.detail}${X}` : ''}`);
  }
  if (d.sec) {
    const f = d.sec.facts;
    const tick = (fact(f, 'sec.tickers') || []).join(', ');
    const exch = (fact(f, 'sec.exchanges') || []).join(', ');
    out(`               ${fact(f, 'sec.name')}${tick ? ` · ${tick}${exch ? ` (${exch})` : ''}` : ''}${fact(f, 'sec.filer_category') ? ` · ${fact(f, 'sec.filer_category')}` : ''}${fact(f, 'sec.state_of_incorporation') ? ` · incorporated ${fact(f, 'sec.state_of_incorporation')}` : ''}`);
    const latest = ['10-K', '20-F', '10-Q', '8-K', 'DEF 14A'].filter((k) => d.sec.latest[k]).map((k) => `${k} ${d.sec.latest[k].filed}`);
    if (latest.length) out(`  filings      ${latest.join(' · ')}`);
    out(`  8-K events   ${d.sec.events.length} since ${d.sec.events_cover_since} · cybersecurity incidents (1.05): ${d.sec.cybersecurity_incidents.length} · auditor changes (4.01): ${d.sec.auditor_changes.length} · non-reliance (4.02): ${d.sec.non_reliance.length}`);
    const short = { 'Revenue': 'revenue', 'Net income (loss)': 'net income', 'Total assets': 'assets' };
    for (const x of d.sec.financials) out(`  ${(short[x.label] || x.label).padEnd(11)}  ${num(x.value)} ${x.unit} ${D}(${x.period_start ? `year ending ${x.period_end}` : `at ${x.period_end}`}, ${x.form} filed ${x.filed})${X}`);
  }
  if (d.lei) {
    const f = d.lei.facts;
    out(`               ${fact(f, 'lei.legal_name')} · ${fact(f, 'lei.jurisdiction') || 'no jurisdiction'} · ${fact(f, 'lei.registration_status')}${fact(f, 'lei.registry_number') ? ` · registry number ${fact(f, 'lei.registry_number')}` : ''}`);
    if (d.lei.direct_parent) out(`               parent ${d.lei.direct_parent.name || ''} ${D}(${d.lei.direct_parent.lei})${X}`);
  }
  if (d.dns.length) {
    const v = (k) => fact(d.dns, k);
    out(`  DNS          DNSSEC ${v('dns.dnssec') ? 'yes' : 'no'} · MTA-STS ${v('dns.mta_sts') ? v('dns.mta_sts_mode') || 'published' : 'no'} · TLS-RPT ${v('dns.tls_rpt') ? 'yes' : 'no'} · BIMI ${v('dns.bimi') ? 'yes' : 'no'} · DMARC ${v('dns.dmarc_policy') || 'none'}`);
  }
  if (d.certificates) out(`  certificates ${d.certificates.unexpired}${d.certificates.page_full ? ' or more' : ''} unexpired for ${d.domain} in CT logs · issuers ${d.certificates.issuers.join(', ') || 'none'}${d.certificates.soonest_expiry ? ` · soonest expiry ${d.certificates.soonest_expiry.slice(0, 10)}` : ''}`);
  if (d.security_txt) out(`  security.txt ${d.security_txt.contacts.join(', ')}${d.security_txt.expired ? ` ${bad('expired')}` : d.security_txt.expires ? ` ${D}(expires ${d.security_txt.expires.slice(0, 10)})${X}` : ''}`);
  if (d.site.links?.length) out(`  linked       ${d.site.links.map((l) => `${l.kind.replace(/_/g, ' ')} ${D}${l.url}${X}`).join(' · ')}`);
  if (d.sanctions) out(`  sanctions    ${d.sanctions.matches.length ? warn(`${d.sanctions.matches.length} OFAC SDN entr${d.sanctions.matches.length === 1 ? 'y' : 'ies'} with the same name: ${d.sanctions.matches.map((x) => `${x.name} (${x.programs})`).join('; ')}. A name match is not an identification.`) : `no OFAC SDN entity with the name ${d.sanctions.names_checked.join(' or ')}`}`);
  if (d.sam) {
    const regs = d.sam.registrations.map((x) => `${x.legal_name}${x.uei ? ` UEI ${x.uei}` : ''}${x.status ? ` (${x.status}${x.expires ? `, expires ${x.expires}` : ''})` : ''}`);
    out(`  SAM.gov      ${regs.length ? regs.join('; ') : `no registration named ${d.sam.names_checked.join(' or ')}`} ${D}(read ${fmtDate(d.sam.read_at)})${X}`);
    if (d.sam.exclusions.length) out(`               ${warn(`${d.sam.exclusions.length} exclusion record${d.sam.exclusions.length === 1 ? '' : 's'} with the same name: ${d.sam.exclusions.map((x) => `${x.name} (${[x.agency, x.type, x.record_status].filter(Boolean).join(', ')})`).join('; ')}. A name match is not an identification.`)}`);
  }
  if (d.patents) out(`  patents      ${num(d.patents.applications)} application${d.patents.applications === 1 ? '' : 's'} with first applicant ${d.patents.applicant_names.join(' or ')}${d.patents.recent[0] ? ` · newest ${d.patents.recent[0].application}${d.patents.recent[0].title ? ` "${d.patents.recent[0].title}"` : ''}${d.patents.recent[0].filed ? ` filed ${d.patents.recent[0].filed}` : ''}` : ''}`);
  if (Array.isArray(d.registries) && d.registries.length) out(`  registries   ${d.registries.map((x) => `${x.jurisdiction} ${x.id}${x.status ? ` ${x.status}` : ''}${x.formation_jurisdiction ? `, formed in ${x.formation_jurisdiction}` : ''}`).join(' · ')} ${D}(exact-name matches)${X}`);
  if (d.merger_review) out(`  mergers      ${d.merger_review.notices.length ? `${d.merger_review.notices.length} FTC early termination notice${d.merger_review.notices.length === 1 ? '' : 's'} naming ${d.merger_review.names_checked.join(' or ')}${d.merger_review.notices[0].date ? `, newest ${d.merger_review.notices[0].date}` : ''}` : `no FTC early termination notice names ${d.merger_review.names_checked.join(' or ')}`}`);
  if (d.domain_registration) out(`  domain       registered ${d.domain_registration.registered || 'date not given'}${d.domain_registration.registrar ? ` · registrar ${d.domain_registration.registrar}` : ''}${d.domain_registration.expires ? ` · expires ${d.domain_registration.expires}` : ''}`);
  if (Array.isArray(d.changes) && d.changes.length) {
    out(`  changes      ${d.changes.length} recorded, newest first:`);
    for (const c of d.changes.slice(0, 5)) out(`               ${c.date || 'undated'}  ${c.detail}`);
  }
  if (d.continuity && Array.isArray(d.continuity.events)) {
    if (!d.continuity.previous) out(`  ${D}continuity   no earlier reading of this domain to compare with${X}`);
    else for (const e of d.continuity.events) out(`  continuity   ${e.kind === 'unchanged' ? ok('unchanged') : warn(e.kind.replace(/_/g, ' '))} ${D}since the reading of ${String(d.continuity.previous.read_at).slice(0, 10)}: ${e.detail}${X}`);
  }
  if (Array.isArray(d.evidence_classes)) {
    const read = d.evidence_classes.filter((c) => c.read);
    if (read.length) out(`  ${D}freshness    ${read.map((c) => `${c.class.replace(/_/g, ' ')} until ${String(c.stale_after).slice(0, 10)}`).join('; ')}${X}`);
  }
  if (d.declaration === null) out(`  ${D}declaration  not looked for in this reading${X}`);
  else if (d.declaration && typeof d.declaration === 'object') {
    const dc = d.declaration;
    const label = dc.status === 'checked' ? ok('checked') : dc.status === 'absent' ? `${D}absent${X}` : dc.status === 'not_read' ? warn('not read') : bad(dc.status);
    const parts = [];
    if (dc.status === 'checked' || dc.status === 'expired') {
      parts.push(`key${dc.keys.length === 1 ? '' : 's'} ${dc.keys.join(', ')}`, dc.key_pinned_by_dns ? 'pinned by DNS' : 'not pinned by DNS');
      if (dc.expires_at) parts.push(`${dc.status === 'expired' ? 'expired' : 'valid until'} ${String(dc.expires_at).slice(0, 10)}`);
      parts.push(`${dc.products.length} product${dc.products.length === 1 ? '' : 's'}, ${dc.apis.length} API${dc.apis.length === 1 ? '' : 's'}, ${dc.repositories.length} repositor${dc.repositories.length === 1 ? 'y' : 'ies'}`);
    }
    if (dc.reason && dc.status !== 'checked') parts.push(dc.reason);
    out(`  declaration  ${label} ${dc.url} ${D}${parts.length ? `(${parts.join('; ')})` : ''}${X}`);
  }
  if (Array.isArray(d.proofs)) {
    if (!d.proofs.length) out(`  ${D}proofs       none in this reading${X}`);
    for (const p of d.proofs) {
      const label = p.status === 'confirmed' ? ok('confirmed') : p.status === 'claimed' ? warn('claimed') : p.status === 'not_found' ? bad('not found') : warn('not read');
      out(`  proof        ${String(p.proof_method).replace(/_/g, ' ')} ${label} ${D}${(p.binds || []).join(' to ')}: ${p.detail} (${p.source}${p.observed_at ? `, ${String(p.observed_at).slice(0, 10)}` : ''})${X}`);
    }
  }
  if (Array.isArray(d.subjects) && d.subjects.length) out(`  ${D}subjects     ${d.subjects.map((x) => x.id).join(', ')}${X}`);
  if (Array.isArray(d.sources)) out(`  ${D}sources      ${d.sources.length} responses read, each kept by its SHA-256${X}`);
  out(`  ${D}not read     ${d.not_read.map((x) => x.source).join('; ')}${X}`);
  if (sig) {
    const line = sig.status === 'signed' ? ok(sig.reason) : sig.status === 'unsigned' ? warn(sig.reason) : bad(sig.reason);
    out(`  signature    ${line}${sig.log?.vkey_source ? ` ${D}(log key ${sig.log.vkey_source})${X}` : ''}`);
  }
  out(`\n${D}${d.note}${X}`);
}

/* ------------------------------------------------------------ mcp-tools ---- */

const MCP_TOOLS_STATEMENT = 'trooth.mcp-tools.v1';

/**
 * Check a signed statement envelope against Trooth's key list: RFC 8785
 * bytes, Ed25519, the signer inside the bytes is the envelope key, and the
 * key was trusted when the statement was issued. Returns {status, reason, key}.
 */
async function checkEnvelope(st, statementType) {
  let p;
  try { p = JSON.parse(String(st.payload)); } catch { return { status: 'not_trusted', reason: 'the statement payload is not JSON', key: null, payload: null }; }
  if (p?.statement !== statementType) return { status: 'not_trusted', reason: `the payload is not a ${statementType} statement`, key: null, payload: p };
  if (st.alg !== 'Ed25519' || st.canonicalization !== 'RFC8785' || !isCanonical(st.payload)) return { status: 'not_trusted', reason: 'the statement is not RFC 8785 bytes signed with Ed25519', key: null, payload: p };
  if (p.signer?.key_id !== st.key_id || p.signer?.issuer !== 'trooth.co') return { status: 'not_trusted', reason: 'the signer inside the statement is not the envelope key', key: null, payload: p };
  let keys;
  try {
    const kr = await getFrom(API, '/public/keys', MAX_BODY_SMALL);
    if (kr.status !== 200) throw new Error(`HTTP ${kr.status}`);
    keys = parseJsonBody(kr).keys;
  } catch (e) { return { status: 'unsigned', reason: `the key list could not be read, so the signature was not checked: ${e.message}`, key: st.key_id, payload: p }; }
  const published = (Array.isArray(keys) ? keys : []).find((k) => k && k.kid === st.key_id);
  const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(st.signature));
  const { createPublicKey, verify: edVerify } = await import('node:crypto');
  let valid = false;
  try { valid = !!(m && published && edVerify(null, Buffer.from(st.payload, 'utf8'), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: keyBytes(published).toString('base64url') }, format: 'jwk' }), Buffer.from(m[1], 'base64'))); } catch { valid = false; }
  if (!valid) return { status: 'not_trusted', reason: 'the signature does not check against the published key', key: st.key_id, payload: p };
  const kt = keyTrust(st.key_id, keys, typeof p.issued_at === 'string' ? p.issued_at : null);
  if (!kt.trusted) return { status: 'not_trusted', reason: kt.reason, key: st.key_id, payload: p };
  return { status: 'signed', reason: null, key: st.key_id, payload: p };
}

/** Check an MCP tool reading (docs/EVIDENCE.md section 9). */
async function checkMcpReading(d, flags) {
  const res = { status: 'unsigned', reason: null, key: null, statement_id: null, log: null, hashes: 'checked' };
  for (const t of d.tools) {
    if (createHash('sha256').update(t.description, 'utf8').digest('hex') !== t.description_sha256) return { ...res, status: 'mismatch', hashes: 'mismatch', reason: `the description of ${t.name} is not the one its hash names` };
  }
  if (manifestOf(d.tools) !== d.manifest_sha256) return { ...res, status: 'mismatch', hashes: 'mismatch', reason: 'the manifest hash is not the hash of the tools listed' };
  const { signed, last_checked, ...reading } = d;
  void last_checked;
  if (!signed) return { ...res, reason: 'the reading carries no signed block' };
  const sha = createHash('sha256').update(canonicalizeRecord(reading), 'utf8').digest('hex');
  if (sha !== signed.reading_sha256) return { ...res, status: 'mismatch', reason: 'the reading is not the one the statement names: its SHA-256 differs' };
  const st = signed.statement;
  if (!st) return { ...res, reason: signed.problem || 'the reading was not signed' };
  res.statement_id = statementId(st.payload);
  const env = await checkEnvelope(st, MCP_TOOLS_STATEMENT);
  res.key = env.key;
  if (env.status !== 'signed') return { ...res, status: env.status, reason: env.reason };
  const p = env.payload;
  const named = JSON.stringify((p.tools || []).map((t) => [t.name, t.description_sha256, t.definition_sha256]));
  const listed = JSON.stringify(d.tools.map((t) => [t.name, t.description_sha256, t.definition_sha256]));
  if (p.reading_sha256 !== sha || p.manifest_sha256 !== d.manifest_sha256 || p.endpoint !== d.endpoint || p.read_at !== d.read_at || named !== listed) return { ...res, status: 'mismatch', reason: 'the statement names another reading' };
  if (signed.log) {
    let { vkeys, source } = logVkeys(flags);
    if (!vkeys.length) {
      const v = await getFrom(LOG_BASE, '/vkey', 4096);
      vkeys = v.status === 200 ? [v.text.trim()] : [];
      source = 'served by the log (not pinned in this release)';
    }
    const r = checkReceipt({ kind: 'mcp_tools', statement: st, receipt: signed.log, vkeys });
    res.log = { ...r, vkey_source: source };
    if (r.status !== 'included') return { ...res, status: 'mismatch', reason: `the log receipt does not check: ${r.reason}` };
  }
  return { ...res, status: 'signed', reason: signed.log ? `signed by ${st.key_id}, and entry ${signed.log.index} of the log` : `signed by ${st.key_id}; ${signed.problem || 'not logged'}` };
}

async function mcpToolsCmd() {
  const { flags, positional } = parseArgs('mcp-tools');
  if (positional.length > 1) fail(EXIT.USAGE, 'trooth mcp-tools takes at most one <endpoint>. Try: trooth mcp-tools https://api.trooth.co/public/mcp');
  try {
    if (!positional.length) {
      if (flags['--live']) fail(EXIT.USAGE, '--live needs an <endpoint>.');
      const r = await getFrom(API, '/scan/mcp-tools', MAX_BODY_SMALL);
      if (r.status !== 200) throw new Upstream(`the MCP tool index answered HTTP ${r.status}`, { http_status: r.status });
      const d = parseJsonBody(r);
      if (asJson) { emitJson(d); return EXIT.OK; }
      out(`${B}MCP servers whose tool lists Trooth logs${X}`);
      for (const e of d.endpoints || []) out(`  ${e.endpoint}  ${e.manifest_sha256 ? `${e.tools} tools · manifest ${e.manifest_sha256.slice(0, 16)}… · read ${fmtDate(e.read_at)}${e.log_index !== null ? ` · log entry ${e.log_index}` : ''}` : `${A}not read yet${X}`}`);
      out(`\n${D}Check one, and compare it with what the server lists now: trooth mcp-tools <endpoint> --live${X}`);
      return EXIT.OK;
    }
    let ep;
    try { ep = new URL(positional[0]); } catch { fail(EXIT.USAGE, `${positional[0]} is not a URL.`); }
    const loopback = ep.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(ep.hostname);
    if ((ep.protocol !== 'https:' && !loopback) || ep.username || ep.password || ep.hash) fail(EXIT.USAGE, 'the endpoint is an https URL (or http on this machine) with no credentials and no fragment.');
    const r = await getFrom(API, `/scan/mcp-tools/reading?endpoint=${encodeURIComponent(positional[0])}`, MAX_BODY_SMALL * 4);
    if (r.status === 404) fail(EXIT.FINDING, `Trooth has no reading of ${positional[0]}. The servers it reads: trooth mcp-tools`);
    if (r.status !== 200) throw new Upstream(`the MCP tool reading answered HTTP ${r.status}`, { http_status: r.status });
    const d = parseJsonBody(r);
    if (d?.format !== 'trooth.mcp-tools.v1' || !Array.isArray(d.tools)) throw new Upstream('the answer is not an MCP tool reading');
    const sig = await checkMcpReading(d, flags);
    let live = null;
    if (flags['--live']) {
      try {
        const l = await listTools(positional[0], { userAgent: `trooth-cli/${VERSION}` });
        const now = l.tools.map(hashTool);
        const diff = diffTools(d.tools, now);
        live = { tools: now.length, manifest_sha256: manifestOf(now), same: manifestOf(now) === d.manifest_sha256, ...diff, server: { name: l.server.name ?? null, version: l.server.version ?? null } };
      } catch (e) { live = { error: e && e.message ? e.message : String(e) }; }
    }
    if (asJson) emitJson({ ...d, cli_check: sig, ...(live ? { live } : {}) });
    else {
      const ok = (t) => `${J}${t}${X}`, bad = (t) => `${R}${t}${X}`, warn = (t) => `${A}${t}${X}`;
      out(`${B}${d.endpoint}${X}  ${D}${d.server.name || 'MCP server'}${d.server.version ? ` ${d.server.version}` : ''}, read ${fmtDate(d.read_at)}${d.last_checked ? `, unchanged when last checked ${fmtDate(d.last_checked)}` : ''}${X}`);
      out(`  tools      ${d.tools.length} · manifest ${d.manifest_sha256}`);
      for (const t of d.tools.slice(0, 40)) out(`             ${t.name.padEnd(28)} ${D}description ${t.description_sha256.slice(0, 12)}… definition ${t.definition_sha256.slice(0, 12)}…${X}`);
      if (d.tools.length > 40) out(`             ${D}and ${d.tools.length - 40} more (--json for all)${X}`);
      if (d.changed) out(`  since      ${d.previous ? `${fmtDate(d.previous.read_at)}: ` : ''}${[d.changed.added.length ? `added ${d.changed.added.join(', ')}` : '', d.changed.removed.length ? `removed ${d.changed.removed.join(', ')}` : '', d.changed.changed.length ? `changed ${d.changed.changed.join(', ')}` : ''].filter(Boolean).join('; ') || 'no change'}`);
      out(`  signature  ${sig.status === 'signed' ? ok(sig.reason) : sig.status === 'unsigned' ? warn(sig.reason) : bad(sig.reason)}${sig.log?.vkey_source ? ` ${D}(log key ${sig.log.vkey_source})${X}` : ''}`);
      if (live) {
        if (live.error) out(`  live       ${warn(`the server could not be read from here: ${live.error}`)}`);
        else if (live.same) out(`  live       ${ok('the server lists the same tools now, byte for byte')} ${D}(${live.tools} tools)${X}`);
        else out(`  live       ${bad('the server lists different tools now')}: ${[live.added.length ? `added ${live.added.join(', ')}` : '', live.removed.length ? `removed ${live.removed.join(', ')}` : '', live.changed.length ? `changed ${live.changed.join(', ')}` : ''].filter(Boolean).join('; ')}`);
      }
      out(`\n${D}${d.note}${X}`);
    }
    if (sig.status === 'not_trusted') return EXIT.NOT_TRUSTED;
    if (sig.status === 'mismatch') return EXIT.MISMATCH;
    if (live && !live.error && !live.same) return EXIT.MISMATCH;
    if (live && live.error) return EXIT.INCOMPLETE;
    return EXIT.OK;
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', ...e.extra });
    throw e;
  }
}

/* ----------------------------------------------------------------- log ---- */

const LOG_BASE = `${API}/scan/log/v1`;

/** The log keys to check checkpoints against: --log-vkey, else the pinned keys, else none. */
function logVkeys(flags) {
  if (flags['--log-vkey']) {
    try { parseVkey(flags['--log-vkey']); } catch (e) { fail(EXIT.USAGE, `--log-vkey: ${e.message}`); }
    return { vkeys: [flags['--log-vkey']], source: '--log-vkey' };
  }
  return { vkeys: PINNED_LOG_VKEYS, source: PINNED_LOG_VKEYS.length ? `pinned in trooth ${VERSION}` : null };
}

/** Ask the log about one statement. Never throws: a log that cannot be read is reported, not fatal. */
async function readLog(payload, flags) {
  const { createHash } = await import('node:crypto');
  const sid = `trooth:statement:${createHash('sha256').update(Buffer.from(payload, 'utf8')).digest('hex')}`;
  try {
    let { vkeys, source } = logVkeys(flags);
    if (!vkeys.length) {
      const v = await getFrom(LOG_BASE, '/vkey', 4096);
      if (v.status !== 200) throw new Error(`the log key answered HTTP ${v.status}`);
      vkeys = [v.text.trim()];
      source = 'served by the log (not pinned in this release)';
    }
    const look = await getFrom(LOG_BASE, `/lookup?statement_id=${encodeURIComponent(sid)}`, MAX_BODY_SMALL);
    let receipt = null;
    if (look.status === 200) receipt = parseJsonBody(look).receipt ?? null;
    else if (look.status !== 404) throw new Error(`the log answered HTTP ${look.status}`);
    let corrections = [];
    if (receipt) {
      const c = await getFrom(LOG_BASE, `/corrections?statement_id=${encodeURIComponent(sid)}`, MAX_BODY_SMALL);
      if (c.status !== 200) throw new Error(`the log's corrections answered HTTP ${c.status}`);
      corrections = parseJsonBody(c).corrections ?? [];
    }
    return { vkeys, vkey_source: source, receipt, corrections };
  } catch (e) {
    return { vkeys: [], vkey_source: null, receipt: null, corrections: [], unavailable: e && e.message ? e.message : String(e) };
  }
}

async function readCheckpoint(flags) {
  let { vkeys, source } = logVkeys(flags);
  if (!vkeys.length) {
    const v = await getFrom(LOG_BASE, '/vkey', 4096);
    if (v.status !== 200) throw new Upstream(`the log key answered HTTP ${v.status}`, { http_status: v.status });
    vkeys = [v.text.trim()];
    source = 'served by the log (not pinned in this release)';
  }
  const r = await getFrom(LOG_BASE, '/checkpoint', 64 * 1024);
  if (r.status !== 200) throw new Upstream(`the log checkpoint answered HTTP ${r.status}`, { http_status: r.status });
  let cp = null, why = '';
  for (const k of vkeys) { try { cp = openCheckpoint(r.text, k); break; } catch (e) { why = e.message; } }
  return { cp, why, note: r.text, vkeys, source };
}

/**
 * The log's second signature, by its hardware key in AWS KMS (docs/KEY-CEREMONY.md
 * ceremony v2): checked against the hardware vkey pinned in this release, when one is.
 * The software key's signature is what makes a checkpoint check; this line says
 * whether the hardware key signed it too.
 */
function hardwareSigned(note, flags) {
  if (flags['--log-vkey']) return { pinned: false, signed: null, vkey: null, reason: '--log-vkey given; the hardware key was not checked' };
  if (!HARDWARE_LOG_VKEY) return { pinned: false, signed: null, vkey: null, reason: `no hardware key is pinned in trooth ${VERSION}` };
  let signed = false;
  try { signed = !!verifyNote(note, HARDWARE_LOG_VKEY); } catch { signed = false; }
  return { pinned: true, signed, vkey: HARDWARE_LOG_VKEY, reason: null };
}

function hardwareLine(h) {
  if (!h.pinned) return `  hardware   ${D}${h.reason}${X}`;
  return h.signed ? `  hardware   ${J}also signed by the hardware key${X} ${D}(AWS KMS, ${h.vkey.split('+')[1]})${X}` : `  hardware   ${A}not signed by the hardware key; the software key's signature stands${X}`;
}

/** --witnesses <n>: how many pinned witnesses must have cosigned. */
function witnessesRequired(flags) {
  if (flags['--witnesses'] === undefined) return 0;
  if (!/^(0|[1-9][0-9]?)$/.test(flags['--witnesses'])) fail(EXIT.USAGE, '--witnesses is a whole number: how many pinned witnesses must have cosigned.');
  const n = Number(flags['--witnesses']);
  if (n > PINNED_WITNESSES.length) fail(EXIT.USAGE, `--witnesses ${n}: this release pins ${PINNED_WITNESSES.length} witnesses.`);
  return n;
}

function cosignLines(cos) {
  const valid = cos.filter((c) => c.valid);
  if (!valid.length) return `  witnesses  ${A}no cosignature from the ${cos.length} pinned witnesses yet${X}`;
  return `  witnesses  ${J}cosigned by ${valid.length} of ${cos.length}${X}: ${valid.map((c) => `${c.operator || c.name} ${D}(${c.time})${X}`).join(', ')}`;
}

async function logReceiptCmd(flags, positional) {
  if (positional.length !== 2 || !/^(0|[1-9][0-9]{0,15})$/.test(positional[1])) fail(EXIT.USAGE, 'trooth log receipt takes one entry index. Try: trooth log receipt 0');
  if (flags['--out'] && existsSync(flags['--out'])) fail(EXIT.USAGE, `--out will not overwrite ${flags['--out']}; choose a new path.`);
  const index = Number(positional[1]);
  let { vkeys, source } = logVkeys(flags);
  if (!vkeys.length) {
    const v = await getFrom(LOG_BASE, '/vkey', 4096);
    if (v.status !== 200) throw new Upstream(`the log key answered HTTP ${v.status}`, { http_status: v.status });
    vkeys = [v.text.trim()];
    source = 'served by the log (not pinned in this release)';
  }
  const e = await getFrom(LOG_BASE, `/entries/${index}`, MAX_BODY_SMALL);
  if (e.status === 404) fail(EXIT.FINDING, `the log has no entry ${index}.`);
  if (e.status !== 200) throw new Upstream(`the log entry answered HTTP ${e.status}`, { http_status: e.status });
  const entry = parseJsonBody(e);
  const entryBytes = Buffer.from(canonicalize(entry.entry), 'utf8');
  const receipt = await getBytes(`${LOG_BASE}/receipt/${index}`, 64 * 1024);
  let published = null;
  try { published = keysFromKeySet(await getBytes(`${API}/.well-known/scitt-keys`, 64 * 1024)); } catch { published = null; }
  let result = null;
  for (const k of vkeys) { result = checkCoseReceipt(receipt, entryBytes, parseVkey(k).key); if (result.valid) break; }
  const listed = published ? vkeys.some((k) => published.some((p) => p.key.equals(parseVkey(k).key))) : null;
  if (flags['--out'] && result.valid) writeFileSync(flags['--out'], receipt);
  const doc = { log: LOG_ORIGIN, index, kind: entry.kind, statement_id: entry.statement_id, receipt: { valid: result.valid, reason: result.reason, tree_size: result.tree_size, root_hash: result.root, bytes: receipt.length, format: 'RFC 9942 COSE receipt of inclusion (COSE_Sign1, vds RFC9162_SHA256)' }, scitt_keys_lists_log_key: listed, vkey_source: source, written: flags['--out'] && result.valid ? flags['--out'] : null };
  if (asJson) emitJson(doc);
  else {
    out(`${B}${LOG_ORIGIN}${X}  entry ${index} ${D}(${entry.kind}, ${entry.statement_id})${X}`);
    out(`  COSE receipt  ${result.valid ? `${J}checks${X}: ${result.reason}` : `${R}does not check${X}: ${result.reason}`}`);
    out(`  scitt-keys    ${listed === null ? `${A}not read${X}` : listed ? `${J}lists the log key${X}` : `${R}does not list the log key${X}`} ${D}(${API}/.well-known/scitt-keys)${X}`);
    out(`  ${D}log key ${source}${doc.written ? `; receipt written to ${doc.written}` : ''}${X}`);
  }
  return result.valid && listed !== false ? EXIT.OK : EXIT.MISMATCH;
}

async function logCmd() {
  const sub = argv[1];
  const { flags, positional } = parseArgs('log');
  if (sub !== 'checkpoint' && sub !== 'monitor' && sub !== 'receipt') fail(EXIT.USAGE, 'trooth log takes checkpoint, monitor or receipt. Try: trooth log checkpoint');
  try {
    if (sub === 'receipt') return await logReceiptCmd(flags, positional);
    if (positional.length > 1) fail(EXIT.USAGE, `unexpected argument: ${positional.slice(1).join(' ')}`);
    if (sub === 'monitor' && !flags['--state']) fail(EXIT.USAGE, 'trooth log monitor needs --state <file>: where the last checkpoint seen is kept.');
    const need = witnessesRequired(flags);
    const { cp, why, note, source } = await readCheckpoint(flags);
    if (!cp) {
      const doc = { log: LOG_ORIGIN, consistent: false, problem: `the checkpoint does not check: ${why}` };
      if (asJson) emitJson(doc); else out(`${R}The log's checkpoint does not check.${X} ${why}`);
      return EXIT.MISMATCH;
    }
    const cos = checkCosignatures(note, PINNED_WITNESSES);
    const cosigned = cos.filter((c) => c.valid).length;
    const hardware = hardwareSigned(note, flags);
    const witnessDoc = { required: need, cosigned, pinned: cos.length, cosignatures: cos };
    const short = need > cosigned ? `${cosigned} of the pinned witnesses cosigned this checkpoint; --witnesses asked for ${need}` : null;
    const now = { size: Number(cp.size), root: toB64(cp.root), checkpoint: note };
    if (sub === 'checkpoint') {
      const doc = { log: LOG_ORIGIN, tree_size: now.size, root_hash: now.root, vkey_source: source, hardware_key: hardware, witnesses: witnessDoc, problem: short, checkpoint: note };
      if (asJson) emitJson(doc); else out(`${B}${LOG_ORIGIN}${X}  ${J}checkpoint checks${X}
  tree size  ${now.size}
  root hash  ${now.root}
${hardwareLine(hardware)}
${cosignLines(cos)}${short ? `\n  ${R}${short}${X}` : ''}
  ${D}log key ${source}; witness keys pinned in trooth ${VERSION}${X}`);
      return short ? EXIT.MISMATCH : EXIT.OK;
    }
    const path = flags['--state'];
    let prior = null;
    if (existsSync(path)) {
      try { prior = JSON.parse(readFileSync(path, 'utf8')); } catch { fail(EXIT.USAGE, `${path} is not a state file this command wrote.`); }
      if (!Number.isSafeInteger(prior?.size) || !fromB64(prior?.root)) fail(EXIT.USAGE, `${path} is not a state file this command wrote.`);
    }
    let consistent = true, problem = null;
    if (prior) {
      if (now.size < prior.size) { consistent = false; problem = `the log shrank from ${prior.size} to ${now.size}`; }
      else if (now.size === prior.size) { if (now.root !== prior.root) { consistent = false; problem = `two different roots at size ${now.size}`; } }
      else {
        const pr = await getFrom(LOG_BASE, `/proof/consistency?first=${prior.size}&second=${now.size}`, MAX_BODY_SMALL);
        if (pr.status !== 200) throw new Upstream(`the log's consistency proof answered HTTP ${pr.status}`, { http_status: pr.status });
        const proof = (parseJsonBody(pr).consistency_proof || []).map(fromB64);
        if (proof.some((h) => !h) || !verifyConsistency(prior.size, now.size, fromB64(prior.root), cp.root, proof)) { consistent = false; problem = `the tree of ${now.size} is not an extension of the tree of ${prior.size}`; }
      }
    }
    if (consistent) writeFileSync(path, JSON.stringify({ log: LOG_ORIGIN, size: now.size, root: now.root, checkpoint: now.checkpoint, cosigned_by: cos.filter((c) => c.valid).map((c) => c.name), seen_at: new Date().toISOString() }, null, 2) + '\n');
    const doc = { log: LOG_ORIGIN, consistent, previous_size: prior?.size ?? null, tree_size: now.size, root_hash: now.root, problem: problem || short, vkey_source: source, witnesses: witnessDoc };
    if (asJson) emitJson(doc);
    else {
      if (!prior) out(`${B}${LOG_ORIGIN}${X}  first checkpoint recorded: size ${now.size}\n  ${D}saved to ${path}; the next run checks the log only grew from here${X}`);
      else if (consistent) out(`${B}${LOG_ORIGIN}${X}  ${J}consistent${X}: size ${prior.size} to ${now.size}, append-only`);
      else out(`${B}${LOG_ORIGIN}${X}  ${R}NOT CONSISTENT${X}: ${problem}. The state file was left as it was.`);
      out(cosignLines(cos));
      if (short) out(`  ${R}${short}${X}`);
    }
    return consistent && !short ? EXIT.OK : EXIT.MISMATCH;
  } catch (e) {
    if (e instanceof Upstream) fail(EXIT.UPSTREAM, e.message, { state: 'service_error', ...e.extra });
    throw e;
  }
}

function printVerify(d, payload) {
  const ok = (t) => `${J}${t}${X}`, bad = (t) => `${R}${t}${X}`, warn = (t) => `${A}${t}${X}`;
  const when = d.read_at ? `, read ${fmtDate(d.read_at)}` : '';
  out(`${B}${d.domain || '(no domain)'}${X}  ${D}witness statement ${d.version}${when}${X}`);
  out(`  signature  ${d.signature === 'valid' ? ok('valid') : bad(d.signature)} ${D}(Ed25519${d.version === 'v3' ? ' over RFC 8785 bytes' : ''}, key ${d.key.kid}, ${d.key.state})${X}`);
  if (!d.key.trusted) out(`             ${bad(d.key.reason)}`);
  if (d.verdict === 'signature_not_trusted') {
    out(`\n${bad('Not trusted.')} Nothing in this statement is relied on.`);
    if (d.sources.bundle_written) out(`${D}Bundle written: ${d.sources.bundle_written}${X}`);
    return;
  }
  const subj = d.subject.status === 'match' ? ok(`${d.subject.signed}, the domain asked about`) : d.subject.status === 'mismatch' ? bad(`signed for ${d.subject.signed}, not ${d.subject.asked}`) : warn(`${d.subject.signed} (no domain given to compare)`);
  out(`  subject    ${subj}`);
  const part = (name, st, extra) => out(`  ${name.padEnd(9)}  ${st === 'match' ? ok('matches') : st === 'mismatch' ? bad('does not match') : st === 'absent' ? warn('not bound by a v1 statement') : warn('not supplied')} ${D}${extra}${X}`);
  part('mapping', d.binding.mapping, payload?.methodology ? `(check mapping ${payload.methodology.mapping_version}, ${payload.methodology.mapping_digest})` : '');
  part('manifest', d.binding.manifest, payload?.evidence_manifest ? `(${payload.evidence_manifest.entries} entries, ${payload.evidence_manifest.digest})` : '');
  const c = payload?.counts || {};
  out(`  counts     ${d.counts.identities_hold ? ok('hold') : bad('disagree')} ${D}(${c.read} read, ${c.as_expected} as expected${c.not_read !== undefined ? `, ${c.not_read} not read` : ''})${X}`);
  for (const p of d.counts.problems.slice(0, 5)) out(`             ${bad(p)}`);
  if (d.log) {
    const l = d.log;
    const line = l.status === 'included' ? ok(`included, entry ${l.index} of a signed tree of ${l.tree_size}`) : l.status === 'not_logged' ? warn('not in the log') : l.status === 'unavailable' ? warn(`not read: ${l.reason}`) : bad(`${l.status.replace('_', ' ')}: ${l.reason}`);
    out(`  log        ${line}${l.vkey_source ? ` ${D}(log key ${l.vkey_source})${X}` : ''}`);
    const valid = l.corrections.filter((x) => x.valid);
    for (const x of valid) out(`             ${bad(`${x.effect} by a correction (${x.code}) issued ${x.issued_at}`)}${x.replacement ? ` ${D}replacement ${x.replacement}${X}` : ''}`);
    const ignored = l.corrections.length - valid.length;
    if (ignored) out(`             ${warn(`${ignored} correction${ignored === 1 ? '' : 's'} in the log did not check and ${ignored === 1 ? 'is' : 'are'} not relied on`)}`);
  }
  const head = { checked: ok('Checked.'), checked_v1: ok('Checked (v1).'), partially_checked: warn('Partially checked.'), mismatch: bad('Mismatch.'), superseded: bad('Superseded.') }[d.verdict];
  out(`\n${head} ${D}${d.assurance}${X}`);
  if (d.statement_id) out(`${D}Statement id: ${d.statement_id}${X}`);
  if (d.keys_read_at && d.sources.keys && !/^https?:/.test(String(d.sources.keys))) out(`${D}The key list was saved at ${d.keys_read_at}; a compromise announced after that is not in it. Refresh it before relying on this for a decision.${X}`);
  if (d.sources.bundle_written) out(`${D}Bundle written: ${d.sources.bundle_written} (check it later with: trooth verify --bundle ${d.sources.bundle_written})${X}`);
}

/* --------------------------------------------------------------- guard ---- */

/** Build a guard from the command's flags. Throws PolicyError or Error; the caller decides the exit. */
async function guardFromFlags(flags, { needCache = false } = {}) {
  if (!flags['--policy']) throw new PolicyError('--policy <file> is required.');
  const policy = await loadGuardPolicy(flags['--policy']);
  let maxAge = 900;
  if (flags['--max-age'] !== undefined) {
    if (!/^(0|[1-9][0-9]{0,7})$/.test(flags['--max-age'])) throw new PolicyError('--max-age is a whole number of seconds.');
    maxAge = Number(flags['--max-age']);
  }
  if (needCache && !flags['--cache']) throw new PolicyError('--cache <dir> is required.');
  if (flags['--offline'] && !flags['--cache']) throw new PolicyError('--offline reads only cached bundles; it needs --cache <dir>.');
  const opts = { policy, api: API, web: WEB, cache: flags['--cache'] ? { dir: flags['--cache'], maxAgeSeconds: maxAge } : null, offline: !!flags['--offline'] };
  if (flags['--log-vkey']) { parseVkey(flags['--log-vkey']); opts.vkeys = [flags['--log-vkey']]; }
  if (flags['--witness']) opts.witnesses = flags['--witness'];
  if (flags['--timeout-ms'] !== undefined) opts.timeoutMs = Number(flags['--timeout-ms']);
  return createGuard(opts);
}

/** One line per reason, for people and for the hook's reason. Every detail was written by the guard. */
function guardReasonText(d) {
  const parts = d.reasons.filter((r) => d.decision === 'allow' || r.code !== 'RULE_PASSED').map((r) => `${r.code}${r.rule_id ? ` [${r.rule_id}]` : ''}${r.needed ? ` needs ${r.needed}` : ''}${r.detail ? `: ${r.detail}` : ''}`);
  return parts.join('; ');
}

function printGuardDecision(d) {
  const color = d.decision === 'allow' ? J : d.decision === 'hold' ? A : R;
  out(`${B}${d.action?.tool || '(tool)'}${X} → ${d.action?.host || '(no host)'}  ${color}${d.decision.toUpperCase()}${X}  ${D}policy ${d.policy.id} v${d.policy.version}${X}`);
  for (const r of d.reasons) out(`  ${r.code.padEnd(21)}${r.rule_id ? ` ${r.rule_id}` : ''}${r.needed ? ` ${D}needs ${r.needed}${X}` : ''}${r.detail ? ` ${D}${r.detail}${X}` : ''}`);
  if (d.subject) out(`  ${D}subject ${d.subject}; ${d.evidence.length} signed fact${d.evidence.length === 1 ? '' : 's'} read; decided ${d.decided_at}${X}`);
  out(`${D}The guard answers about this action under your policy. It does not say whether a company is safe.${X}`);
}

async function readStdin(limit = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const c of process.stdin) {
    total += c.length;
    if (total > limit) throw new Error(`the hook input is over ${limit} bytes`);
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function guardHook(flags) {
  // Claude Code reads exit 2 as "block" and any other non-zero code as a
  // non-blocking error that lets the tool run, so every failure here exits 2.
  const block = (why) => { diag(`trooth guard: ${why}`); return 2; };
  let guard;
  try { guard = await guardFromFlags(flags); }
  catch (e) { return block(`the policy could not be used, so the action is stopped: ${e.message}`); }
  let input;
  try { input = JSON.parse(await readStdin()); }
  catch (e) { return block(`the hook input is not JSON, so the action is stopped: ${e.message}`); }
  if (!input || typeof input !== 'object' || typeof input.tool_name !== 'string') return block('the hook input has no tool_name, so the action is stopped.');
  if (!guard.applies(input.tool_name)) return EXIT.OK;
  let d;
  try { d = await guard.decideToolCall({ name: input.tool_name, arguments: input.tool_input ?? {} }); }
  catch (e) { return block(`the guard could not decide, so the action is stopped: ${e.message}`); }
  if (!d) return EXIT.OK;
  const reason = `Trooth guard, policy ${d.policy.id} v${d.policy.version}: ${d.decision} for ${d.action?.host || 'no host'}. ${guardReasonText(d)}`;
  if (d.decision === 'allow') return EXIT.OK;
  if (d.decision === 'hold') {
    out(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: reason } }));
    return EXIT.OK;
  }
  diag(`${reason} Reason codes: ${[...new Set(d.reasons.filter((r) => r.code !== 'RULE_PASSED').map((r) => r.code))].join(', ')}`);
  return 2;
}

function gitDiff(base) {
  try {
    return execFileSync('git', ['diff', '--unified=0', '--no-color', '--no-ext-diff', `${base}...HEAD`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    fail(EXIT.USAGE, `git diff ${base}...HEAD did not run: ${String(e.stderr || e.message).trim().split('\n')[0]}. Pass --base <ref> or the files to scan.`);
  }
}

async function guardCmd() {
  const { flags, positional } = parseArgs('guard');
  const sub = positional[0];
  const rest = positional.slice(1);
  if (sub === 'hook') {
    hookMode = true;
    if (rest.length) return guardHookUsage(`unexpected argument: ${rest.join(' ')}`);
    return guardHook(flags);
  }
  if (!['decide', 'ci', 'cache'].includes(sub)) fail(EXIT.USAGE, 'trooth guard takes decide, hook, ci or cache. Try: trooth guard decide --policy policy.yaml --tool stripe.create_payout --host api.stripe.com');
  let guard;
  try { guard = await guardFromFlags(flags, { needCache: sub === 'cache' }); }
  catch (e) { fail(EXIT.USAGE, e.message); }

  if (sub === 'decide') {
    if (rest.length) fail(EXIT.USAGE, `unexpected argument: ${rest.join(' ')}`);
    if (!flags['--tool']) fail(EXIT.USAGE, '--tool <name> is required.');
    let args;
    if (flags['--args'] !== undefined) { try { args = JSON.parse(flags['--args']); } catch { fail(EXIT.USAGE, '--args is not valid JSON.'); } }
    if (!guard.applies(flags['--tool'])) {
      // The policy does not cover this tool: nothing is decided, and the caller
      // lets the call run as its policy intends. Not an allow.
      const doc = { covered: false, tool: flags['--tool'], policy: { id: guard.policy.id, version: guard.policy.version, sha256: guard.policy.sha256 }, note: 'The policy does not cover this tool, so the guard decided nothing about it.' };
      if (asJson) emitJson(doc); else out(`${flags['--tool']}  ${D}not covered by the policy ${guard.policy.id} v${guard.policy.version}; nothing decided${X}`);
      return EXIT.OK;
    }
    let d;
    if (flags['--host'] !== undefined) d = await guard.decide({ tool: flags['--tool'], host: flags['--host'], args });
    else d = await guard.decideToolCall({ name: flags['--tool'], arguments: args ?? {} });
    if (asJson) emitJson(d); else printGuardDecision(d);
    return d.decision === 'allow' ? EXIT.OK : d.decision === 'hold' ? EXIT.GUARD_HOLD : EXIT.GUARD_DENY;
  }

  if (sub === 'ci') {
    let lines;
    if (rest.length) {
      lines = [];
      for (const f of rest) {
        if (!existsSync(f) || !statSync(f).isFile()) fail(EXIT.USAGE, `not a file: ${f}`);
        readFileSync(f, 'utf8').split('\n').forEach((text, i) => lines.push({ file: f, line: i + 1, text }));
      }
    } else {
      lines = addedLines(gitDiff(flags['--base'] || 'origin/main'));
    }
    const { findings, allowed } = scanLines(lines, guard.policy);
    if (asJson) emitJson({ policy: { id: guard.policy.id, version: guard.policy.version, sha256: guard.policy.sha256 }, scanned: rest.length ? 'files' : `git diff ${flags['--base'] || 'origin/main'}...HEAD`, lines: lines.length, findings, allowed });
    else {
      for (const f of findings) out(`${f.file}:${f.line}  ${R}${f.host}${X}  ${D}not in destinations.allowed${X}`);
      if (findings.length) out(`\n${findings.length} added destination${findings.length === 1 ? '' : 's'} the policy ${guard.policy.id} does not list. Add the host to destinations.allowed after review, or remove it.`);
      else out(`${J}No added destination outside destinations.allowed${X} ${D}(${lines.length} line${lines.length === 1 ? '' : 's'} read; ${allowed.length} allowed host reference${allowed.length === 1 ? '' : 's'})${X}`);
    }
    return findings.length ? EXIT.GUARD_CI_FOUND : EXIT.OK;
  }

  // cache
  if (!rest.length) fail(EXIT.USAGE, 'trooth guard cache needs at least one <domain>.');
  const results = [];
  for (const raw of rest) {
    const norm = normalizeDomain(raw);
    if (norm.error) fail(EXIT.USAGE, norm.error.replace('trooth check', 'trooth guard cache'));
    results.push(await guard.saveBundle(norm.domain));
  }
  if (asJson) emitJson({ cache: flags['--cache'], results });
  else for (const r of results) out(r.saved ? `${J}saved${X}  ${r.domain}  ${D}${r.path}; witness statement ${r.witness_statement ? 'yes' : 'no'}, public record ${r.public_record ? 'yes' : 'no'}, signature ${r.signature}, key ${r.key_status}, log ${r.log}, ${r.witnesses} witness cosignature${r.witnesses === 1 ? '' : 's'}${X}` : `${A}not saved${X}  ${r.domain}  ${r.reason}`);
  if (results.some((r) => !r.saved && !/^no Trooth record/.test(r.reason))) return EXIT.UPSTREAM;
  if (results.some((r) => !r.saved)) return EXIT.FINDING;
  return EXIT.OK;
}

/* -------------------------------------------------------------- declare ---- */

// The domain-signed declaration (docs/DECLARATION.md): a company signs, with its
// own Ed25519 key, a document it publishes at https://<domain>/.well-known/trooth.json
// naming that key, its products, its APIs and its code repositories. `init` makes
// the key and keeps it on this machine; `sign` writes the document; `check` reads
// one (from the site, or a file) and checks every rule. Nothing secret is printed.

function declareDomain(raw, flag = '--domain') {
  const d = String(raw ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!d) fail(EXIT.USAGE, `${flag} <domain> is required.`);
  if (!ID_TYPES.domain.test(d)) fail(EXIT.USAGE, `${flag}: ${String(raw).slice(0, 100)} is not a domain name (lowercase ASCII, IDNA A-labels, no scheme or path).`);
  return d;
}

function defaultKeyPath(domain) { return join(homedir(), '.trooth', 'declaration-key', `${domain}.jwk`); }

function readKeyFile(path) {
  if (!existsSync(path)) fail(EXIT.USAGE, `the key file was not found: ${path}`);
  let text;
  try { text = readFileSync(path, 'utf8'); } catch (e) { fail(EXIT.USAGE, `the key file could not be read: ${e && e.code ? e.code : e}`); }
  try { return readPrivateJwk(text); } catch (e) { fail(EXIT.USAGE, `${path}: ${e.message}`); }
}

function readPublicJwkFile(path) {
  if (!existsSync(path)) fail(EXIT.USAGE, `--add-key: file not found: ${path}`);
  let j;
  try { j = JSON.parse(readFileSync(path, 'utf8')); } catch { fail(EXIT.USAGE, `--add-key: ${path} is not JSON.`); }
  try { const pub = publicJwkOf(j); jwkThumbprint(pub); return pub; } catch (e) { fail(EXIT.USAGE, `--add-key: ${path}: ${e.message}`); }
}

function parseProduct(v) {
  const i = v.indexOf('=');
  const rest = i < 0 ? '' : v.slice(i + 1);
  const j = rest.indexOf('=https://');
  if (i < 1 || j < 1) fail(EXIT.USAGE, `--product is id=name=url, for example widget=Widget=https://acme.com/widget (got ${v.slice(0, 120)}).`);
  return { id: v.slice(0, i), name: rest.slice(0, j), url: rest.slice(j + 1) };
}

function parseApi(v) {
  const parts = v.split(',');
  if (parts.length === 1) return { base_url: parts[0] };
  if (parts.length === 3) return { base_url: parts[0], mcp: { url: parts[1], manifest_sha256: parts[2].toLowerCase() } };
  fail(EXIT.USAGE, `--api is base_url or base_url,mcp_url,manifest_sha256 (got ${v.slice(0, 160)}).`);
}

async function declareCmd() {
  const { flags, positional } = parseArgs('declare');
  const sub = positional[0];
  const rest = positional.slice(1);
  if (!['init', 'sign', 'check'].includes(sub)) fail(EXIT.USAGE, 'trooth declare takes init, sign or check. Try: trooth declare init --domain acme.com');
  const allowed = { init: ['--json', '--domain', '--key'], sign: ['--json', '--domain', '--key', '--record', '--days', '--out', '--product', '--api', '--repo', '--add-key'], check: ['--json', '--domain', '--file', '--no-dns'] }[sub];
  for (const f of Object.keys(flags)) if (!allowed.includes(f)) fail(EXIT.USAGE, `${f} is not a flag of \`trooth declare ${sub}\`. Its flags: ${allowed.join(', ')}.`);

  if (sub === 'init') {
    if (rest.length) fail(EXIT.USAGE, `unexpected argument: ${rest.join(' ')}`);
    const domain = declareDomain(flags['--domain']);
    const path = flags['--key'] || defaultKeyPath(domain);
    if (existsSync(path)) fail(EXIT.USAGE, `${path} already exists; trooth declare init never overwrites a key. Choose another --key path.`);
    const k = generateDeclarationKey();
    try {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      writeFileSync(path, JSON.stringify({ ...k.privateJwk, kid: keyIdFor(domain, k.publicJwk) }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      chmodSync(path, 0o600);
    } catch (e) {
      if (e && e.code === 'EEXIST') fail(EXIT.USAGE, `${path} already exists; trooth declare init never overwrites a key.`);
      fail(EXIT.USAGE, `the key could not be written to ${path}: ${e && e.code ? e.code : e}`);
    }
    const doc = { domain, key_path: path, kid: keyIdFor(domain, k.publicJwk), thumbprint: k.thumbprint, public_jwk: k.publicJwk, pin_txt: pinLine(domain, k.thumbprint) };
    if (asJson) emitJson(doc);
    else {
      out(`${J}key created${X}  ${path} ${D}(mode 0600; the private key never leaves this file)${X}`);
      out(`  kid          ${doc.kid}`);
      out(`  next         trooth declare sign --domain ${domain} --key ${path} --out trooth.json`);
      out(`  ${D}optional DNS pin: ${doc.pin_txt}${X}`);
    }
    return EXIT.OK;
  }

  if (sub === 'sign') {
    if (rest.length) fail(EXIT.USAGE, `unexpected argument: ${rest.join(' ')}`);
    const domain = declareDomain(flags['--domain']);
    if (!flags['--key']) fail(EXIT.USAGE, '--key <path> is required: the private JWK trooth declare init wrote.');
    if (!flags['--out']) fail(EXIT.USAGE, '--out <file> is required: where to write the signed declaration.');
    if (existsSync(flags['--out'])) fail(EXIT.USAGE, `--out will not overwrite ${flags['--out']}; choose a new path.`);
    let days = DEFAULT_VALIDITY_DAYS;
    if (flags['--days'] !== undefined) {
      if (!/^[1-9][0-9]{0,3}$/.test(flags['--days']) || Number(flags['--days']) > MAX_VALIDITY_DAYS) fail(EXIT.USAGE, `--days is a whole number from 1 to ${MAX_VALIDITY_DAYS}.`);
      days = Number(flags['--days']);
    }
    const jwk = readKeyFile(flags['--key']);
    try { if (process.platform !== 'win32' && (statSync(flags['--key']).mode & 0o077)) diag(`note: ${flags['--key']} can be read by other users of this machine; chmod 600 it.`); } catch {}
    let doc;
    try {
      doc = buildDeclaration({
        domain, privateJwk: jwk, days,
        record: flags['--record'] ?? null,
        products: (flags['--product'] || []).map(parseProduct),
        apis: (flags['--api'] || []).map(parseApi),
        repositories: flags['--repo'] || [],
        extraKeys: (flags['--add-key'] || []).map(readPublicJwkFile),
      });
    } catch (e) {
      if (e instanceof DeclarationError) fail(EXIT.USAGE, `the declaration would not check: ${e.message}`);
      throw e;
    }
    const text = JSON.stringify(doc, null, 2) + '\n';
    try { writeFileSync(flags['--out'], text, { flag: 'wx' }); }
    catch (e) { fail(EXIT.USAGE, `could not write ${flags['--out']}: ${e && e.code ? e.code : e}`); }
    const tp = jwkThumbprint(publicJwkOf(jwk));
    const res = { out: flags['--out'], domain, kid: doc.signature.kid, thumbprint: tp, issued_at: doc.issued_at, expires_at: doc.expires_at, sha256: createHash('sha256').update(text, 'utf8').digest('hex'), publish_at: `https://${domain}${DECLARATION_PATH}`, pin_txt: pinLine(domain, tp) };
    if (asJson) emitJson(res);
    else {
      out(`${J}signed${X}  ${flags['--out']}  ${D}by ${res.kid}, valid until ${res.expires_at}${X}`);
      out(`  publish at   ${res.publish_at} ${D}(served directly, no redirect, at most 64 KB)${X}`);
      out(`  ${D}products ${doc.products.length} · apis ${doc.apis.length} · repositories ${doc.repositories.length}${doc.record ? ` · record ${doc.record}` : ''}${X}`);
      out(`  DNS pin      add this TXT record to bind the key to the zone as well:`);
      out(`               ${res.pin_txt}`);
      out(`  then         trooth declare check ${domain}`);
    }
    return EXIT.OK;
  }

  // check
  if (rest.length > 1) fail(EXIT.USAGE, `trooth declare check takes one <domain>, got: ${rest.join(' ')}`);
  if (rest.length && flags['--file']) fail(EXIT.USAGE, 'give a <domain> or --file <path>, not both.');
  if (!rest.length && !flags['--file']) fail(EXIT.USAGE, 'trooth declare check takes a <domain> or --file <path>. Try: trooth declare check acme.com');
  let r, source, url = null, readFailure = null;
  if (flags['--file']) {
    const f = flags['--file'];
    if (!existsSync(f) || !statSync(f).isFile()) fail(EXIT.USAGE, `not a file: ${f}`);
    if (statSync(f).size > 10 * 1024 * 1024) fail(EXIT.USAGE, `${f} is far over the 64 KB a declaration may be.`);
    const domain = flags['--domain'] !== undefined ? declareDomain(flags['--domain']) : null;
    r = checkDeclaration(readFileSync(f), { domain, now: Date.now() });
    source = 'file';
    url = r.domain ? `https://${r.domain}${DECLARATION_PATH}` : null;
  } else {
    if (flags['--domain'] !== undefined) fail(EXIT.USAGE, '--domain goes with --file; with a <domain> the document must name the host it is served from.');
    const domain = declareDomain(rest[0], '<domain>');
    const got = await fetchDeclaration(domain, { timeoutMs: TIMEOUT_MS, userAgent: `trooth-cli/${VERSION}` });
    source = 'network'; url = got.url;
    if (got.status === 'read') r = checkDeclaration(got.bytes, { domain, now: Date.now() });
    else { readFailure = got; r = { status: got.status, reason: got.reason, problems: got.status === 'invalid' ? [got.reason] : [], signature: 'not_checked', sha256: null, domain, issued_at: null, expires_at: null, kid: null, keys: [], thumbprints: [], record: null, products: [], apis: [], repositories: [], host_checked: true }; }
  }
  // The optional zone pin, read over DNS over HTTPS.
  let pin = { status: 'not_read', name: r.domain ? `_trooth-key.${r.domain}` : null, thumbprints: [], reason: flags['--no-dns'] ? 'not asked (--no-dns)' : 'no domain to ask about' };
  if (!flags['--no-dns'] && r.domain) pin = await readKeyPin(r.domain, { timeoutMs: TIMEOUT_MS, dohUrl: (process.env.TROOTH_DOH || DOH_URL) });
  const ps = pinStatus(pin, r.status === 'checked' || r.status === 'expired' ? r.thumbprints : []);
  const doc = {
    url, source, status: r.status, reason: r.reason, problems: r.problems, sha256: r.sha256,
    issued_at: r.issued_at, expires_at: r.expires_at, signature: r.signature, kid: r.kid, keys: r.keys,
    key_pinned_by_dns: ps.pinned, dns_pin: { name: pin.name, status: pin.status, state: ps.state, thumbprints: pin.thumbprints, reason: pin.reason },
    host_checked: r.host_checked, record: r.record, products: r.products, apis: r.apis, repositories: r.repositories,
  };
  if (r.status === 'checked' && ps.state === 'other_key') doc.problems = [...doc.problems, `${pin.name} pins ${ps.thumbprint}, which is not a key in the declaration`];
  if (asJson) emitJson(doc);
  else {
    const ok = (t) => `${J}${t}${X}`, bad = (t) => `${R}${t}${X}`, warn = (t) => `${A}${t}${X}`;
    out(`${B}${r.domain || '(no domain)'}${X}  ${D}declaration ${url || ''}${source === 'file' ? ` (read from ${flags['--file']})` : ''}${X}`);
    const label = r.status === 'checked' ? ok('checked') : r.status === 'absent' ? warn('absent') : r.status === 'not_read' ? warn('not read') : bad(r.status);
    out(`  status       ${label}  ${r.reason || ''}`);
    for (const p of doc.problems.slice(r.status === 'checked' ? 0 : 1)) out(`               ${bad(p)}`);
    if (source === 'file' && !r.host_checked) out(`  ${D}host         not checked: read from a file; pass --domain to require the domain it names${X}`);
    if (r.sha256) out(`  ${D}sha256       ${r.sha256}${X}`);
    if (r.status === 'checked' || r.status === 'expired') {
      for (const k of r.keys) out(`  key          ${k}`);
      out(`  DNS pin      ${ps.state === 'matches' ? ok(`${pin.name} pins ${ps.thumbprint}: the key is bound to the zone as well`) : ps.state === 'other_key' ? bad(`${pin.name} pins ${ps.thumbprint}, which is not a key in the declaration`) : ps.state === 'absent' ? `${D}none at ${pin.name}; to add one: ${pinLine(r.domain, r.thumbprints[0])}${X}` : warn(`not read: ${pin.reason}`)}`);
      if (r.record) out(`  record       ${r.record}`);
      for (const p of r.products) out(`  product      ${p.id}  ${p.name}  ${D}${p.url}${X}`);
      for (const a of r.apis) out(`  api          ${a.base_url}${a.mcp ? `  ${D}MCP ${a.mcp.url} manifest sha256 ${a.mcp.manifest_sha256}${X}` : ''}`);
      for (const x of r.repositories) out(`  repository   ${x}`);
    }
    out(`\n${D}A declaration that checks shows that whoever controlled the site's content when it was read published this key and these subjects. It does not establish the legal entity or a person's authority to act for it. No URL inside it was fetched.${X}`);
  }
  if (r.status === 'checked') return ps.state === 'other_key' ? EXIT.MISMATCH : EXIT.OK;
  if (r.status === 'absent') return EXIT.FINDING;
  if (r.status === 'not_read') return EXIT.UPSTREAM;
  if (r.status === 'expired') return EXIT.EXPIRED;
  if (readFailure) return EXIT.MISMATCH;
  return isSignatureProblem(r) ? EXIT.NOT_TRUSTED : EXIT.MISMATCH;
}

function guardHookUsage(why) { diag(`trooth guard: ${why}`); return 2; }

/** Set for `trooth guard hook`: Claude Code lets the tool run on any exit but 0 and 2. */
let hookMode = false;

async function main() {
  if (cmd === '--version' || cmd === '-v' || cmd === 'version') { out(VERSION); return EXIT.OK; }
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { out(helpText()); return EXIT.OK; }
  if (cmd === 'check') return check();
  if (cmd === 'lint') return lint();
  if (cmd === 'verify') return verifyCmd();
  if (cmd === 'log') return logCmd();
  if (cmd === 'public-record') return publicRecordCmd();
  if (cmd === 'mcp-tools') return mcpToolsCmd();
  if (cmd === 'guard') return guardCmd();
  if (cmd === 'declare') return declareCmd();
  if (Object.prototype.hasOwnProperty.call(RETIRED, cmd)) {
    fail(EXIT.USAGE, `\`trooth ${cmd}\` is retired. ${RETIRED[cmd]} Run \`trooth --help\`.`);
  }
  if (cmd.startsWith('-')) fail(EXIT.USAGE, `unknown flag ${cmd}. Run \`trooth --help\`.`);
  diag(helpText());
  fail(EXIT.USAGE, `unknown command: ${cmd}. Commands: check, lint, verify, log, public-record, mcp-tools, guard, declare.`);
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
  // The hook never fails open: an unexpected failure, or an ask (or a deny reason)
  // that was not delivered, blocks the tool (exit 2) instead of letting it run.
  if (hookMode && (outputFailure || (code !== EXIT.OK && code !== 2))) {
    try { if (!process.stderr.destroyed && process.stderr.writable) process.stderr.write('trooth guard: the hook could not deliver its answer, so the action is stopped.\n', () => {}); } catch {}
    process.exitCode = 2;
    return;
  }
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
