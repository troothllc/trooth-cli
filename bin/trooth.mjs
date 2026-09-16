#!/usr/bin/env node
// Trooth CLI. Command name: `trooth`
// Copyright 2025-2026 Trooth, LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file in this
// repository, or http://www.apache.org/licenses/LICENSE-2.0
//
// The Trooth Network is one public record per company: identity, products and demos,
// domain and marketing links, people, documents, security and privacy posture,
// procurement terms, relationships and sub-processors — each one witnessed, signed
// and dated. This CLI is the terminal interface to that record.
//
// Commands:
//   trooth check <domain>   Read a company's witnessed record from the public Trooth
//                           Network. Read-only. No key, no account, nothing sent about you.
//   trooth lint [path]      Read the infrastructure THIS repository declares and print
//                           the declared facts plus a canonical digest of them.
//                           Fully local. Offline. Your source never leaves the machine.
//   trooth --help           Show help.   trooth --version  Show version.
//
// WHAT THIS TOOL DOES NOT DO, ON PURPOSE:
//   It does not score, rate, rank, grade or tier a company or a repository.
//   It does not check anything against a named certification, standard or regulation.
//   It does not produce a verdict, a pass mark or a percentage.
//   It publishes facts and counts, reported apart, and never adds them into one number.
//
// Exit codes (stable, for scripts):
//   0  ok                      (listed; lint read at least one declaration; help/version)
//   1  finding                 (domain not listed; lint found nothing to read)
//   2  usage error             (missing argument, unknown flag or command, unreadable path)
//   3  network/upstream error  (Trooth unreachable, non-2xx, malformed response)
//
// With --json, stdout carries exactly one JSON document and nothing else. Every
// diagnostic goes to stderr.

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { join, relative, extname, basename } from 'node:path';

const API = process.env.TROOTH_API || 'https://api.trooth.co';
const require = createRequire(import.meta.url);
let VERSION = '0.4.0';
try { VERSION = require('../package.json').version; } catch {}

const EXIT = { OK: 0, FINDING: 1, USAGE: 2, UPSTREAM: 3 };

// Colour only when stdout is a TTY and NO_COLOR is unset, so piped output is clean.
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
  lint:  { bool: ['--json'], value: [] },
};

/** Commands that existed in an earlier release and are gone. Naming them explicitly
 *  means an old README, an old CI job or an old blog post gets a sentence that says
 *  what happened, instead of "unknown command". */
const RETIRED = {
  scan: 'Trooth does not scan infrastructure against a standard and does not issue a verdict. `trooth lint` reads what your infrastructure declares and prints those facts, locally.',
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
  trooth check <domain>     Read a company's witnessed record on the Trooth Network
  trooth lint [path]        Read what your infrastructure declares, locally. Offline.
  trooth --help | --version

${B}Examples${X}
  trooth check stripe.com                ${D}# read a company's witnessed record${X}
  trooth check trooth.co --json          ${D}# one JSON document on stdout, for scripting${X}
  trooth lint ./infra                    ${D}# read declared facts + print a canonical digest${X}
  trooth lint --json >> attestation.json ${D}# the same facts, for a CI artifact${X}

${B}Flags${X}
  --json                    machine-readable JSON on stdout; diagnostics on stderr

${B}Exit codes${X}
  0 ok   1 finding (not listed / nothing declared)   2 usage error   3 Trooth unreachable

${D}check reads only public, already-published records. No key, no account.
lint is entirely local: it opens files, and opens no sockets. Your source never leaves.
Trooth publishes facts and counts, never one number that sums a company up.
Trooth automates. Trooth never signs for you.${X}
`;
}

/* -------------------------------------------------------------- fetch ---- */

async function callTrooth(path, init, what) {
  let res;
  try {
    res = await fetch(`${API}${path}`, {
      ...init,
      headers: { accept: 'application/json', 'user-agent': `trooth-cli/${VERSION}`, ...(init && init.headers) },
    });
  } catch (e) {
    fail(EXIT.UPSTREAM, `could not reach ${what} at ${API}: ${e && e.message ? e.message : e}`);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    fail(EXIT.UPSTREAM, `${what} returned HTTP ${res.status}.${body ? ' ' + body.slice(0, 300).replace(/\s+/g, ' ') : ''}`, { http_status: res.status });
  }
  try { return await res.json(); }
  catch { fail(EXIT.UPSTREAM, `${what} returned a response that is not JSON.`); }
}

/* --------------------------------------------------------------- check ---- */

function normalizeDomain(input) {
  if (!input) return '';
  let s = String(input).trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, '');
  s = s.replace(/\/.*$/, '');
  s = s.replace(/^www\./, '');
  s = s.replace(/\.$/, '');
  return s;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  return d.toISOString().slice(0, 10);
}

function count(obj) {
  if (!obj || typeof obj !== 'object') return null;
  if (typeof obj.passed !== 'number' || typeof obj.total !== 'number') return null;
  return { passed: obj.passed, total: obj.total };
}

function projectRecord(v, domain) {
  const events = Array.isArray(v.events)
    ? v.events.filter((e) => e && e.type).map((e) => ({ type: String(e.type), at: e.at, detail: e.detail }))
    : [];
  const rec = {
    domain,
    listed: true,
    company_name: v.company_name || domain,
    witnessed_at: v.passed_at || null,
    first_published_at: v.first_published_at || null,
    badge_id: v.badge_id || null,
    probes: count(v.probes),
    attested: count(v.attested),
    events,
    receipt_signature: v.receipt_signature || null,
    authority_key_id: v.authority_key_id || null,
    verify_keys: `${API}/public/keys`,
    record_url: `https://trooth.co/network/${encodeURIComponent(domain)}`,
  };
  if (v.category) rec.category = String(v.category);
  if (v.description) rec.description = String(v.description);
  return scrub(rec);
}

async function check() {
  const { positional } = parseArgs('check');
  if (positional.length > 1) fail(EXIT.USAGE, `check takes one <domain>, got: ${positional.join(' ')}`);
  const domain = normalizeDomain(positional[0]);
  if (!domain) fail(EXIT.USAGE, 'missing <domain>. Try: trooth check stripe.com');

  const data = await callTrooth('/directory/api/vendors', { method: 'GET' }, 'the Trooth Network');
  const vendors = Array.isArray(data && data.vendors) ? data.vendors : [];
  const vendor = vendors.find((v) => v && normalizeDomain(v.domain) === domain) || null;

  if (!vendor) {
    if (asJson) {
      emitJson({ domain, listed: false, record_url: `https://trooth.co/network/${encodeURIComponent(domain)}` });
    } else {
      out(`\n${B}${domain}${X} ${D}//${X} ${A}not listed on the Trooth Network yet${X}`);
      out(`\n${D}No witnessed record has been published for this domain. That is not a`);
      out(`judgement. It simply has not been witnessed. A company gets a record by`);
      out(`listing at ${X}${C}https://trooth.co/get-started${X}${D}: Trooth reads its public surface and`);
      out(`publishes a signed, dated record that anyone — or any agent — can check.${X}\n`);
    }
    process.exit(EXIT.FINDING);
  }

  const rec = projectRecord(vendor, domain);
  if (asJson) { emitJson(rec); process.exit(EXIT.OK); }

  const when = fmtDate(rec.witnessed_at);
  const since = fmtDate(rec.first_published_at);
  out(`\n${J}${B}Trooth Network${X} ${D}// witnessed · public · read-only //${X}`);
  out(`${B}${rec.company_name}${X}   ${C}${domain}${X}`);
  out(`Standing: ${J}listed and witnessed${X}` +
      (when ? `   ${D}witnessed ${when}${X}` : `   ${D}date not published${X}`) +
      (since ? `   ${D}first published ${since}${X}` : ''));

  const line = [];
  if (rec.probes) line.push(`${B}Live probes${X} ${rec.probes.passed}/${rec.probes.total}`);
  if (rec.attested) line.push(`${B}Attestations${X} ${rec.attested.passed}/${rec.attested.total}`);
  if (line.length) {
    out(`\n${line.join('     ')}`);
    out(`${D}Probes are checks Trooth read for itself. Attestations are the company's own declarations.`);
    out(`They are counts, reported apart on purpose. Trooth never adds them up into one number.${X}`);
  }

  const ids = [];
  if (rec.badge_id) ids.push(`${D}Badge ${rec.badge_id}${X}`);
  if (rec.authority_key_id) ids.push(`${D}Key ${rec.authority_key_id}${X}`);
  if (ids.length) out(ids.join('   '));

  if (rec.events.length) {
    out(`\n${B}Recent witness events${X}`);
    for (const e of rec.events.slice(0, 3)) {
      out(`  ${J}•${X} ${D}${fmtDate(e.at)}${X}  ${e.type.replace(/_/g, ' ')}${e.detail ? `${D}  ${e.detail}${X}` : ''}`);
    }
  }

  out(`\n${D}A witnessed, point-in-time reading of public evidence. Not a certification. Not one number.`);
  out(`Full record: ${X}${C}${rec.record_url}${X}${D}   ·   Signing keys: ${rec.verify_keys}${X}\n`);
  process.exit(EXIT.OK);
}

/* ---------------------------------------------------------------- lint ---- */
/* WHAT lint IS, AND WHAT IT IS CAREFULLY NOT.
 *
 * It reads the infrastructure a repository DECLARES and reports those
 * declarations as facts: how many storage resources declare encryption, which
 * regions appear, how many rules declare exposure to the whole internet. It
 * does not judge them. There is no verdict, no pass mark, no severity, no
 * score, and nothing is checked against a named standard or regulation.
 * Declaring public ingress is not a failing; a load balancer is supposed to be
 * public. What the facts mean is the reader's call.
 *
 * It opens files and opens no sockets. Nothing about the repository leaves the
 * machine. The digest at the end is a SHA-256 over the canonical fact document
 * with the timestamp excluded, so the same tree always produces the same digest
 * and you can record it as evidence that a given state was observed, without
 * publishing the tree it came from.
 *
 * It is a declaration reader, not an HCL parser: .tf.json, Kubernetes YAML and
 * terraform plan JSON are parsed properly, and .tf files are read at the
 * attribute level. That limit is stated in the output rather than hidden. */

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.terraform', '.next', 'dist', 'build', 'vendor',
  '.venv', 'venv', '__pycache__', '.cache', 'coverage', '.turbo',
]);
const MAX_FILES = 5000;
const MAX_BYTES = 4 * 1024 * 1024;

function walk(root) {
  const found = [];
  const stack = [root];
  let st;
  try { st = statSync(root); } catch { return found; }
  if (st.isFile()) return [root];
  while (stack.length && found.length < MAX_FILES) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(join(dir, e.name)); continue; }
      if (!e.isFile()) continue;
      const n = e.name.toLowerCase();
      const ext = extname(n);
      const keep =
        ext === '.tf' || n.endsWith('.tf.json') ||
        ext === '.yaml' || ext === '.yml' || ext === '.json' ||
        n === 'dockerfile' || n.startsWith('dockerfile.');
      if (keep) found.push(join(dir, e.name));
      if (found.length >= MAX_FILES) break;
    }
  }
  return found;
}

const REGION_RE = /\b(?:region|location|availability_zone|aws_region)\s*[:=]\s*["']([A-Za-z0-9][A-Za-z0-9._-]{2,40})["']/g;
const RESOURCE_RE = /\bresource\s+"([a-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"/g;
const ENCRYPT_RE = /(?:encrypted|encryption|kms_key|sse_algorithm|server_side_encryption|encrypt_at_rest)/i;
// Classification runs on the RESOURCE TYPE TOKEN (aws_db_instance, not the body
// text), matched as a substring. An earlier version wrapped these in \b, which
// never fires inside a snake_case identifier: \bdynamodb\b cannot match
// aws_dynamodb_table because the underscore either side is a word character, so
// every storage resource whose name was not the bare word "bucket" went
// uncounted. Substring matching on the type is both simpler and correct.
const STORAGE_TYPE = /(bucket|storage|blob|disk|volume|filestore|_db|database|rds|dynamodb|_sql|redis|memcache|elasticache|efs|fileshare|cosmos|bigtable|spanner)/i;
const LOGGING_TYPE = /(log|trail|audit|monitor|insight|diagnostic)/i;
const IDENTITY_TYPE = /(iam|role|policy|service_account|serviceaccount|rbac|identity|access_key|keyring|secret)/i;
const OPEN_CIDR_RE = /(?:"0\.0\.0\.0\/0"|'0\.0\.0\.0\/0'|"::\/0"|'::\/0')/;
const PUBLIC_RE = /\b(?:publicly_accessible\s*[:=]\s*true|acl\s*[:=]\s*["']public-read|public_network_access_enabled\s*[:=]\s*true|type\s*:\s*LoadBalancer|type\s*:\s*NodePort)\b/;
// A literal that looks like a credential sitting in the file. Reported as a
// count only: no file name, no line, and never the value itself.
const SECRET_RE = /\b(?:password|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\s*[:=]\s*["'][^"'${}\n]{8,}["']/i;

function classify(file, text) {
  const n = basename(file).toLowerCase();
  if (n.endsWith('.tf')) return 'terraform';
  if (n.endsWith('.tf.json')) return 'terraform';
  if (n === 'dockerfile' || n.startsWith('dockerfile.')) return 'container';
  if (n.endsWith('.yaml') || n.endsWith('.yml')) {
    return /^\s*apiVersion\s*:/m.test(text) && /^\s*kind\s*:/m.test(text) ? 'kubernetes' : null;
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

function lint() {
  const { positional } = parseArgs('lint');
  if (positional.length > 1) fail(EXIT.USAGE, `lint takes one optional [path], got: ${positional.join(' ')}`);
  const target = positional[0] || '.';
  if (!existsSync(target)) fail(EXIT.USAGE, `path not found: ${target}`);

  const files = walk(target);
  const byKind = { terraform: 0, 'terraform-plan': 0, kubernetes: 0, container: 0 };
  const regions = new Set();
  const resourceTypes = new Map();
  let read = 0, storage = 0, storageEncrypted = 0, logging = 0, identity = 0;
  let openIngress = 0, publicAccess = 0, inlineCredentials = 0;

  for (const f of files) {
    let text;
    try {
      if (statSync(f).size > MAX_BYTES) continue;
      text = readFileSync(f, 'utf8');
    } catch { continue; }
    const kind = classify(f, text);
    if (!kind) continue;
    byKind[kind]++;
    read++;

    for (const m of text.matchAll(REGION_RE)) regions.add(m[1]);

    if (kind === 'terraform') {
      for (const m of text.matchAll(RESOURCE_RE)) {
        resourceTypes.set(m[1], (resourceTypes.get(m[1]) || 0) + 1);
      }
    }

    // Terraform is split on top-level resource blocks so an attribute in one
    // resource is never credited to another; every other kind is read whole.
    const blocks = kind === 'terraform' ? text.split(/\n(?=resource\s+")/) : [text];
    for (const b of blocks) {
      const header = b.match(/^resource\s+"([a-z0-9_]+)"/);
      const subject = header ? header[1] : b;
      if (STORAGE_TYPE.test(subject)) { storage++; if (ENCRYPT_RE.test(b)) storageEncrypted++; }
      if (LOGGING_TYPE.test(subject)) logging++;
      if (IDENTITY_TYPE.test(subject)) identity++;
      if (OPEN_CIDR_RE.test(b)) openIngress++;
      if (PUBLIC_RE.test(b)) publicAccess++;
    }
    for (const line of text.split('\n')) if (SECRET_RE.test(line)) inlineCredentials++;
  }

  if (read === 0) {
    const msg = `no infrastructure declarations found under ${target}.`;
    diag(`${A}nothing to read${X} ${msg}`);
    diag(`${D}  lint reads .tf, .tf.json, Kubernetes YAML (apiVersion + kind), terraform plan`);
    diag(`  JSON and Dockerfiles. ${files.length} file(s) were opened and none matched.${X}`);
    if (asJson) emitJson({ ok: false, error: msg, exit: EXIT.FINDING, files_opened: files.length });
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
    storage_declarations: storage,
    storage_declaring_encryption: storageEncrypted,
    logging_declarations: logging,
    identity_declarations: identity,
    declarations_open_to_any_address: openIngress,
    declarations_marked_public: publicAccess,
    inline_credential_literals: inlineCredentials,
  };

  const digest = createHash('sha256').update(canonical(facts)).digest('hex');
  const doc = {
    tool: 'trooth-lint',
    cli_version: VERSION,
    observed_at: new Date().toISOString(),
    root: (() => { const r = relative(process.cwd(), target); return !r ? '.' : r.startsWith('..') ? target : r; })(),
    facts,
    digest: `sha256:${digest}`,
    note: 'Declared facts only. Read locally; nothing was transmitted. No score, no verdict, no assessment against any standard.',
  };

  if (asJson) { emitJson(doc); process.exit(EXIT.OK); }

  out(`\n${J}${B}trooth lint${X} ${D}// local · offline · declarations only //${X}`);
  out(`${D}${doc.root}   ${read} declaration file(s) read${X}`);

  const src = Object.entries(facts.sources).map(([k, n]) => `${k} ${n}`).join(' · ');
  if (src) out(`${D}${src}${X}`);

  out(`\n${B}Declared${X}`);
  const row = (label, value) => out(`  ${label.padEnd(40)} ${value}`);
  row('Regions and zones', facts.regions_and_zones_declared.length ? facts.regions_and_zones_declared.join(', ') : `${D}none declared${X}`);
  row('Storage declarations', `${facts.storage_declarations}`);
  row('  of those declaring encryption', `${facts.storage_declaring_encryption}`);
  row('Logging declarations', `${facts.logging_declarations}`);
  row('Identity declarations', `${facts.identity_declarations}`);
  row('Open to any address (0.0.0.0/0, ::/0)', `${facts.declarations_open_to_any_address}`);
  row('Marked public', `${facts.declarations_marked_public}`);
  row('Inline credential literals', `${facts.inline_credential_literals}`);

  if (topTypes.length) {
    out(`\n${B}Most declared resource types${X}`);
    for (const t of topTypes.slice(0, 6)) out(`  ${String(t.count).padStart(4)}  ${D}${t.type}${X}`);
  }

  out(`\n${B}Digest${X}  ${C}${doc.digest}${X}`);
  out(`${D}A SHA-256 over the facts above, in canonical form, with the timestamp excluded.`);
  out(`The same tree always produces the same digest, so you can record it as evidence`);
  out(`that a state was observed without publishing the tree it came from.${X}`);

  out(`\n${D}Counts of what the files declare. Not a judgement: a public load balancer is`);
  out(`supposed to be public. Trooth issues no verdict here and checks nothing against`);
  out(`any standard. Nothing left this machine: lint opens files and opens no sockets.`);
  out(`Publish what you choose on your record at ${X}${C}https://trooth.co/dashboard${X}${D}.${X}\n`);
  process.exit(EXIT.OK);
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
