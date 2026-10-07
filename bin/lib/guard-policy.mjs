// bin/lib/guard-policy.mjs - the customer's guard policy (docs/GUARD.md
// section 3, schemas/guard-policy.v1.schema.json): reading it, refusing what
// it cannot mean, and the interception rules that follow from it (which tool
// calls are covered and which host a call is about).
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// Imports only node: built-ins and this package's own modules.

import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { canonicalize, CanonicalizationError } from './jcs.mjs';
import { parseYaml, YamlError } from './yaml-lite.mjs';
import { PINNED_WITNESSES } from './log-trust.mjs';

export class PolicyError extends Error {}

/** Claims the guard can derive from signed, logged Trooth artifacts (docs/GUARD.md section 4). */
export const KNOWN_CLAIMS = [
  'trooth_reading',
  'legal_entity_registry_record',
  'no_sanctions_name_match',
  'no_sam_exclusion_name_match',
  'domain_registration_record',
  'security_txt_published',
  // Named so a policy that asks for it reads, but it is not a signed claim
  // today: a rule requiring it always finds it missing (hold).
  'domain_control_confirmed',
];
export const CHECK_CLAIM = /^check:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export const TRUSTED_KEY_STATUSES = ['active', 'retired_before_use'];
export const DEFAULT_HOST_FROM = ['url', 'endpoint', 'host', 'domain', 'base_url', 'webhook_url', 'email', 'to'];
const ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const TOP_KEYS = ['policy', 'version', 'description', 'applies_to', 'host_from', 'log', 'rules', 'destinations', 'unknown_counterparty', 'source_unreachable'];
const HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', '*'];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const where = (path) => (path ? `${path}: ` : '');

function onlyKeys(obj, allowed, path) {
  for (const k of Object.keys(obj)) {
    if (allowed.includes(k)) continue;
    if (k === 'failMode' || k === 'fail_mode' || k === 'failmode') {
      if (obj[k] === 'allow') throw new PolicyError(`${where(path)}${k}: allow is refused. The guard never fails open on a consequential action; use source_unreachable: hold or deny.`);
      throw new PolicyError(`${where(path)}${k} is not a policy key. Write source_unreachable: hold or deny; the guard's own failMode is an option of createGuard.`);
    }
    throw new PolicyError(`${where(path)}unknown key "${k}". Allowed: ${allowed.join(', ')}.`);
  }
}
function str(v, path, re) {
  if (typeof v !== 'string' || v === '') throw new PolicyError(`${path} must be a non-empty string.`);
  if (re && !re.test(v)) throw new PolicyError(`${path} "${v}" is not in the accepted form.`);
  return v;
}
function strList(v, path, { min = 0, re } = {}) {
  if (!Array.isArray(v)) throw new PolicyError(`${path} must be a list.`);
  if (v.length < min) throw new PolicyError(`${path} must list at least ${min} entr${min === 1 ? 'y' : 'ies'}.`);
  v.forEach((x, i) => str(x, `${path}[${i}]`, re));
  if (new Set(v).size !== v.length) throw new PolicyError(`${path} lists an entry twice.`);
  return [...v];
}
function int(v, path, min, max) {
  if (!Number.isSafeInteger(v)) throw new PolicyError(`${path} must be a whole number.`);
  if (v < min || (max !== undefined && v > max)) throw new PolicyError(`${path} must be between ${min} and ${max ?? 'any'}.`);
  return v;
}
function choice(v, path, options) {
  if (!options.includes(v)) {
    if (v === 'allow') throw new PolicyError(`${path}: allow is refused. The guard never fails open on a consequential action; use ${options.join(' or ')}.`);
    throw new PolicyError(`${path} must be one of ${options.join(', ')}; got ${JSON.stringify(v)}.`);
  }
  return v;
}

/**
 * A host pattern: an exact host, or "*." followed by a host of at least two
 * labels. A bare "*", "*.com" or a pattern with a "*" anywhere else is refused,
 * because it would cover hosts the author did not mean.
 */
export function checkHostPattern(p, path) {
  str(p, path);
  const s = p.toLowerCase();
  if (s.startsWith('*.')) {
    const rest = s.slice(2);
    if (rest.includes('*')) throw new PolicyError(`${path} "${p}": "*" is accepted only as the first label.`);
    if (!isDomainName(rest) || rest.split('.').length < 2) throw new PolicyError(`${path} "${p}": a wildcard must be followed by a domain of at least two labels (not "*" or "*.com").`);
    return s;
  }
  if (s.includes('*')) throw new PolicyError(`${path} "${p}": "*" is accepted only as the first label, as in *.example.com.`);
  if (!isDomainName(s)) throw new PolicyError(`${path} "${p}" is not a host name.`);
  return s;
}

/** Whether a host matches a checked host pattern. "*.a.com" covers b.a.com and a.com's subdomains, not a.com. */
export function hostMatches(pattern, host) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  if (pattern.startsWith('*.')) return h.endsWith(pattern.slice(1)) && h.length > pattern.length - 1;
  return h === pattern;
}

function readRule(r, i, seen) {
  const path = `rules[${i}]`;
  if (!isObj(r)) throw new PolicyError(`${path} must be a mapping with id, require and on_fail.`);
  onlyKeys(r, ['id', 'description', 'require', 'on_fail', 'absolute'], path);
  const id = str(r.id, `${path}.id`, ID);
  if (seen.has(id)) throw new PolicyError(`${path}.id "${id}" is used by another rule; rule ids must be unique.`);
  seen.add(id);
  if (r.description !== undefined) str(r.description, `${path}.description`);
  if (!isObj(r.require)) throw new PolicyError(`${path}.require must be a mapping: { claim: ..., max_age_days: ... } or { signature: valid, key_status: [...] }.`);
  const req = r.require;
  let require;
  if ('claim' in req) {
    onlyKeys(req, ['claim', 'max_age_days'], `${path}.require`);
    const claim = str(req.claim, `${path}.require.claim`);
    if (!KNOWN_CLAIMS.includes(claim) && !CHECK_CLAIM.test(claim)) throw new PolicyError(`${path}.require.claim "${claim}" is not a claim the guard can read. Known: ${KNOWN_CLAIMS.join(', ')}, check:<check_id>.`);
    require = { claim, max_age_days: req.max_age_days === undefined ? null : int(req.max_age_days, `${path}.require.max_age_days`, 1, 36500) };
  } else if ('signature' in req || 'key_status' in req) {
    onlyKeys(req, ['signature', 'key_status'], `${path}.require`);
    if (req.signature !== 'valid') throw new PolicyError(`${path}.require.signature must be "valid".`);
    const ks = req.key_status === undefined ? [...TRUSTED_KEY_STATUSES] : strList(req.key_status, `${path}.require.key_status`, { min: 1 });
    for (const k of ks) if (!TRUSTED_KEY_STATUSES.includes(k)) throw new PolicyError(`${path}.require.key_status "${k}" is not accepted; a key may be ${TRUSTED_KEY_STATUSES.join(' or ')}.`);
    require = { signature: 'valid', key_status: ks };
  } else {
    throw new PolicyError(`${path}.require names neither a claim nor a signature.`);
  }
  const absolute = r.absolute === undefined ? false : r.absolute;
  if (typeof absolute !== 'boolean') throw new PolicyError(`${path}.absolute must be true or false.`);
  const onFail = r.on_fail === undefined ? (absolute ? 'deny' : 'hold') : choice(r.on_fail, `${path}.on_fail`, ['hold', 'deny']);
  // Missing or stale evidence routes to a person; only a failed proof or a
  // rule the customer marked absolute stops the action.
  if (onFail === 'deny' && !absolute) throw new PolicyError(`${path}: on_fail: deny needs absolute: true. Missing or stale evidence routes to a person (hold); only a rule marked absolute denies.`);
  if (absolute && onFail !== 'deny') throw new PolicyError(`${path}: absolute: true with on_fail: hold contradicts itself; an absolute rule that fails denies.`);
  return { id, require, on_fail: onFail, absolute };
}

/** Check a parsed policy document and return the policy the guard uses. Throws PolicyError. */
export function normalizePolicy(doc) {
  if (!isObj(doc)) throw new PolicyError('the policy must be a mapping at the top level.');
  onlyKeys(doc, TOP_KEYS, '');
  const id = str(doc.policy, 'policy', ID);
  const version = int(doc.version, 'version', 1);
  if (doc.description !== undefined) str(doc.description, 'description');
  if (!isObj(doc.applies_to)) throw new PolicyError('applies_to must be a mapping with tools (and, for the http adapter, http).');
  onlyKeys(doc.applies_to, ['tools', 'http'], 'applies_to');
  const tools = doc.applies_to.tools === undefined ? [] : strList(doc.applies_to.tools, 'applies_to.tools', { re: /^[\x21-\x7e]+$/ });
  for (const t of tools) if (/\*\*/.test(t)) throw new PolicyError(`applies_to.tools "${t}": write one "*", not "**".`);
  const http = [];
  if (doc.applies_to.http !== undefined) {
    if (!Array.isArray(doc.applies_to.http)) throw new PolicyError('applies_to.http must be a list of { method, host }.');
    doc.applies_to.http.forEach((h, i) => {
      const p = `applies_to.http[${i}]`;
      if (!isObj(h)) throw new PolicyError(`${p} must be a mapping { method, host }.`);
      onlyKeys(h, ['method', 'host'], p);
      const method = choice(String(h.method ?? '').toUpperCase(), `${p}.method`, HTTP_METHODS);
      http.push({ method, host: checkHostPattern(h.host, `${p}.host`) });
    });
  }
  if (!tools.length && !http.length) throw new PolicyError('applies_to lists no tools and no http destinations, so the policy would cover nothing.');
  const hostFrom = doc.host_from === undefined ? [...DEFAULT_HOST_FROM] : strList(doc.host_from, 'host_from', { min: 1, re: /^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$/ });
  let log = { required: true, min_witnesses: 1 };
  if (doc.log !== undefined) {
    if (!isObj(doc.log)) throw new PolicyError('log must be a mapping { required, min_witnesses }.');
    onlyKeys(doc.log, ['required', 'min_witnesses'], 'log');
    if (doc.log.required !== undefined && typeof doc.log.required !== 'boolean') throw new PolicyError('log.required must be true or false.');
    log = { required: doc.log.required ?? true, min_witnesses: doc.log.min_witnesses === undefined ? 1 : int(doc.log.min_witnesses, 'log.min_witnesses', 0, PINNED_WITNESSES.length) };
  }
  if (!Array.isArray(doc.rules) || !doc.rules.length) throw new PolicyError('rules must list at least one rule.');
  const seen = new Set();
  const rules = doc.rules.map((r, i) => readRule(r, i, seen));
  const destinations = { allowed: [], watch: [] };
  if (doc.destinations !== undefined) {
    if (!isObj(doc.destinations)) throw new PolicyError('destinations must be a mapping { allowed, watch }.');
    onlyKeys(doc.destinations, ['allowed', 'watch'], 'destinations');
    if (doc.destinations.allowed !== undefined) destinations.allowed = strList(doc.destinations.allowed, 'destinations.allowed').map((p, i) => checkHostPattern(p, `destinations.allowed[${i}]`));
    if (doc.destinations.watch !== undefined) destinations.watch = strList(doc.destinations.watch, 'destinations.watch').map((p, i) => (p === '*' ? '*' : checkHostPattern(p, `destinations.watch[${i}]`)));
  }
  const unknown = doc.unknown_counterparty === undefined ? 'hold' : choice(doc.unknown_counterparty, 'unknown_counterparty', ['hold', 'deny']);
  const unreachable = doc.source_unreachable === undefined ? 'hold' : choice(doc.source_unreachable, 'source_unreachable', ['hold', 'deny']);
  let sha256;
  try { sha256 = createHash('sha256').update(canonicalize(doc), 'utf8').digest('hex'); }
  catch (e) { throw new PolicyError(`the policy has no RFC 8785 form: ${e instanceof CanonicalizationError ? e.message : e}`); }
  return Object.freeze({
    id, version, sha256,
    applies_to: { tools, http },
    host_from: hostFrom,
    log,
    rules,
    destinations,
    unknown_counterparty: unknown,
    source_unreachable: unreachable,
    document: doc,
  });
}

/** Parse a policy from YAML-subset or JSON text. Throws PolicyError. */
export function parsePolicy(text, format) {
  if (typeof text !== 'string') throw new PolicyError('the policy is not text.');
  const fmt = format ?? (/^\s*[{]/.test(text) ? 'json' : 'yaml');
  if (fmt !== 'json' && fmt !== 'yaml') throw new PolicyError(`unknown policy format ${format}; use yaml or json.`);
  let doc;
  if (fmt === 'json') {
    try { doc = JSON.parse(text); } catch (e) { throw new PolicyError(`the policy is not valid JSON: ${e.message}`); }
    // A duplicate key in JSON silently keeps the last value; refuse it.
    const dupe = findJsonDuplicate(text);
    if (dupe) throw new PolicyError(`the policy JSON names the key "${dupe}" twice in one object.`);
    if (!jsonIntegersOnly(doc)) throw new PolicyError('the policy JSON holds a number that is not a whole number.');
  } else {
    try { doc = parseYaml(text); } catch (e) { if (e instanceof YamlError) throw new PolicyError(`the policy YAML is not accepted: ${e.message}`); throw e; }
  }
  return normalizePolicy(doc);
}

function jsonIntegersOnly(v) {
  if (typeof v === 'number') return Number.isSafeInteger(v);
  if (Array.isArray(v)) return v.every(jsonIntegersOnly);
  if (isObj(v)) return Object.values(v).every(jsonIntegersOnly);
  return true;
}

/** The first key that appears twice in one JSON object, or null. A small scanner over valid JSON text. */
function findJsonDuplicate(text) {
  const stack = [];
  let i = 0;
  const n = text.length;
  let expectKey = false;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const s = JSON.parse(text.slice(i, j + 1));
      const top = stack[stack.length - 1];
      if (top && top.type === 'obj' && expectKey) {
        if (top.keys.has(s)) return s;
        top.keys.add(s);
        expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (ch === '{') { stack.push({ type: 'obj', keys: new Set() }); expectKey = true; }
    else if (ch === '[') { stack.push({ type: 'arr' }); }
    else if (ch === '}' || ch === ']') { stack.pop(); expectKey = false; }
    else if (ch === ',') { const top = stack[stack.length - 1]; expectKey = !!top && top.type === 'obj'; }
    i++;
  }
  return null;
}

/* ------------------------------------------------------- interception ---- */

function globRe(pattern) {
  return new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 's');
}
const fold = (s) => String(s).normalize('NFKC').toLowerCase();

/**
 * Whether a tool call is covered. A name matches a pattern exactly, with "*"
 * standing for any run of characters. To fail toward checking, a name is
 * also covered when it matches only once case and Unicode compatibility forms
 * are folded (STRIPE.create_payout, a fullwidth letter), and any name that is
 * not plain printable ASCII is covered whenever the policy lists tools at all,
 * because a look-alike letter cannot be told apart from the real one by rule.
 */
export function toolCovered(policy, toolName) {
  const name = String(toolName ?? '');
  const tools = policy.applies_to.tools;
  if (!tools.length) return false;
  if (tools.some((p) => globRe(p).test(name))) return true;
  if (tools.some((p) => globRe(fold(p)).test(fold(name)))) return true;
  if (!/^[\x21-\x7e]+$/.test(name)) return true;
  return false;
}

/** A host as the guard keys records by: lower case, no trailing dot, ASCII (punycode) form. */
export function normalizeHost(h) {
  if (typeof h !== 'string') return null;
  let s = h.trim();
  if (!s) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (isIP(s)) return s.toLowerCase();
  try {
    const u = new URL(`https://${s}/`);
    if (u.username || u.password || u.pathname !== '/' || u.search || u.hash || u.port) return null;
    s = u.hostname;
  } catch { return null; }
  s = s.toLowerCase().replace(/\.$/, '');
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  return s || null;
}

export function isDomainName(s) {
  return typeof s === 'string' && s.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s) && !/^[0-9.]+$/.test(s);
}

/** IP literals, localhost and single-label names: hosts that have no Trooth record. */
export function isNonRecordHost(h) {
  if (!h) return true;
  if (isIP(h)) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa') || h.endsWith('.in-addr.arpa') || h.endsWith('.ip6.arpa')) return true;
  return !isDomainName(h);
}

const EMAIL = /^[^\s@<>"]+@([^\s@<>"]+)$/;
const NAMED_EMAIL = /^[^<>]*<([^\s@<>"]+@[^\s@<>"]+)>$/;

/** The host one typed value names, or null. Strings only: a URL, an email address or a bare host name. */
export function hostOfValue(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim();
  if (!s || s.length > 2048) return null;
  const named = NAMED_EMAIL.exec(s);
  if (named) s = named[1];
  if (/\s/.test(s)) return null;
  // A backslash is read as "/" by WHATWG URL parsers and as part of the user
  // info by others (Python's urllib reads https://a.com\@b.com as b.com), so a
  // value holding one has no single host.
  if (s.includes('\\')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^[^:/]+:\d+$/.test(s)) {
    if (/^mailto:/i.test(s)) return hostOfValue(s.slice(7).split('?')[0]);
    if (!/^https?:\/\//i.test(s)) return null;
    let u;
    try { u = new URL(s); } catch { return null; }
    return normalizeHost(u.hostname);
  }
  const e = EMAIL.exec(s);
  if (e) return normalizeHost(e[1]);
  // host[:port] with no scheme
  const hp = /^([^/:?#]+)(?::\d{1,5})?$/.exec(s);
  if (hp) {
    const h = normalizeHost(hp[1]);
    if (h && (isIP(h) || h === 'localhost' || h.includes('.'))) return h;
  }
  return null;
}

function getPath(obj, path) {
  let cur = obj;
  for (const part of path.split('.')) {
    if (!isObj(cur) || !Object.prototype.hasOwnProperty.call(cur, part)) return undefined;
    cur = cur[part];
  }
  return cur;
}

/**
 * The hosts a tool call's typed arguments name, read only from the fields
 * the policy lists in host_from (or the default list). A prose field (a
 * description, a memo, a message body) is never read, so a host written in
 * text the model or a vendor produced cannot become the target. Returns
 * { hosts: [...distinct], fields: [...], ambiguous: boolean }.
 */
export function targetHosts(policy, toolCall) {
  let args = toolCall?.arguments;
  if (typeof args === 'string') { try { args = JSON.parse(args); } catch { args = undefined; } }
  const found = [];
  const fields = [];
  let unreadable = false;
  if (isObj(args)) {
    for (const f of policy.host_from) {
      const v = getPath(args, f);
      if (v === undefined || v === null) continue;
      const values = Array.isArray(v) ? v : [v];
      for (const x of values) {
        const h = hostOfValue(x);
        if (h) { found.push(h); fields.push(f); }
        // A host field whose value may name a destination the guard cannot read
        // (evil.com/pay, ftp://evil.com, a list of addresses, a backslash) must
        // not let another field decide the target alone.
        else if (typeof x === 'string' && /[./@:\\]/.test(x)) { unreadable = true; fields.push(f); }
      }
    }
  }
  const hosts = [...new Set(found)];
  return { hosts, fields: [...new Set(fields)], ambiguous: hosts.length > 1 || (unreadable && hosts.length > 0) };
}

/**
 * Domains under which unrelated parties each get a name (a public suffix in
 * all but name). A record for one of them never stands for a host under it,
 * so the walk from a host to its parents stops before reaching one. This is
 * a short list, not the Public Suffix List.
 */
export const SHARED_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.sg', 'com.hk', 'co.kr',
  'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'herokuapp.com', 'pages.dev', 'workers.dev', 'appspot.com', 'web.app', 'firebaseapp.com',
  'cloudfront.net', 'azurewebsites.net', 'blob.core.windows.net', 'amazonaws.com', 's3.amazonaws.com', 'blogspot.com', 'onrender.com', 'fly.dev', 'glitch.me',
  'repl.co', 'replit.app', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'r2.dev', 'myshopify.com', 'wordpress.com', 'wixsite.com', 'squarespace.com', 'notion.site', 'webflow.io', 'framer.app', 'carrd.co', 'surge.sh', 'deno.dev', 'run.app', 'cloudfunctions.net', 'supabase.co', 'ddns.net', 'duckdns.org', 'no-ip.org',
  // Platform domains whose owner has a record of its own but whose subdomains customers name
  // (an Azure VM label under cloudapp.azure.com must not stand on azure.com's record).
  'cloudapp.azure.com', 'cloudapp.net', 'core.windows.net', 'azurestaticapps.net', 'azureedge.net', 'azurefd.net', 'trafficmanager.net', 'sharepoint.com',
  'googleusercontent.com', 'firebaseio.com', 'amplifyapp.com', 'elasticbeanstalk.com', 'awsapprunner.com', 'on.aws', 'ondigitalocean.app', 'railway.app',
  'readthedocs.io', 'gitbook.io', 'pythonanywhere.com', 'atlassian.net', 'zendesk.com', 'ngrok.app', 'ngrok.dev', 'hf.space', 'streamlit.app',
]);

/** The exact host, then each parent down to two labels, stopping before a shared suffix. */
export function hostCandidates(host) {
  const labels = host.split('.');
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) {
    const c = labels.slice(i).join('.');
    if (SHARED_SUFFIXES.has(c)) break;
    out.push(c);
  }
  return out;
}

/** Whether `parent` is `host` or one of its parent domains. */
export function isHostOrParent(parent, host) {
  return parent === host || host.endsWith(`.${parent}`);
}
