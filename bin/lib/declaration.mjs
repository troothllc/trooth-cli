// bin/lib/declaration.mjs - the domain-signed declaration (docs/DECLARATION.md):
// https://<domain>/.well-known/trooth.json, a document a company publishes on
// its own site and signs with its own Ed25519 key, naming that key, its
// products, its APIs and its code repositories.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// What a declaration that checks shows: whoever controlled the site's content
// when it was read published this key and these subjects. It does not establish
// the legal entity or a person's authority to act for it. The declaration is
// self-signed; what Trooth adds is a signed, logged reading of it, so the first
// key seen and every later change are public.
//
// No URL inside a declaration is ever fetched. The only requests this module
// makes are the declaration itself (https://<domain>/.well-known/trooth.json,
// no redirects, 64 KB at most, a deadline) and one DNS-over-HTTPS query for the
// optional key pin at _trooth-key.<domain>.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';
import { canonicalize } from './jcs.mjs';

export const DECLARATION_FORMAT = 'trooth.declaration.v1';
export const DECLARATION_PATH = '/.well-known/trooth.json';
export const MAX_DECLARATION_BYTES = 64 * 1024;
export const MAX_VALIDITY_DAYS = 400;
export const DEFAULT_VALIDITY_DAYS = 365;
export const REPOSITORY_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org'];
export const DOH_URL = 'https://cloudflare-dns.com/dns-query';
export const RECORD_PREFIX = 'https://trooth.co/network/company/';
const DAY = 86400000;
const CLOCK_SKEW_MS = 5 * 60000;
const MAX_KEYS = 8;
const MAX_ITEMS = 100;
const TOP_LEVEL = ['format', 'domain', 'issued_at', 'expires_at', 'record', 'keys', 'products', 'apis', 'repositories', 'signature'];
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PRODUCT_ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const THUMBPRINT_RE = /^[A-Za-z0-9_-]{43}$/;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const REPO_RE = /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)\/([A-Za-z0-9_.-]{1,100})\/?$/;

export class DeclarationError extends Error {}

/* ------------------------------------------------------------- keys ---- */

/** The RFC 7638 JWK thumbprint of an Ed25519 public key: SHA-256 over {"crv","kty","x"}, base64url. */
export function jwkThumbprint(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || !B64URL_32.test(jwk.x)) throw new DeclarationError('not an Ed25519 public JWK (kty OKP, crv Ed25519, x of 32 bytes base64url)');
  const members = `{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`;
  return createHash('sha256').update(members, 'utf8').digest('base64url');
}

/** The key id a declaration names a key by: <domain>#<thumbprint>. */
export function keyIdFor(domain, jwk) { return `${domain}#${jwkThumbprint(jwk)}`; }

/** The public JWK (kty, crv, x) of a private or public Ed25519 JWK. */
export function publicJwkOf(jwk) {
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') throw new DeclarationError('not an Ed25519 JWK');
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}

/** A new Ed25519 key pair: the private JWK (keep it secret) and the public JWK. */
export function generateDeclarationKey() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const priv = privateKey.export({ format: 'jwk' });
  const privateJwk = { kty: 'OKP', crv: 'Ed25519', x: priv.x, d: priv.d };
  return { privateJwk, publicJwk: publicJwkOf(privateJwk), thumbprint: jwkThumbprint(privateJwk) };
}

/** Read a private JWK (as text or an object) and check that its public half matches its private half. */
export function readPrivateJwk(input) {
  let jwk = input;
  if (typeof input === 'string') { try { jwk = JSON.parse(input); } catch { throw new DeclarationError('the key file is not JSON'); } }
  if (!jwk || jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.d !== 'string' || typeof jwk.x !== 'string') throw new DeclarationError('the key file is not a private Ed25519 JWK (kty OKP, crv Ed25519, x and d)');
  let derived;
  try { derived = createPublicKey(createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d }, format: 'jwk' })).export({ format: 'jwk' }).x; }
  catch { throw new DeclarationError('the key file does not hold a usable Ed25519 key'); }
  if (derived !== jwk.x) throw new DeclarationError('the key file is inconsistent: x is not the public half of d');
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d };
}

/** The DNS TXT line that pins a key to the zone. */
export function pinLine(domain, thumbprint) { return `_trooth-key.${domain} TXT "trooth-key=${thumbprint}"`; }

/* ------------------------------------------------------------ build ---- */

/** The bytes a declaration's signature covers: RFC 8785 of the document without `signature`. */
export function signingBytes(doc) {
  const { signature, ...rest } = doc;
  void signature;
  return Buffer.from(canonicalize(rest), 'utf8');
}

/** Sign a declaration (any `signature` member is replaced) with a private JWK. */
export function signDeclaration(doc, privateJwk) {
  const jwk = readPrivateJwk(privateJwk);
  const kid = keyIdFor(doc.domain, jwk);
  const priv = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d }, format: 'jwk' });
  const { signature, ...rest } = doc;
  void signature;
  const value = edSign(null, signingBytes(rest), priv).toString('base64');
  return { ...rest, signature: { kid, alg: 'Ed25519', canonicalization: 'RFC8785', value: `ed25519:${value}` } };
}

/** ISO 8601 UTC to the second. */
export function isoSeconds(ms) { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'); }

/**
 * Build and sign a declaration. `products` [{id, name, url}], `apis`
 * [{base_url, mcp?: {url, manifest_sha256}}], `repositories` [url]. The key
 * named first in `keys` is the signing key; `extraKeys` (public JWKs) are
 * listed after it, for a key rotation. Throws DeclarationError when the result
 * would not check.
 */
export function buildDeclaration({ domain, privateJwk, now = Date.now(), days = DEFAULT_VALIDITY_DAYS, record = null, products = [], apis = [], repositories = [], extraKeys = [] }) {
  if (!Number.isInteger(days) || days < 1 || days > MAX_VALIDITY_DAYS) throw new DeclarationError(`the validity is 1 to ${MAX_VALIDITY_DAYS} days`);
  const jwk = readPrivateJwk(privateJwk);
  const pub = publicJwkOf(jwk);
  const issued = isoSeconds(now);
  const doc = {
    format: DECLARATION_FORMAT,
    domain,
    issued_at: issued,
    expires_at: isoSeconds(Date.parse(issued) + days * DAY),
    ...(record ? { record } : {}),
    keys: [pub, ...extraKeys.map(publicJwkOf)].map((k) => ({ kid: keyIdFor(domain, k), ...k })),
    products,
    apis,
    repositories,
  };
  const signed = signDeclaration(doc, jwk);
  const r = checkDeclaration(signed, { domain, now });
  if (r.status !== 'checked') throw new DeclarationError(r.problems.join('; ') || r.reason);
  return signed;
}

/* ------------------------------------------------------------ check ---- */

/** Whether `host` is `domain` or a subdomain of it. */
export function hostInDomain(host, domain) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  return h === domain || h.endsWith(`.${domain}`);
}

function urlProblem(raw, domain, what) {
  if (typeof raw !== 'string' || raw.length > 2000) return `${what} is not a URL string`;
  let u;
  try { u = new URL(raw); } catch { return `${what} is not a URL`; }
  if (u.protocol !== 'https:') return `${what} is not https`;
  if (u.username || u.password) return `${what} carries credentials`;
  if (u.port) return `${what} names a port`;
  if (u.hash) return `${what} carries a fragment`;
  if (!hostInDomain(u.hostname, domain)) return `${what} is on ${u.hostname}, which is not ${domain} or a subdomain of it`;
  return null;
}

const nonEmptyString = (v, max = 200) => typeof v === 'string' && v.trim().length > 0 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');

/**
 * Check a declaration against every rule in docs/DECLARATION.md section 2.
 * `input` is the bytes served (Buffer or string) or a parsed object. `domain`
 * is the host it was served from (null when read from a file and no domain was
 * given: then the document's own domain is used and the served-host rule is
 * reported as not checked).
 *
 * Returns { status: 'checked' | 'invalid' | 'expired', reason, problems[],
 * signature: 'valid' | 'invalid' | 'not_checked', sha256, domain, issued_at,
 * expires_at, kid, keys[kid], thumbprints[], products, apis, repositories,
 * record, host_checked }. Only a 'checked' result carries subjects.
 */
export function checkDeclaration(input, { domain = null, now = Date.now() } = {}) {
  const problems = [];
  const res = { status: 'invalid', reason: null, problems, signature: 'not_checked', sha256: null, domain: null, issued_at: null, expires_at: null, kid: null, keys: [], thumbprints: [], record: null, products: [], apis: [], repositories: [], host_checked: domain !== null };
  const done = (status, reason) => { res.status = status; res.reason = reason; if (status !== 'checked') { res.products = []; res.apis = []; res.repositories = []; res.record = null; } return res; };
  let doc = input;
  if (typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
    res.sha256 = sha256Hex(bytes);
    if (bytes.length > MAX_DECLARATION_BYTES) { problems.push(`the document is ${bytes.length} bytes, over the ${MAX_DECLARATION_BYTES}-byte limit`); return done('invalid', problems[0]); }
    try { doc = JSON.parse(bytes.toString('utf8')); } catch { problems.push('the document is not valid JSON'); return done('invalid', problems[0]); }
  } else {
    try { const text = JSON.stringify(input); res.sha256 = sha256Hex(Buffer.from(text, 'utf8')); if (Buffer.byteLength(text) > MAX_DECLARATION_BYTES) { problems.push(`the document is over the ${MAX_DECLARATION_BYTES}-byte limit`); return done('invalid', problems[0]); } } catch {}
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) { problems.push('the document is not a JSON object'); return done('invalid', problems[0]); }
  if (doc.format !== DECLARATION_FORMAT) problems.push(`format is not ${DECLARATION_FORMAT}`);
  for (const k of Object.keys(doc)) if (!TOP_LEVEL.includes(k)) problems.push(`unknown member ${JSON.stringify(k).slice(0, 40)}`);

  // The domain: the host it is served from.
  if (typeof doc.domain !== 'string' || !DOMAIN_RE.test(doc.domain)) problems.push('domain is not a lowercase domain name');
  else if (domain !== null && doc.domain !== domain) problems.push(`domain is ${doc.domain}, but the document was served from ${domain}`);
  const dom = domain ?? (typeof doc.domain === 'string' && DOMAIN_RE.test(doc.domain) ? doc.domain : null);
  res.domain = dom;

  // Times.
  const issued = typeof doc.issued_at === 'string' && TIME_RE.test(doc.issued_at) ? Date.parse(doc.issued_at) : NaN;
  const expires = typeof doc.expires_at === 'string' && TIME_RE.test(doc.expires_at) ? Date.parse(doc.expires_at) : NaN;
  if (!Number.isFinite(issued)) problems.push('issued_at is not an ISO 8601 UTC time');
  if (!Number.isFinite(expires)) problems.push('expires_at is not an ISO 8601 UTC time');
  if (Number.isFinite(issued) && Number.isFinite(expires)) {
    if (expires <= issued) problems.push('expires_at is not after issued_at');
    else if (expires - issued > MAX_VALIDITY_DAYS * DAY) problems.push(`expires_at is more than ${MAX_VALIDITY_DAYS} days after issued_at`);
  }
  if (Number.isFinite(issued) && issued > now + CLOCK_SKEW_MS) problems.push('issued_at is in the future');
  if (Number.isFinite(issued)) res.issued_at = doc.issued_at;
  if (Number.isFinite(expires)) res.expires_at = doc.expires_at;

  // The company's Trooth record (optional).
  if (doc.record !== undefined && doc.record !== null) {
    let ok = false;
    if (typeof doc.record === 'string' && doc.record.startsWith(RECORD_PREFIX)) ok = SLUG_RE.test(doc.record.slice(RECORD_PREFIX.length));
    if (!ok) problems.push(`record is not a Trooth company record URL (${RECORD_PREFIX}<slug>)`);
    else res.record = doc.record;
  }

  // Keys.
  const keys = [];
  if (!Array.isArray(doc.keys) || doc.keys.length === 0) problems.push('keys is not a non-empty array');
  else if (doc.keys.length > MAX_KEYS) problems.push(`keys holds more than ${MAX_KEYS} keys`);
  else {
    for (const [i, k] of doc.keys.entries()) {
      if (!k || typeof k !== 'object' || Array.isArray(k)) { problems.push(`keys[${i}] is not an object`); continue; }
      const extra = Object.keys(k).filter((m) => !['kid', 'kty', 'crv', 'x'].includes(m));
      if (extra.includes('d')) { problems.push(`keys[${i}] holds a private key (d); it must never be published`); continue; }
      if (extra.length) { problems.push(`keys[${i}] has members other than kid, kty, crv and x`); continue; }
      let tp;
      try { tp = jwkThumbprint(k); } catch (e) { problems.push(`keys[${i}]: ${e.message}`); continue; }
      if (dom && k.kid !== `${dom}#${tp}`) { problems.push(`keys[${i}].kid is not ${dom}#<its RFC 7638 thumbprint>`); continue; }
      if (keys.some((x) => x.kid === k.kid)) { problems.push(`keys[${i}] repeats ${k.kid}`); continue; }
      keys.push({ kid: k.kid, x: k.x, thumbprint: tp });
    }
  }
  res.keys = keys.map((k) => k.kid);
  res.thumbprints = keys.map((k) => k.thumbprint);

  // Products.
  const products = [];
  if (doc.products !== undefined) {
    if (!Array.isArray(doc.products) || doc.products.length > MAX_ITEMS) problems.push(`products is not an array of at most ${MAX_ITEMS}`);
    else for (const [i, p] of doc.products.entries()) {
      if (!p || typeof p !== 'object' || Array.isArray(p) || Object.keys(p).some((m) => !['id', 'name', 'url'].includes(m))) { problems.push(`products[${i}] is not {id, name, url}`); continue; }
      if (typeof p.id !== 'string' || !PRODUCT_ID_RE.test(p.id)) { problems.push(`products[${i}].id does not match ^[a-z0-9][a-z0-9-]{0,62}$`); continue; }
      if (products.some((x) => x.id === p.id)) { problems.push(`products[${i}] repeats the id ${p.id}`); continue; }
      if (!nonEmptyString(p.name)) { problems.push(`products[${i}].name is not a name of 1 to 200 characters`); continue; }
      const up = dom ? urlProblem(p.url, dom, `products[${i}].url`) : 'no domain to check the url against';
      if (up) { problems.push(up); continue; }
      products.push({ id: p.id, name: p.name, url: p.url });
    }
  }
  // APIs.
  const apis = [];
  if (doc.apis !== undefined) {
    if (!Array.isArray(doc.apis) || doc.apis.length > MAX_ITEMS) problems.push(`apis is not an array of at most ${MAX_ITEMS}`);
    else for (const [i, a] of doc.apis.entries()) {
      if (!a || typeof a !== 'object' || Array.isArray(a) || Object.keys(a).some((m) => !['base_url', 'mcp'].includes(m))) { problems.push(`apis[${i}] is not {base_url, mcp?}`); continue; }
      const up = dom ? urlProblem(a.base_url, dom, `apis[${i}].base_url`) : 'no domain to check the url against';
      if (up) { problems.push(up); continue; }
      const out = { base_url: a.base_url };
      if (a.mcp !== undefined && a.mcp !== null) {
        const m = a.mcp;
        if (!m || typeof m !== 'object' || Array.isArray(m) || Object.keys(m).some((x) => !['url', 'manifest_sha256'].includes(x))) { problems.push(`apis[${i}].mcp is not {url, manifest_sha256}`); continue; }
        const mp = urlProblem(m.url, dom, `apis[${i}].mcp.url`);
        if (mp) { problems.push(mp); continue; }
        if (typeof m.manifest_sha256 !== 'string' || !SHA256_HEX.test(m.manifest_sha256)) { problems.push(`apis[${i}].mcp.manifest_sha256 is not 64 lowercase hex characters`); continue; }
        out.mcp = { url: m.url, manifest_sha256: m.manifest_sha256 };
      }
      apis.push(out);
    }
  }
  // Repositories: an organization or user on a known code host.
  const repositories = [];
  if (doc.repositories !== undefined) {
    if (!Array.isArray(doc.repositories) || doc.repositories.length > MAX_ITEMS) problems.push(`repositories is not an array of at most ${MAX_ITEMS}`);
    else for (const [i, r] of doc.repositories.entries()) {
      if (typeof r !== 'string' || !REPO_RE.test(r)) { problems.push(`repositories[${i}] is not https://<${REPOSITORY_HOSTS.join('|')}>/<owner>`); continue; }
      repositories.push(r);
    }
  }

  // The signature, by one of the keys.
  const s = doc.signature;
  let sigOk = false;
  if (!s || typeof s !== 'object' || Array.isArray(s)) problems.push('signature is missing');
  else if (s.alg !== 'Ed25519' || s.canonicalization !== 'RFC8785') problems.push('signature is not Ed25519 over RFC 8785 bytes');
  else {
    res.kid = typeof s.kid === 'string' ? s.kid : null;
    const key = keys.find((k) => k.kid === s.kid);
    const m = /^ed25519:([A-Za-z0-9+/]+={0,2})$/.exec(String(s.value ?? ''));
    if (!key) problems.push(`signature.kid ${JSON.stringify(String(s.kid ?? '')).slice(0, 120)} is not one of keys`);
    else if (!m) problems.push('signature.value is not ed25519:<base64>');
    else {
      let bytes = null;
      try { bytes = signingBytes(doc); } catch (e) { problems.push(`the document has no RFC 8785 form: ${e.message}`); }
      if (bytes) {
        try { sigOk = edVerify(null, bytes, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), Buffer.from(m[1], 'base64')); } catch { sigOk = false; }
        res.signature = sigOk ? 'valid' : 'invalid';
        if (!sigOk) problems.push(`the signature does not check against ${s.kid}`);
      }
    }
  }
  if (problems.length) return done('invalid', problems[0]);
  res.products = products; res.apis = apis; res.repositories = repositories;
  if (now >= expires) return done('expired', `the declaration expired at ${doc.expires_at}`);
  return done('checked', `signed by ${s.kid}, valid until ${doc.expires_at}`);
}

/** Whether a check failure is about the signature or its key (exit 8) rather than the document's content (exit 9). */
export function isSignatureProblem(r) {
  if (r.status !== 'invalid' || r.problems.some((p) => /^domain /.test(p))) return false;
  return r.signature === 'invalid' || r.problems.some((p) => /^signature/.test(p));
}

/* ------------------------------------------------------------- fetch ---- */

async function readCapped(res, max) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > max) { try { await res.body?.cancel(); } catch {} return { over: true, size: len }; }
  if (!res.body) return { bytes: Buffer.alloc(0) };
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) { try { await reader.cancel(); } catch {} return { over: true, size: total }; }
    chunks.push(Buffer.from(value));
  }
  return { bytes: Buffer.concat(chunks) };
}

/**
 * Fetch https://<domain>/.well-known/trooth.json: no redirects, at most 64 KB,
 * a deadline. Returns { status: 'read' | 'absent' | 'invalid' | 'not_read',
 * url, bytes?, reason, http_status? }. A redirect is invalid (the document must
 * be served from the domain itself); 404 and 410 are absent; anything else that
 * is not a 200 is not read.
 */
export async function fetchDeclaration(domain, { fetch: f = globalThis.fetch, timeoutMs = 10000, userAgent = 'trooth-cli' } = {}) {
  const url = `https://${domain}${DECLARATION_PATH}`;
  let res;
  try {
    res = await f(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json', 'user-agent': userAgent } });
  } catch (e) {
    const timedOut = e && (e.name === 'TimeoutError' || e.name === 'AbortError');
    return { status: 'not_read', url, reason: timedOut ? `${url} did not answer within ${timeoutMs} ms` : `${url} could not be reached: ${e && e.message ? e.message : e}` };
  }
  const code = res.status;
  if ((code >= 300 && code < 400) || res.type === 'opaqueredirect') {
    try { await res.body?.cancel(); } catch {}
    const to = res.headers?.get?.('location');
    return { status: 'invalid', url, http_status: code, reason: `${url} answered with a redirect${to ? ` to ${String(to).slice(0, 200)}` : ''}; a declaration is read only from the domain itself, without redirects` };
  }
  if (code === 404 || code === 410) { try { await res.body?.cancel(); } catch {} return { status: 'absent', url, http_status: code, reason: `${url} answered HTTP ${code}: the site publishes no declaration` }; }
  if (code !== 200) { try { await res.body?.cancel(); } catch {} return { status: 'not_read', url, http_status: code, reason: `${url} answered HTTP ${code}` }; }
  let got;
  try { got = await readCapped(res, MAX_DECLARATION_BYTES); }
  catch (e) { return { status: 'not_read', url, reason: `${url} could not be read to the end: ${e && e.message ? e.message : e}` }; }
  if (got.over) return { status: 'invalid', url, http_status: code, reason: `${url} is over the ${MAX_DECLARATION_BYTES}-byte limit` };
  return { status: 'read', url, http_status: code, bytes: got.bytes, reason: null };
}

/**
 * Read the TXT records at _trooth-key.<domain> through DNS over HTTPS
 * (application/dns-json). Returns { status: 'present' | 'absent' | 'not_read',
 * name, thumbprints[], reason }.
 */
export async function readKeyPin(domain, { fetch: f = globalThis.fetch, timeoutMs = 10000, dohUrl = DOH_URL } = {}) {
  const name = `_trooth-key.${domain}`;
  const out = { status: 'not_read', name, thumbprints: [], reason: null };
  let res;
  try {
    res = await f(`${dohUrl}?name=${encodeURIComponent(name)}&type=TXT`, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/dns-json' } });
  } catch (e) { return { ...out, reason: `DNS over HTTPS could not be read: ${e && e.message ? e.message : e}` }; }
  if (res.status !== 200) { try { await res.body?.cancel(); } catch {} return { ...out, reason: `DNS over HTTPS answered HTTP ${res.status}` }; }
  let j;
  try { const got = await readCapped(res, 64 * 1024); if (got.over) return { ...out, reason: 'the DNS answer is too large' }; j = JSON.parse(got.bytes.toString('utf8')); }
  catch { return { ...out, reason: 'the DNS answer is not JSON' }; }
  if (j?.Status === 3) return { ...out, status: 'absent', reason: `${name} does not exist (NXDOMAIN)` };
  if (j?.Status !== 0) return { ...out, reason: `the DNS answer has status ${Number(j?.Status)}` };
  const values = (Array.isArray(j.Answer) ? j.Answer : []).filter((a) => a && a.type === 16 && typeof a.data === 'string').map((a) => txtValue(a.data));
  const thumbprints = [];
  for (const v of values) { const m = /^trooth-key=([A-Za-z0-9_-]{43})$/.exec(v.trim()); if (m) thumbprints.push(m[1]); }
  if (!thumbprints.length) return { ...out, status: 'absent', reason: values.length ? `${name} holds no trooth-key= value` : `${name} holds no TXT record` };
  return { ...out, status: 'present', thumbprints, reason: null };
}

/** A TXT record's data as DNS JSON gives it ("a" "b" quoted strings) joined into one value. */
export function txtValue(data) {
  const parts = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : String(data);
}

/** Compare a pin reading with a checked declaration's thumbprints. */
export function pinStatus(pin, thumbprints) {
  if (pin.status !== 'present') return { pinned: false, state: pin.status, thumbprint: null };
  const match = pin.thumbprints.find((t) => thumbprints.includes(t));
  return match ? { pinned: true, state: 'matches', thumbprint: match } : { pinned: false, state: 'other_key', thumbprint: pin.thumbprints[0] };
}

export { THUMBPRINT_RE, PRODUCT_ID_RE, SLUG_RE };
