// tests/declaration.test.mjs - the domain-signed declaration (docs/DECLARATION.md):
// `trooth declare init|sign|check` end to end with a throwaway key in a temporary
// home, every rule's negative case, the fetch rules (no redirects, 64 KB, 404 is
// absent) through an injected fetch, and the DNS pin through a loopback DNS-JSON
// server. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import {
  jwkThumbprint, generateDeclarationKey, buildDeclaration, signDeclaration, checkDeclaration, fetchDeclaration,
  readKeyPin, pinStatus, pinLine, txtValue, isSignatureProblem, readPrivateJwk, keyIdFor, MAX_DECLARATION_BYTES,
} from '../bin/lib/declaration.mjs';

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const DAY = 86400000;
const NOW = Date.parse('2026-10-07T12:00:00Z');
const tmp = () => mkdtempSync(join(tmpdir(), 'trooth-declare-'));

function run(args, { home, env = {} } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, ...args], { env: { ...process.env, HOME: home || tmp(), NO_COLOR: '1', TROOTH_DOH: 'http://127.0.0.1:9/dns-query', TROOTH_TIMEOUT_MS: '3000', ...env } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
  });
}

const KEY = generateDeclarationKey();
const FULL = { record: 'https://trooth.co/network/company/acme', products: [{ id: 'widget', name: 'Widget', url: 'https://acme.com/widget' }], apis: [{ base_url: 'https://api.acme.com', mcp: { url: 'https://api.acme.com/mcp', manifest_sha256: 'a'.repeat(64) } }], repositories: ['https://github.com/acme'] };
const good = (extra = {}) => buildDeclaration({ domain: 'acme.com', privateJwk: KEY.privateJwk, now: NOW, ...FULL, ...extra });
/** Edit a signed declaration and sign it again, so only the rule under test fails. */
const resign = (edit, jwk = KEY.privateJwk) => { const d = structuredClone(good()); edit(d); return signDeclaration(d, jwk); };
const check = (doc, opts = {}) => checkDeclaration(typeof doc === 'string' || Buffer.isBuffer(doc) ? doc : JSON.stringify(doc), { domain: 'acme.com', now: NOW, ...opts });

test('the RFC 7638 thumbprint of an Ed25519 key matches RFC 8037 appendix A.3', () => {
  assert.equal(jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
  assert.equal(keyIdFor('acme.com', KEY.publicJwk), `acme.com#${KEY.thumbprint}`);
  assert.equal(pinLine('acme.com', 'T'), '_trooth-key.acme.com TXT "trooth-key=T"');
  assert.throws(() => jwkThumbprint({ kty: 'EC', crv: 'P-256', x: 'a' }));
  assert.throws(() => readPrivateJwk({ ...KEY.privateJwk, x: generateDeclarationKey().publicJwk.x }), /inconsistent/);
});

test('a declaration that checks: every subject carried, sha256 of the bytes served', () => {
  const d = good();
  const text = JSON.stringify(d, null, 2);
  const r = check(text);
  assert.equal(r.status, 'checked', r.problems.join('; '));
  assert.equal(r.signature, 'valid');
  assert.equal(r.kid, `acme.com#${KEY.thumbprint}`);
  assert.deepEqual(r.keys, [r.kid]);
  assert.deepEqual(r.thumbprints, [KEY.thumbprint]);
  assert.equal(r.products.length, 1); assert.equal(r.apis[0].mcp.manifest_sha256, 'a'.repeat(64)); assert.deepEqual(r.repositories, ['https://github.com/acme']);
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
  assert.equal(Date.parse(d.expires_at) - Date.parse(d.issued_at), 365 * DAY);
  assert.equal(check(JSON.stringify(d)).status, 'checked', 'whitespace is not signed: the RFC 8785 bytes are');
  // A subdomain is the domain's own.
  assert.equal(check(resign((x) => { x.products[0].url = 'https://shop.eu.acme.com/w?x=1'; })).status, 'checked');
});

test('negative: bad signature, kid not in keys, a private key, a key whose kid is not its thumbprint', () => {
  let d = good(); d.products[0].name = 'Widget Pro';
  let r = check(d);
  assert.equal(r.status, 'invalid'); assert.equal(r.signature, 'invalid'); assert.match(r.reason, /signature does not check/); assert.ok(isSignatureProblem(r));
  assert.deepEqual(r.products, [], 'nothing from a document that does not check is carried');
  d = good(); d.signature.kid = `acme.com#${generateDeclarationKey().thumbprint}`;
  r = check(d); assert.equal(r.status, 'invalid'); assert.match(r.reason, /signature\.kid .* is not one of keys/); assert.ok(isSignatureProblem(r));
  d = good(); d.signature.value = 'ed25519:not base64!';
  r = check(d); assert.match(r.reason, /ed25519:<base64>/);
  d = good(); delete d.signature;
  r = check(d); assert.match(r.reason, /signature is missing/);
  d = good(); d.signature.alg = 'ES256';
  r = check(d); assert.match(r.reason, /not Ed25519/);
  r = check(resign((x) => { x.keys[0].d = KEY.privateJwk.d; }));
  assert.match(r.reason, /holds a private key/);
  r = check(resign((x) => { x.keys[0].kid = 'acme.com#' + 'A'.repeat(43); }));
  assert.match(r.reason, /kid is not acme\.com#<its RFC 7638 thumbprint>/);
  // Signed by a key the document does not list.
  const other = generateDeclarationKey();
  const forged = signDeclaration(structuredClone(good()), other.privateJwk);
  r = check(forged); assert.match(r.reason, /is not one of keys/);
});

test('negative: wrong domain, expired, more than 400 days, issued in the future, times not ISO', () => {
  let r = check(good(), { domain: 'other.com' });
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /domain is acme\.com, but the document was served from other\.com/);
  assert.equal(isSignatureProblem(r), false, 'a wrong domain is a mismatch, not a signature problem');
  r = check(good(), { now: NOW + 366 * DAY });
  assert.equal(r.status, 'expired'); assert.match(r.reason, /expired at/); assert.deepEqual(r.products, []);
  r = check(resign((x) => { x.expires_at = new Date(Date.parse(x.issued_at) + 401 * DAY).toISOString().replace('.000', ''); }));
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /more than 400 days/);
  assert.equal(check(resign((x) => { x.expires_at = new Date(Date.parse(x.issued_at) + 400 * DAY).toISOString(); })).status, 'checked', 'exactly 400 days');
  r = check(resign((x) => { x.expires_at = x.issued_at; }));
  assert.match(r.reason, /not after issued_at/);
  r = check(good({ now: NOW + DAY }));
  assert.match(r.reason, /issued_at is in the future/);
  r = check(resign((x) => { x.issued_at = '2026-10-07'; }));
  assert.match(r.reason, /issued_at is not an ISO 8601 UTC time/);
  assert.throws(() => good({ days: 401 }), /1 to 400 days/);
});

test('negative: a URL on another host, a bad repository, a bad record, a bad product id, a bad MCP hash, an unknown member', () => {
  const cases = [
    [(x) => { x.products[0].url = 'https://acme.com.evil.com/'; }, /products\[0\]\.url is on acme\.com\.evil\.com/],
    [(x) => { x.products[0].url = 'https://notacme.com/'; }, /not acme\.com or a subdomain/],
    [(x) => { x.products[0].url = 'http://acme.com/'; }, /not https/],
    [(x) => { x.products[0].url = 'https://user:pw@acme.com/'; }, /credentials/],
    [(x) => { x.apis[0].base_url = 'https://api.example.net'; }, /apis\[0\]\.base_url is on api\.example\.net/],
    [(x) => { x.apis[0].mcp.url = 'https://mcp.example.net/mcp'; }, /apis\[0\]\.mcp\.url is on mcp\.example\.net/],
    [(x) => { x.apis[0].mcp.manifest_sha256 = 'XYZ'; }, /manifest_sha256 is not 64 lowercase hex/],
    [(x) => { x.repositories = ['https://evil.example/acme']; }, /repositories\[0\]/],
    [(x) => { x.repositories = ['https://github.com/acme/repo/extra']; }, /repositories\[0\]/],
    [(x) => { x.record = 'https://evil.example/network/company/acme'; }, /record is not a Trooth company record URL/],
    [(x) => { x.products[0].id = 'Widget'; }, /products\[0\]\.id does not match/],
    [(x) => { x.products.push({ ...x.products[0] }); }, /repeats the id widget/],
    [(x) => { x.products[0].name = ''; }, /name is not a name/],
    [(x) => { x.extra = 'surprise'; }, /unknown member "extra"/],
    [(x) => { x.format = 'trooth.declaration.v2'; }, /format is not trooth\.declaration\.v1/],
    [(x) => { x.keys = []; }, /keys is not a non-empty array/],
  ];
  for (const [edit, re] of cases) {
    const r = check(resign(edit));
    assert.equal(r.status, 'invalid', String(re));
    assert.ok(r.problems.some((p) => re.test(p)), `${re} in ${r.problems.join(' | ')}`);
    assert.equal(isSignatureProblem(r), r.problems.some((p) => /^signature/.test(p)));
  }
  // A number outside the RFC 8785 profile has no canonical form.
  const r = check(JSON.stringify(good()).replace('"widget",', '"widget","n":0.5,'));
  assert.equal(r.status, 'invalid');
});

test('negative: oversize and invalid JSON', () => {
  const big = JSON.stringify(good(), null, 2).replace('{', '{' + ' '.repeat(MAX_DECLARATION_BYTES));
  let r = check(big);
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /over the 65536-byte limit/);
  r = check('{"format": "trooth.declaration.v1",');
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /not valid JSON/);
  r = check('[]'); assert.match(r.reason, /not a JSON object/);
});

/* --------------------------------------------------------- fetching ---- */

const resp = (status, body = '', headers = {}) => new Response(body, { status, headers });

test('fetching: https only at /.well-known/trooth.json, redirect manual; a redirect is invalid, 404 absent, 5xx and errors not read, oversize invalid', async () => {
  const seen = [];
  const body = JSON.stringify(good());
  let r = await fetchDeclaration('acme.com', { fetch: async (u, init) => { seen.push([u, init.redirect, init.headers.accept]); return resp(200, body, { 'content-type': 'application/json' }); } });
  assert.equal(r.status, 'read');
  assert.deepEqual(seen[0], ['https://acme.com/.well-known/trooth.json', 'manual', 'application/json']);
  assert.equal(check(r.bytes).status, 'checked');
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(301, '', { location: 'https://evil.example/trooth.json' }) });
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /redirect to https:\/\/evil\.example\/trooth\.json/);
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(302, '', { location: 'https://www.acme.com/.well-known/trooth.json' }) });
  assert.equal(r.status, 'invalid', 'even to a subdomain of the same domain: the document is read from the host itself');
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(404, 'nope') });
  assert.equal(r.status, 'absent');
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(503, 'down') });
  assert.equal(r.status, 'not_read');
  r = await fetchDeclaration('acme.com', { fetch: async () => { throw new TypeError('fetch failed'); } });
  assert.equal(r.status, 'not_read'); assert.match(r.reason, /could not be reached/);
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(200, 'x'.repeat(10), { 'content-length': String(MAX_DECLARATION_BYTES + 1) }) });
  assert.equal(r.status, 'invalid'); assert.match(r.reason, /over the 65536-byte limit/);
  r = await fetchDeclaration('acme.com', { fetch: async () => resp(200, new ReadableStream({ start(c) { for (let i = 0; i < 70; i++) c.enqueue(new Uint8Array(1024)); c.close(); } })) });
  assert.equal(r.status, 'invalid', 'a body with no length that passes 64 KB is cut off');
  const keepAlive = setTimeout(() => {}, 2000); // AbortSignal.timeout does not hold the event loop open
  r = await fetchDeclaration('acme.com', { timeoutMs: 50, fetch: (u, init) => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))) });
  assert.equal(r.status, 'not_read'); assert.match(r.reason, /did not answer within 50 ms/);
  clearTimeout(keepAlive);
});

test('the DNS pin: TXT values joined, a match, another key, NXDOMAIN, a failed answer', async () => {
  assert.equal(txtValue('"trooth-key=abc" "def"'), 'trooth-key=abcdef');
  const doh = (j, status = 200) => async (u, init) => { assert.equal(init.headers.accept, 'application/dns-json'); assert.match(u, /\?name=_trooth-key\.acme\.com&type=TXT$/); return resp(status, JSON.stringify(j)); };
  const half = Math.floor(KEY.thumbprint.length / 2);
  let p = await readKeyPin('acme.com', { fetch: doh({ Status: 0, Answer: [{ name: '_trooth-key.acme.com', type: 16, data: `"trooth-key=${KEY.thumbprint.slice(0, half)}" "${KEY.thumbprint.slice(half)}"` }, { type: 16, data: '"v=spf1 -all"' }] }) });
  assert.equal(p.status, 'present'); assert.deepEqual(p.thumbprints, [KEY.thumbprint]);
  assert.deepEqual(pinStatus(p, [KEY.thumbprint]), { pinned: true, state: 'matches', thumbprint: KEY.thumbprint });
  assert.equal(pinStatus(p, ['B'.repeat(43)]).state, 'other_key');
  p = await readKeyPin('acme.com', { fetch: doh({ Status: 3 }) });
  assert.equal(p.status, 'absent');
  p = await readKeyPin('acme.com', { fetch: doh({ Status: 0, Answer: [{ type: 16, data: '"trooth-key=short"' }] }) });
  assert.equal(p.status, 'absent');
  p = await readKeyPin('acme.com', { fetch: doh({ Status: 2 }) });
  assert.equal(p.status, 'not_read');
  p = await readKeyPin('acme.com', { fetch: doh({}, 500) });
  assert.equal(p.status, 'not_read');
  assert.equal(pinStatus(p, [KEY.thumbprint]).pinned, false);
});

/* -------------------------------------------------------------- CLI ---- */

function dohServer(answerFor) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const name = new URL(req.url, 'http://x').searchParams.get('name');
      res.writeHead(200, { 'content-type': 'application/dns-json' });
      res.end(JSON.stringify(answerFor(name)));
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

test('CLI round trip: init (0600, never overwrites, nothing secret), sign (the pin line), check from a file', async () => {
  const home = tmp();
  let r = await run(['declare', 'init', '--domain', 'Acme.com'], { home });
  assert.equal(r.code, 0, r.err);
  const keyPath = join(home, '.trooth', 'declaration-key', 'acme.com.jwk');
  assert.ok(existsSync(keyPath));
  assert.equal(statSync(keyPath).mode & 0o777, 0o600);
  const jwk = JSON.parse(readFileSync(keyPath, 'utf8'));
  assert.ok(jwk.d && !r.out.includes(jwk.d) && !r.err.includes(jwk.d), 'the private key is never printed');
  assert.match(r.out, new RegExp(`kid\\s+acme\\.com#${jwkThumbprint(jwk)}`));
  r = await run(['declare', 'init', '--domain', 'acme.com'], { home });
  assert.equal(r.code, 2); assert.match(r.err, /already exists; trooth declare init never overwrites a key/);
  assert.equal(JSON.parse(readFileSync(keyPath, 'utf8')).d, jwk.d, 'the key is unchanged');
  const j = JSON.parse((await run(['declare', 'init', '--domain', 'acme.com', '--key', join(home, 'k2.jwk'), '--json'], { home })).out);
  assert.equal(j.key_path, join(home, 'k2.jwk')); assert.ok(!('d' in j.public_jwk) && !JSON.stringify(j).includes('"d"'));

  const out = join(home, 'trooth.json');
  r = await run(['declare', 'sign', '--domain', 'acme.com', '--key', keyPath, '--record', 'https://trooth.co/network/company/acme', '--product', 'widget=Widget = Pro=https://acme.com/widget?a=b', '--api', `https://api.acme.com,https://api.acme.com/mcp,${'A'.repeat(64)}`, '--api', 'https://status.acme.com', '--repo', 'https://github.com/acme', '--days', '30', '--out', out], { home });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, new RegExp(`_trooth-key\\.acme\\.com TXT "trooth-key=${jwkThumbprint(jwk)}"`));
  assert.ok(!r.out.includes(jwk.d));
  const doc = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(doc.products[0].name, 'Widget = Pro'); assert.equal(doc.products[0].url, 'https://acme.com/widget?a=b');
  assert.equal(doc.apis[0].mcp.manifest_sha256, 'a'.repeat(64)); assert.equal(doc.apis.length, 2);
  assert.equal(Date.parse(doc.expires_at) - Date.parse(doc.issued_at), 30 * DAY);
  assert.ok(!JSON.stringify(doc).includes(jwk.d), 'the published document carries no private key');
  r = await run(['declare', 'sign', '--domain', 'acme.com', '--key', keyPath, '--out', out], { home });
  assert.equal(r.code, 2); assert.match(r.err, /will not overwrite/);

  r = await run(['declare', 'check', '--file', out, '--no-dns'], { home });
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /status\s+checked/); assert.match(r.out, /product\s+widget\s+Widget = Pro/); assert.match(r.out, /host\s+not checked: read from a file/);
  r = await run(['declare', 'check', '--file', out, '--domain', 'acme.com', '--no-dns', '--json'], { home });
  const c = JSON.parse(r.out);
  assert.equal(c.status, 'checked'); assert.equal(c.host_checked, true); assert.equal(c.source, 'file'); assert.equal(c.key_pinned_by_dns, false);
});

test('CLI: sign refuses what would not check (exit 2): more than 400 days, a URL on another host, a bad flag value, a bad key file', async () => {
  const home = tmp();
  const keyPath = join(home, 'k.jwk');
  await run(['declare', 'init', '--domain', 'acme.com', '--key', keyPath], { home });
  const sign = (...extra) => run(['declare', 'sign', '--domain', 'acme.com', '--key', keyPath, '--out', join(home, `o${Math.random()}.json`), ...extra], { home });
  let r = await sign('--days', '401'); assert.equal(r.code, 2); assert.match(r.err, /1 to 400/);
  r = await sign('--days', '400'); assert.equal(r.code, 0, r.err);
  r = await sign('--product', 'w=W=https://evil.example/w'); assert.equal(r.code, 2); assert.match(r.err, /would not check: products\[0\]\.url is on evil\.example/);
  r = await sign('--product', 'no-url-here'); assert.equal(r.code, 2); assert.match(r.err, /--product is id=name=url/);
  r = await sign('--api', 'https://api.acme.com,https://api.acme.com/mcp'); assert.equal(r.code, 2);
  r = await sign('--repo', 'https://sourceforge.net/acme'); assert.equal(r.code, 2);
  r = await sign('--record', 'https://evil.example/x'); assert.equal(r.code, 2);
  writeFileSync(join(home, 'bad.jwk'), JSON.stringify({ ...generateDeclarationKey().privateJwk, x: KEY.publicJwk.x }));
  r = await run(['declare', 'sign', '--domain', 'acme.com', '--key', join(home, 'bad.jwk'), '--out', join(home, 'z.json')], { home });
  assert.equal(r.code, 2); assert.match(r.err, /inconsistent/);
  r = await run(['declare', 'sign', '--domain', 'not a domain', '--key', keyPath, '--out', join(home, 'z.json')], { home });
  assert.equal(r.code, 2);
  r = await run(['declare', 'frobnicate'], { home }); assert.equal(r.code, 2);
  r = await run(['declare', 'init', '--domain', 'acme.com', '--out', 'x'], { home }); assert.equal(r.code, 2); assert.match(r.err, /not a flag of `trooth declare init`/);
});

test('CLI: key rotation lists a second key; the signature is by the first', async () => {
  const home = tmp();
  const next = generateDeclarationKey();
  writeFileSync(join(home, 'next.pub.jwk'), JSON.stringify(next.publicJwk));
  writeFileSync(join(home, 'cur.jwk'), JSON.stringify(KEY.privateJwk));
  const out = join(home, 'd.json');
  const r = await run(['declare', 'sign', '--domain', 'acme.com', '--key', join(home, 'cur.jwk'), '--add-key', join(home, 'next.pub.jwk'), '--out', out], { home });
  assert.equal(r.code, 0, r.err);
  const d = JSON.parse(readFileSync(out, 'utf8'));
  assert.deepEqual(d.keys.map((k) => k.kid), [`acme.com#${KEY.thumbprint}`, `acme.com#${next.thumbprint}`]);
  assert.equal(d.signature.kid, `acme.com#${KEY.thumbprint}`);
  assert.equal(check(d, { now: Date.now() }).status, 'checked');
});

test('CLI exit codes for check: 8 signature or key, 9 another rule, 11 expired, 2 usage', async () => {
  const home = tmp();
  const f = (name, content) => { const p = join(home, name); writeFileSync(p, typeof content === 'string' ? content : JSON.stringify(content, null, 2)); return p; };
  const tampered = good(); tampered.products[0].name = 'Other';
  const kidGone = good(); kidGone.signature.kid = 'acme.com#' + 'Q'.repeat(43);
  const long = resign((x) => { x.expires_at = new Date(Date.parse(x.issued_at) + 401 * DAY).toISOString().replace('.000', ''); });
  const offHost = resign((x) => { x.apis[0].base_url = 'https://api.example.net'; });
  const expired = buildDeclaration({ domain: 'acme.com', privateJwk: KEY.privateJwk, now: Date.now() - 40 * DAY, days: 30 });
  const cases = [
    ['bad signature', f('a.json', tampered), [], 8],
    ['kid not in keys', f('b.json', kidGone), [], 8],
    ['wrong domain', f('c.json', good()), ['--domain', 'other.com'], 9],
    ['more than 400 days', f('d.json', long), [], 9],
    ['URL on another host', f('e.json', offHost), [], 9],
    ['oversize', f('f.json', JSON.stringify(good()) + ' '.repeat(MAX_DECLARATION_BYTES)), [], 9],
    ['invalid JSON', f('g.json', '{ not json'), [], 9],
    ['expired', f('h.json', expired), [], 11],
  ];
  for (const [label, path, extra, code] of cases) {
    const r = await run(['declare', 'check', '--file', path, '--no-dns', ...extra], { home });
    assert.equal(r.code, code, `${label}: ${r.out}${r.err}`);
    const j = JSON.parse((await run(['declare', 'check', '--file', path, '--no-dns', '--json', ...extra], { home })).out);
    assert.equal(j.status, code === 11 ? 'expired' : 'invalid', label);
    assert.deepEqual(j.products, [], `${label}: nothing carried`);
  }
  assert.equal((await run(['declare', 'check'], { home })).code, 2);
  assert.equal((await run(['declare', 'check', 'acme.com', '--file', 'x'], { home })).code, 2);
  assert.equal((await run(['declare', 'check', 'acme.com', '--domain', 'acme.com'], { home })).code, 2);
  assert.equal((await run(['declare', 'check', 'https://acme.com/'], { home })).code, 2, 'a domain, not a URL');
});

test('CLI: the DNS pin read over DNS over HTTPS: matches (exit 0), another key (exit 9), not readable (still 0, reported)', async () => {
  const home = tmp();
  const path = join(home, 'd.json');
  writeFileSync(path, JSON.stringify(good()));
  let answer = { Status: 0, Answer: [{ type: 16, data: `"trooth-key=${KEY.thumbprint}"` }] };
  const srv = await dohServer(() => answer);
  const env = { TROOTH_DOH: `http://127.0.0.1:${srv.address().port}/dns-query` };
  try {
    let r = await run(['declare', 'check', '--file', path, '--json'], { home, env });
    assert.equal(r.code, 0, r.err);
    let j = JSON.parse(r.out);
    assert.equal(j.key_pinned_by_dns, true); assert.equal(j.dns_pin.state, 'matches'); assert.equal(j.dns_pin.name, '_trooth-key.acme.com');
    r = await run(['declare', 'check', '--file', path], { home, env });
    assert.match(r.out, /DNS pin\s+_trooth-key\.acme\.com pins .*: the key is bound to the zone as well/);
    answer = { Status: 0, Answer: [{ type: 16, data: `"trooth-key=${'Z'.repeat(43)}"` }] };
    r = await run(['declare', 'check', '--file', path, '--json'], { home, env });
    assert.equal(r.code, 9);
    j = JSON.parse(r.out);
    assert.equal(j.key_pinned_by_dns, false); assert.equal(j.dns_pin.state, 'other_key'); assert.match(j.problems.at(-1), /pins Z+, which is not a key in the declaration/);
    answer = { Status: 3 };
    r = await run(['declare', 'check', '--file', path], { home, env });
    assert.equal(r.code, 0); assert.match(r.out, /none at _trooth-key\.acme\.com; to add one: _trooth-key\.acme\.com TXT "trooth-key=/);
  } finally { srv.close(); }
  const r = await run(['declare', 'check', '--file', path, '--json'], { home });
  assert.equal(r.code, 0, 'a DNS answer that cannot be read is reported, and the pin is optional');
  assert.equal(JSON.parse(r.out).dns_pin.status, 'not_read');
});
