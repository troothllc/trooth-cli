// tests/public-record.test.mjs - `trooth public-record` against a loopback
// server that answers as api.trooth.co/scan/public-record does, with readings
// built by the scan worker's reader (tests/fixtures/public-record). Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

const fx = (n) => readFileSync(new URL(`./fixtures/public-record/${n}.json`, import.meta.url), 'utf8');
const seen = [];
function server(status = 200) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      seen.push(req.url);
      const m = /^\/scan\/public-record\/([^?]+)/.exec(req.url);
      if (status !== 200) { res.writeHead(status, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ error: 'apple.com has been read 6 times this hour without a cached answer; try again next hour.' })); }
      let body;
      try { body = fx(decodeURIComponent(m[1])); }
      catch { body = JSON.stringify({ ...JSON.parse(fx('apple.com')), domain: decodeURIComponent(m[1]), bindings: [], sec: null, lei: null }); }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(body);
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const run = (args, port) => new Promise((resolve) => {
  const p = spawn(process.execPath, [cli, ...args], { env: { ...process.env, TROOTH_API: `http://127.0.0.1:${port}`, NO_COLOR: '1' } });
  let out = '', err = ''; p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d)); p.on('close', (code) => resolve({ code, out, err }));
});

test('apple.com: the filer and the LEI, each with its status and evidence, the filings and the values as filed', async () => {
  const srv = await server(); const port = srv.address().port;
  try {
    const r = await run(['public-record', 'https://www.Apple.com/'], port);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /site names\s+Apple Inc\./);
    assert.match(r.out, /SEC filer\s+CIK 0000320193\s+corroborated the 10-K filed 2025-10-31 declares its extension taxonomy under www\.apple\.com/);
    assert.match(r.out, /LEI\s+HWUPKR0MPOU8FGXBT394\s+corroborated/);
    assert.match(r.out, /revenue\s+416,161,000,000 USD \(year ending 2025-09-27, 10-K filed 2025-10-31\)/);
    assert.match(r.out, /assets\s+359,241,000,000 USD \(at 2025-09-27/);
    assert.match(r.out, /entity\s+trooth:entity:lei:HWUPKR0MPOU8FGXBT394 Apple Inc\./);
    assert.match(r.out, /certificates \d+ unexpired for apple\.com in CT logs/);
    assert.match(r.out, /security\.txt https:\/\/security\.apple\.com/);
    assert.match(r.out, /sanctions\s+no OFAC SDN entity with the name Apple Inc\./);
    assert.match(r.out, /signature\s+the answer carries no signed block/);
    assert.match(r.out, /cybersecurity incidents \(1\.05\): 0/);
    assert.match(r.out, /Nothing here grades, rates or ranks the company/);
    const j = JSON.parse((await run(['public-record', 'apple.com', '--json'], port)).out);
    assert.equal(j.format, 'trooth.public-record.v1');
  } finally { srv.close(); }
});

test('a look-alike site is only a claim', async () => {
  const srv = await server(); const port = srv.address().port;
  try {
    const r = await run(['public-record', 'apple-support.example'], port);
    assert.equal(r.code, 0);
    assert.match(r.out, /CIK 0000320193\s+claimed by site/);
    assert.doesNotMatch(r.out, /CIK 0000320193\s+corroborated/);
  } finally { srv.close(); }
});

test('hints travel as query parameters; no identifier found exits 1; limits and bad input are reported', async () => {
  const srv = await server(); const port = srv.address().port;
  try {
    seen.length = 0;
    let r = await run(['public-record', 'nothing.example', '--cik', '320193', '--ticker', 'aapl', '--lei', 'hwupkr0mpou8fgxbt394'], port);
    assert.equal(r.code, 1);
    assert.equal(seen[0], '/scan/public-record/nothing.example?cik=320193&lei=HWUPKR0MPOU8FGXBT394&ticker=AAPL');
    r = await run(['public-record', 'apple.com', '--cik', 'abc'], port); assert.equal(r.code, 2);
    r = await run(['public-record'], port); assert.equal(r.code, 2);
    r = await run(['public-record', 'apple.com', '--bogus'], port); assert.equal(r.code, 2);
  } finally { srv.close(); }
  const limited = await server(429); const p2 = limited.address().port;
  try {
    const r = await run(['public-record', 'apple.com'], p2);
    assert.equal(r.code, 3); assert.match(r.err, /6 times this hour/);
  } finally { limited.close(); }
  const r = await run(['public-record', 'apple.com'], 9);
  assert.equal(r.code, 3);
});

/* ------------------------------------------------- the signed statement ---- */

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { canonicalize, canonicalizeRecord } from '../bin/lib/jcs.mjs';
import { entryBytes, leafHash, rootOf, inclusionPath, formatVkey, noteKeyHash, toB64, LOG_ORIGIN } from '../bin/lib/tlog.mjs';

const seedKey = (label) => {
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), createHash('sha256').update(`trooth test vectors v1 / ${label} / NOT A TROOTH KEY`).digest()]), format: 'der', type: 'pkcs8' });
  return { priv, pub: Buffer.from(createPublicKey(priv).export({ format: 'jwk' }).x, 'base64url') };
};
const KA = seedKey('key-a'), KB = seedKey('key-b'), LK = seedKey('log-key');
const LOGV = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8'));

/** A signed answer built here, from the format in docs/EVIDENCE.md section 5, not by the scan worker's code. */
function signedAnswer({ record = JSON.parse(fx('apple.com')), signer = KA, tamper = null } = {}) {
  const sha = createHash('sha256').update(canonicalizeRecord(record)).digest('hex');
  const payload = canonicalize({
    statement: 'trooth.public-record.v1', subject_id: record.subject_id, domain: record.domain, read_at: record.read_at,
    record_sha256: sha, record_canonicalization: 'RFC8785', entity_id: record.entity?.id ?? null,
    bindings: record.bindings.map((b) => ({ id: b.id, status: b.status })), sources: record.sources.length,
    issued_at: '2026-10-07T01:33:00.000Z', signer: { key_id: 'test-key-a', issuer: 'trooth.co' },
  });
  const statement = { payload, signature: `ed25519:${sign(null, Buffer.from(payload), signer.priv).toString('base64')}`, key_id: 'test-key-a', alg: 'Ed25519', canonicalization: 'RFC8785' };
  const leaves = [leafHash(entryBytes(LOGV.entries[0].kind, LOGV.entries[0].statement)), leafHash(entryBytes('public_record', statement))];
  const root = rootOf(leaves);
  const text = `${LOG_ORIGIN}\n2\n${toB64(root)}\n`;
  const checkpoint = `${text}\n— ${LOG_ORIGIN} ${Buffer.concat([noteKeyHash(LOG_ORIGIN, LK.pub), sign(null, Buffer.from(text), LK.priv)]).toString('base64')}\n`;
  const log = { log: LOG_ORIGIN, index: 1, tree_size: 2, root_hash: toB64(root), inclusion_proof: inclusionPath(1, leaves).map(toB64), checkpoint };
  const answer = { ...record, signed: { record_sha256: sha, record_canonicalization: 'RFC8785', statement, statement_id: `trooth:statement:${createHash('sha256').update(payload).digest('hex')}`, log, problem: null } };
  if (tamper) tamper(answer);
  return JSON.stringify(answer);
}

function signedServer(body, keys = [{ kid: 'test-key-a', alg: 'Ed25519', encoding: 'base64', public_key: KA.pub.toString('base64'), status: 'active' }]) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(req.url.startsWith('/public/keys') ? JSON.stringify({ keys }) : body);
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
const VK = formatVkey(LOG_ORIGIN, LK.pub);

test('a signed reading: its SHA-256, its signature, its key and its log entry all check', async () => {
  const srv = await signedServer(signedAnswer()); const port = srv.address().port;
  try {
    const r = await run(['public-record', 'apple.com', '--log-vkey', VK], port);
    assert.equal(r.code, 0, r.err + r.out);
    assert.match(r.out, /signature\s+signed by test-key-a, and entry 1 of the log/);
    const j = JSON.parse((await run(['public-record', 'apple.com', '--json', '--log-vkey', VK], port)).out);
    assert.equal(j.cli_check.status, 'signed');
    assert.equal(j.cli_check.log.status, 'included');
  } finally { srv.close(); }
});

test('a changed record, a forged signature, a compromised key or a bad log proof is reported, and exits 9 or 8', async () => {
  const cases = [
    ['record changed after signing', signedAnswer({ tamper: (a) => { a.sec.financials[0].value += 1; } }), 9, /its SHA-256 differs/],
    ['signed by another key', signedAnswer({ signer: KB }), 8, /does not check against the published key/],
    ['log proof for another position', signedAnswer({ tamper: (a) => { a.signed.log.index = 0; } }), 9, /log receipt does not check/],
  ];
  for (const [name, body, code, re] of cases) {
    const srv = await signedServer(body); const port = srv.address().port;
    try {
      const r = await run(['public-record', 'apple.com', '--log-vkey', VK], port);
      assert.equal(r.code, code, `${name}: ${r.out}`);
      assert.match(r.out, re, name);
    } finally { srv.close(); }
  }
  const srv = await signedServer(signedAnswer(), [{ kid: 'test-key-a', alg: 'Ed25519', encoding: 'base64', public_key: KA.pub.toString('base64'), status: 'compromised', compromised_at: '2026-10-01T00:00:00Z' }]);
  try {
    const r = await run(['public-record', 'apple.com', '--log-vkey', VK], srv.address().port);
    assert.equal(r.code, 8);
    assert.match(r.out, /compromised/);
  } finally { srv.close(); }
});

test('0.12.0 sections: SAM.gov, patents, state registries, merger review, the domain, changes and subjects', async () => {
  const srv = await server(); const port = srv.address().port;
  try {
    const r = await run(['public-record', 'nvidia.com'], port);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /SAM\.gov\s+NVIDIA CORPORATION UEI ABCDEFG12345 \(Active, expires 2027-05-01\)/);
    assert.match(r.out, /patents\s+12,345 applications with first applicant NVIDIA CORPORATION/);
    assert.match(r.out, /registries\s+US-NY 4986044 Active, formed in Delaware · US-CO 20011213457 Good Standing/);
    assert.match(r.out, /mergers\s+\d+ FTC early termination notices? naming NVIDIA CORPORATION/);
    assert.match(r.out, /domain\s+registered 1993-04-20 · registrar SafeNames Ltd\./);
    assert.match(r.out, /changes\s+\d+ recorded, newest first:/);
    assert.match(r.out, /filed with the SEC as NVIDIA CORP\/CA from 1998-05-07 to 2002-06-04/);
    assert.match(r.out, /subjects\s+trooth:domain:nvidia\.com, trooth:entity:lei:549300S4KLFTLO7GSQ80/);
  } finally { srv.close(); }
});
