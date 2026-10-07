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
    assert.match(r.out, /Revenue\s+416,161,000,000 USD \(year ending 2025-09-27, 10-K filed 2025-10-31\)/);
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
