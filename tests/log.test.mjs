// tests/log.test.mjs - the witness statement log (docs/LOG.md): the vectors in
// tests/vectors/log.json through the core, and `trooth verify` and `trooth log`
// end to end against a loopback server that answers as the log does, built
// from those vectors. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { verifyStatement, verifyBundle } from '../bin/lib/verify.mjs';
import { verifyConsistency, fromB64, parseVkey, LOG_ORIGIN, inclusionPath, consistencyPath, toB64, rootOf } from '../bin/lib/tlog.mjs';
import { PINNED_LOG_VKEYS } from '../bin/lib/log-trust.mjs';

const dir = new URL('./vectors/', import.meta.url);
const L = JSON.parse(readFileSync(new URL('log.json', dir), 'utf8'));
const V = JSON.parse(readFileSync(new URL('vectors.json', dir), 'utf8'));
const MAPPING = readFileSync(new URL(V.mapping_file, dir));
const mappingPath = new URL(V.mapping_file, dir).pathname;
const sid = (p) => `trooth:statement:${createHash('sha256').update(p, 'utf8').digest('hex')}`;

for (const c of L.cases) {
  test(`log vector ${c.name}: ${c.expect.verdict} / ${c.expect.log}`, () => {
    const r = verifyStatement({ statement: c.statement, keys: c.keys, mappingBytes: MAPPING, manifest: c.manifest, domain: c.domain, log: c.log });
    assert.equal(r.verdict, c.expect.verdict, c.note);
    assert.equal(r.log ? r.log.status : null, c.expect.log, c.note);
  });
}

for (const c of L.consistency) {
  test(`consistency vector ${c.name}: ${c.expect}`, () => {
    assert.equal(verifyConsistency(c.first, c.second, fromB64(c.first_root) ?? Buffer.alloc(32), fromB64(c.second_root), c.proof.map(fromB64)), c.expect);
  });
}

test('every pinned log key is a signed-note Ed25519 key for this log', () => {
  for (const k of PINNED_LOG_VKEYS) assert.equal(parseVkey(k).name, LOG_ORIGIN);
});

// ---- a loopback log built from the vectors -------------------------------
const LEAVES = L.entries.map((e) => Buffer.from(e.leaf_hash, 'base64'));
let size = 5;
function server() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'content-type': type }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
      const p = u.pathname.replace('/scan/log/v1', '');
      const receiptFor = (i) => ({ log: LOG_ORIGIN, index: i, tree_size: size, root_hash: toB64(rootOf(LEAVES.slice(0, size))), inclusion_proof: inclusionPath(i, LEAVES.slice(0, size)).map(toB64), checkpoint: L.checkpoints[String(size)] });
      if (p === '/vkey') return send(200, `${L.vkey}\n`, 'text/plain');
      if (p === '/checkpoint') return send(200, L.checkpoints[String(size)], 'text/plain');
      if (p === '/lookup') {
        const i = L.entries.findIndex((e) => e.kind === 'witness_statement' && sid(e.statement.payload) === u.searchParams.get('statement_id'));
        return i >= 0 && i < size ? send(200, { found: true, index: i, receipt: receiptFor(i) }) : send(404, { found: false });
      }
      if (p === '/corrections') {
        const out = L.entries.map((e, i) => [e, i]).filter(([e, i]) => i < size && e.kind === 'correction' && JSON.parse(e.statement.payload).supersedes === u.searchParams.get('statement_id')).map(([e, i]) => ({ statement: e.statement, receipt: receiptFor(i) }));
        return send(200, { corrections: out });
      }
      if (p === '/proof/consistency') return send(200, { consistency_proof: consistencyPath(Number(u.searchParams.get('first')), LEAVES.slice(0, Number(u.searchParams.get('second')))).map(toB64) });
      send(404, { error: 'not found' });
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
function run(args, port) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, ...args], { env: { ...process.env, TROOTH_API: `http://127.0.0.1:${port}`, TROOTH_WEB: 'http://127.0.0.1:9', NO_COLOR: '1' } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
  });
}
function files(statement) {
  const t = mkdtempSync(join(tmpdir(), 'trooth-log-'));
  writeFileSync(join(t, 's.json'), JSON.stringify({ statement, manifest: V.vectors[0].manifest }));
  writeFileSync(join(t, 'keys.json'), JSON.stringify({ keys: V.vectors[0].keys, list_read_at: '2026-10-06T00:00:00.000Z' }));
  return t;
}
const entry = (i) => L.entries[i].statement;

test('trooth verify asks the log: included, superseded, not logged, forged key, --no-log', async () => {
  const srv = await server(); const port = srv.address().port; size = 5;
  try {
    const verify = async (i, extra = []) => { const t = files(entry(i)); return run(['verify', 'acme-vectors.com', '--file', join(t, 's.json'), '--keys', join(t, 'keys.json'), '--mapping', mappingPath, '--json', '--log-vkey', L.vkey, ...extra], port); };
    let r = await verify(0);
    assert.equal(r.code, 0, r.err); let d = JSON.parse(r.out);
    assert.equal(d.verdict, 'checked'); assert.equal(d.log.status, 'included'); assert.equal(d.log.index, 0); assert.equal(d.log.vkey_source, '--log-vkey');
    r = await verify(1);
    assert.equal(r.code, 10, r.err); d = JSON.parse(r.out);
    assert.equal(d.verdict, 'superseded'); assert.equal(d.log.corrections[0].valid, true); assert.equal(d.log.superseded_by, sid(entry(3).payload));
    r = await verify(0, ['--no-log']);
    assert.equal(r.code, 0); assert.equal(JSON.parse(r.out).log, undefined);
    const t = files(entry(0));
    r = await run(['verify', 'acme-vectors.com', '--file', join(t, 's.json'), '--keys', join(t, 'keys.json'), '--mapping', mappingPath, '--json', '--log-vkey', L.impostor_vkey], port);
    assert.equal(r.code, 9); assert.equal(JSON.parse(r.out).log.status, 'checkpoint_invalid');
    size = 3; // a statement the log does not hold yet
    r = await verify(1);
    assert.equal(r.code, 0); assert.equal(JSON.parse(r.out).log.status, 'included');
    const t4 = files(L.entries[4].statement);
    r = await run(['verify', 'acme-third.com', '--file', join(t4, 's.json'), '--keys', join(t4, 'keys.json'), '--json', '--log-vkey', L.vkey], port);
    assert.equal(JSON.parse(r.out).log.status, 'not_logged');
    r = await run(['verify', 'acme-vectors.com', '--file', join(t, 's.json'), '--keys', join(t, 'keys.json'), '--json', '--log-vkey', 'not-a-key'], port);
    assert.equal(r.code, 2);
  } finally { srv.close(); size = 5; }
});

test('a log that cannot be read is reported, never turned into a verdict', async () => {
  const t = files(entry(0));
  const r = await run(['verify', 'acme-vectors.com', '--file', join(t, 's.json'), '--keys', join(t, 'keys.json'), '--mapping', mappingPath, '--json', '--log-vkey', L.vkey], 9);
  assert.equal(r.code, 0, r.err); const d = JSON.parse(r.out);
  assert.equal(d.verdict, 'checked'); assert.equal(d.log.status, 'unavailable');
});

test('--save-bundle carries the log answer, and --bundle checks it offline: superseded', async () => {
  const srv = await server(); const port = srv.address().port; size = 5;
  try {
    const t = files(entry(1));
    let r = await run(['verify', 'acme-vectors.com', '--file', join(t, 's.json'), '--keys', join(t, 'keys.json'), '--mapping', mappingPath, '--log-vkey', L.vkey, '--save-bundle', join(t, 'b.json')], port);
    assert.equal(r.code, 10, r.err);
    const b = JSON.parse(readFileSync(join(t, 'b.json'), 'utf8'));
    assert.equal(b.log.vkey, L.vkey); assert.equal(b.log.corrections.length, 1);
    r = await run(['verify', '--bundle', join(t, 'b.json'), '--json', '--log-vkey', L.vkey], 9);
    assert.equal(r.code, 10, r.err);
    assert.equal(verifyBundle(b).verdict, 'superseded');
    assert.equal(verifyBundle(b, { vkeys: [L.impostor_vkey] }).verdict, 'mismatch', 'a pinned key replaces the key a bundle carries');
  } finally { srv.close(); }
});

test('trooth log checkpoint and trooth log monitor: first sighting, growth, tampering', async () => {
  const srv = await server(); const port = srv.address().port;
  const state = join(mkdtempSync(join(tmpdir(), 'trooth-mon-')), 'state.json');
  try {
    size = 3;
    let r = await run(['log', 'checkpoint', '--json', '--log-vkey', L.vkey], port);
    assert.equal(r.code, 0, r.err); assert.equal(JSON.parse(r.out).tree_size, 3);
    r = await run(['log', 'monitor', '--state', state, '--log-vkey', L.vkey], port);
    assert.equal(r.code, 0, r.err); assert.match(r.out, /first checkpoint recorded: size 3/);
    size = 5;
    r = await run(['log', 'monitor', '--state', state, '--json', '--log-vkey', L.vkey], port);
    assert.equal(r.code, 0, r.err); assert.deepEqual([JSON.parse(r.out).consistent, JSON.parse(r.out).previous_size], [true, 3]);
    const s = JSON.parse(readFileSync(state, 'utf8')); assert.equal(s.size, 5);
    writeFileSync(state, JSON.stringify({ ...s, size: 4, root: L.consistency[0].first_root }));
    r = await run(['log', 'monitor', '--state', state, '--log-vkey', L.vkey], port);
    assert.equal(r.code, 9); assert.match(r.out, /NOT CONSISTENT/);
    assert.equal(JSON.parse(readFileSync(state, 'utf8')).size, 4, 'the state is left as it was');
    r = await run(['log', 'checkpoint', '--log-vkey', L.impostor_vkey], port);
    assert.equal(r.code, 9);
    r = await run(['log', 'monitor'], port);
    assert.equal(r.code, 2);
    r = await run(['log', 'bogus'], port);
    assert.equal(r.code, 2);
    assert.ok(existsSync(state));
  } finally { srv.close(); size = 5; }
});

test('a pinned log key is recorded in docs/KEY-CEREMONY.md, with no placeholder left', () => {
  const doc = readFileSync(new URL('../docs/KEY-CEREMONY.md', import.meta.url), 'utf8');
  if (!PINNED_LOG_VKEYS.length) return;
  for (const k of PINNED_LOG_VKEYS) assert.ok(doc.includes(k), `the ceremony record names ${k}`);
  assert.doesNotMatch(doc, /CEREMONY_DATE|LOG_VKEY/);
});
