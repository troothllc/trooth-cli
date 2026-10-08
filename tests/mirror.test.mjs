// tests/mirror.test.mjs - mirrors of the witness statement log (docs/MIRRORS.md):
// the tile layout, and `trooth mirror` / `trooth mirror --check` end to end
// against a loopback log built from tests/vectors/log.json. Network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, writeFileSync, mkdtempSync, existsSync, readdirSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { entryBytes, leafHash, rootOf, consistencyPath, toB64 } from '../bin/lib/tlog.mjs';
import { tileIndexPath, tilePath, entryBundles, hashTiles, encodeBundle, parseBundle } from '../bin/lib/mirror.mjs';

const L = JSON.parse(readFileSync(new URL('./vectors/log.json', import.meta.url), 'utf8'));
const ENTRIES = L.entries.map((e) => Buffer.from(entryBytes(e.kind, e.statement)));

test('C2SP tile paths', () => {
  assert.equal(tileIndexPath(0), '000');
  assert.equal(tileIndexPath(7), '007');
  assert.equal(tileIndexPath(999), '999');
  assert.equal(tileIndexPath(1000), 'x001/000');
  assert.equal(tileIndexPath(1234067), 'x001/x234/067');
  assert.equal(tilePath(0, 0, 256), 'tile/0/000');
  assert.equal(tilePath(1, 3, 7), 'tile/1/003.p/7');
  assert.equal(tilePath('entries', 1000, 12), 'tile/entries/x001/000.p/12');
});

test('bundles and tiles: widths, levels, round trip', () => {
  assert.deepEqual(entryBundles(600), [{ index: 0, width: 256 }, { index: 1, width: 256 }, { index: 2, width: 88 }]);
  assert.deepEqual(entryBundles(256), [{ index: 0, width: 256 }]);
  const leaves = Array.from({ length: 600 }, (_, i) => leafHash(Buffer.from(`entry ${i}`)));
  const tiles = hashTiles(leaves);
  assert.deepEqual(tiles.map((t) => [t.level, t.index, t.width]), [[0, 0, 256], [0, 1, 256], [0, 2, 88], [1, 0, 2]]);
  assert.ok(tiles[3].bytes.subarray(0, 32).equals(rootOf(leaves.slice(0, 256))));
  const b = encodeBundle(ENTRIES);
  assert.deepEqual(parseBundle(b, ENTRIES.length).map((e) => e.toString()), ENTRIES.map((e) => e.toString()));
  assert.throws(() => parseBundle(b.subarray(0, b.length - 1)), /ends inside/);
  assert.throws(() => parseBundle(b, ENTRIES.length + 1), /expected/);
});

// ---- a loopback log serving tiles ------------------------------------------
let size = 3;
let forged = false; // serve a different entry 0 under the same checkpoint
function server() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const p = u.pathname.replace('/scan/log/v1', '');
      const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'content-type': type }); res.end(body); };
      const entries = ENTRIES.slice(0, size).map((e, i) => (forged && i === 0 ? Buffer.concat([e, Buffer.from(' ')]) : e));
      if (p === '/checkpoint') return send(200, L.checkpoints[String(size)], 'text/plain');
      if (p === '/proof/consistency') return send(200, JSON.stringify({ consistency_proof: consistencyPath(Number(u.searchParams.get('first')), ENTRIES.slice(0, Number(u.searchParams.get('second'))).map((e) => leafHash(e))).map(toB64) }));
      const want = tilePath('entries', 0, size);
      if (p === `/${want}`) return send(200, encodeBundle(entries), 'application/octet-stream');
      send(404, '{}');
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
function run(args, port) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, ...args, '--log-vkey', L.vkey], { env: { ...process.env, TROOTH_API: `http://127.0.0.1:${port}`, TROOTH_WEB: 'http://127.0.0.1:9', NO_COLOR: '1' } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
  });
}

test('trooth mirror: copy, grow append-only, refuse a forked source, mirror a mirror', async () => {
  const srv = await server(); const port = srv.address().port;
  const dir = join(mkdtempSync(join(tmpdir(), 'trooth-mirror-')), 'm');
  try {
    size = 3; forged = false;
    let r = await run(['mirror', dir, '--json'], port);
    assert.equal(r.code, 0, r.err);
    let d = JSON.parse(r.out);
    assert.equal(d.tree_size, 3); assert.equal(d.previous_size, null);
    assert.equal(d.root_hash, toB64(rootOf(ENTRIES.slice(0, 3).map((e) => leafHash(e)))));
    assert.equal(readFileSync(join(dir, 'checkpoint'), 'utf8'), L.checkpoints['3']);
    assert.ok(existsSync(join(dir, 'tile/entries/000.p/3')) && existsSync(join(dir, 'tile/0/000.p/3')));
    r = await run(['mirror', '--check', dir, '--json'], port);
    assert.equal(r.code, 0, r.out); d = JSON.parse(r.out);
    assert.equal(d.compatible, true); assert.equal(d.live_extends_mirror, true);

    size = 5; // the live log grew: the mirror is behind but consistent, then catches up
    r = await run(['mirror', '--check', dir, '--json'], port);
    assert.equal(r.code, 0, r.out); assert.equal(JSON.parse(r.out).live.tree_size, 5);
    r = await run(['mirror', dir, '--json'], port);
    assert.equal(r.code, 0, r.err); d = JSON.parse(r.out);
    assert.equal(d.previous_size, 3); assert.equal(d.tree_size, 5);

    const copy = join(mkdtempSync(join(tmpdir(), 'trooth-mirror2-')), 'm2');
    r = await run(['mirror', copy, '--from', dir, '--json'], port);
    assert.equal(r.code, 0, r.err);
    assert.equal(readFileSync(join(copy, 'tile/entries/000.p/5')).equals(readFileSync(join(dir, 'tile/entries/000.p/5'))), true);

    forged = true; // same signed checkpoint, a different entry: the root does not match
    const fresh = join(mkdtempSync(join(tmpdir(), 'trooth-mirror3-')), 'm3');
    r = await run(['mirror', fresh, '--json'], port);
    assert.equal(r.code, 9); assert.match(JSON.parse(r.out).problem, /not the signed root/);
    assert.equal(existsSync(join(fresh, 'checkpoint')), false, 'nothing is written for a source that does not check');
  } finally { srv.close(); forged = false; size = 3; }
});

test('trooth mirror --check catches a changed entry, a wrong tile, a missing tile, and a mirror ahead of the log', async () => {
  const srv = await server(); const port = srv.address().port;
  const dir = join(mkdtempSync(join(tmpdir(), 'trooth-mirror-')), 'm');
  try {
    size = 5;
    assert.equal((await run(['mirror', dir], port)).code, 0);
    const bad = join(mkdtempSync(join(tmpdir(), 'trooth-bad-')), 'b');
    cpSync(dir, bad, { recursive: true });
    const eb = join(bad, 'tile/entries/000.p/5');
    const bytes = readFileSync(eb); bytes[bytes.length - 2] ^= 1; writeFileSync(eb, bytes);
    let r = await run(['mirror', '--check', bad, '--json'], port);
    assert.equal(r.code, 9); assert.equal(JSON.parse(r.out).entries_match_checkpoint, false);

    cpSync(dir, bad, { recursive: true });
    const t0 = join(bad, 'tile/0/000.p/5');
    const tb = readFileSync(t0); tb[0] ^= 1; writeFileSync(t0, tb);
    r = await run(['mirror', '--check', bad, '--json'], port);
    assert.equal(r.code, 9); let d = JSON.parse(r.out);
    assert.equal(d.entries_match_checkpoint, true); assert.equal(d.tiles_match_entries, false);

    writeFileSync(t0, Buffer.alloc(0));
    r = await run(['mirror', '--check', bad, '--json'], port);
    assert.equal(r.code, 9);

    size = 3; // the live log is smaller than the mirror: a split view, or a lost tail
    r = await run(['mirror', '--check', dir, '--json'], port);
    assert.equal(r.code, 9); d = JSON.parse(r.out);
    assert.equal(d.live_extends_mirror, false); assert.match(d.problems.join(' '), /more than the live log/);
    r = await run(['mirror', dir, '--json'], port);
    assert.equal(r.code, 9, 'an existing mirror never shrinks'); assert.match(JSON.parse(r.out).problem, /fewer than/);
  } finally { srv.close(); size = 3; }
});

test('usage: one target, https for named URLs, no writing to a URL', async () => {
  let r = await run(['mirror'], 9); assert.equal(r.code, 2);
  r = await run(['mirror', 'https://mirror.example/log'], 9); assert.equal(r.code, 2);
  r = await run(['mirror', '--check', 'http://mirror.example/log'], 9); assert.equal(r.code, 2);
  r = await run(['mirror', '--check', join(tmpdir(), 'no-such-mirror-dir-x')], 9); assert.equal(r.code, 2);
});
