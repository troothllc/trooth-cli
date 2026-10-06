// tests/verify.test.mjs - `trooth verify` and its core (bin/lib/verify.mjs)
// against tests/vectors/vectors.json, and the CLI end to end in offline mode.
// Network-free: the CLI is run with --offline and saved files only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { verifyStatement } from '../bin/lib/verify.mjs';

const dir = new URL('./vectors/', import.meta.url);
const doc = JSON.parse(readFileSync(new URL('vectors.json', dir), 'utf8'));
const mapping = readFileSync(new URL(doc.mapping_file, dir));
const other = readFileSync(new URL(doc.other_mapping_file, dir));
const mappingFor = (m) => (m === true ? mapping : m === 'other' ? other : undefined);

test('vectors.json is reproduced exactly by generate.mjs', () => {
  execFileSync(process.execPath, [new URL('generate.mjs', dir).pathname, '--check']);
});

for (const v of doc.vectors) {
  test(`vector ${v.name}: ${v.expect.verdict}`, () => {
    const r = verifyStatement({ statement: v.statement, keys: v.keys, mappingBytes: mappingFor(v.mapping), manifest: v.manifest ?? undefined, domain: v.domain });
    assert.equal(r.verdict, v.expect.verdict, v.note);
    assert.equal(r.signature, v.expect.signature, v.note);
  });
}

test('a statement that is not trusted exposes no payload-derived conclusions', () => {
  const v = doc.vectors.find((x) => x.name === 'compromised-key');
  const r = verifyStatement({ statement: v.statement, keys: v.keys, mappingBytes: mapping, manifest: v.manifest, domain: v.domain });
  assert.equal(r.binding.status, 'unchecked');
  assert.equal(r.subject.status, 'not_checked');
});

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
function run(args) {
  const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, TROOTH_WEB: 'http://127.0.0.1:9', TROOTH_API: 'http://127.0.0.1:9', NO_COLOR: '1' } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function files(v) {
  const t = mkdtempSync(join(tmpdir(), 'trooth-verify-'));
  writeFileSync(join(t, 'statement.json'), JSON.stringify({ statement: v.statement, manifest: v.manifest }));
  writeFileSync(join(t, 'keys.json'), JSON.stringify({ keys: v.keys, list_read_at: '2026-10-06T00:00:00.000Z' }));
  return t;
}

const EXPECT_EXIT = { checked: 0, checked_v1: 0, partially_checked: 4, signature_not_trusted: 8, mismatch: 9 };

for (const name of ['valid-v2', 'valid-v1', 'v2-no-mapping-supplied', 'tampered-payload', 'compromised-key', 'mapping-mismatch', 'domain-mismatch']) {
  test(`trooth verify --offline exits ${name}`, () => {
    const v = doc.vectors.find((x) => x.name === name);
    const t = files(v);
    const args = ['verify', v.domain, '--file', join(t, 'statement.json'), '--keys', join(t, 'keys.json'), '--offline', '--json'];
    if (v.mapping) args.push('--mapping', new URL(v.mapping === true ? doc.mapping_file : doc.other_mapping_file, dir).pathname);
    const r = run(args);
    assert.equal(r.code, EXPECT_EXIT[v.expect.verdict], r.err || r.out);
    const out = JSON.parse(r.out);
    assert.equal(out.verdict, v.expect.verdict);
    assert.equal(out.sources.keys, join(t, 'keys.json'));
  });
}

test('--offline sends nothing: no --keys is a usage error, not a network read', () => {
  const v = doc.vectors[0];
  const t = files(v);
  const r = run(['verify', v.domain, '--file', join(t, 'statement.json'), '--offline']);
  assert.equal(r.code, 2);
  assert.match(r.err, /--offline needs --keys/);
});

test('human output names each part and ends on the verdict', () => {
  const v = doc.vectors[0];
  const t = files(v);
  const r = run(['verify', v.domain, '--file', join(t, 'statement.json'), '--keys', join(t, 'keys.json'), '--offline', '--mapping', new URL(doc.mapping_file, dir).pathname]);
  assert.equal(r.code, 0, r.err);
  for (const word of ['signature', 'subject', 'mapping', 'manifest', 'counts', 'Checked.']) assert.match(r.out, new RegExp(word));
});

test('help lists verify and its exit codes', () => {
  const r = run(['--help']);
  assert.match(r.out, /trooth verify <domain>/);
  assert.match(r.out, /8 verify: signature does not check/);
});
