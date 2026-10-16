// tests/cli-0170.test.mjs - what 0.17.0 added, held without the network:
//   * --quiet (-q) prints nothing on stdout or stderr for a command that runs,
//     and the exit code is unchanged; an error still prints its one line;
//   * --quiet with --json, and --quiet on `guard hook`, are usage errors;
//   * help and --version still print under --quiet;
//   * color: --no-color and NO_COLOR turn it off, FORCE_COLOR=0 turns it off,
//     FORCE_COLOR=1 turns it on when stdout is not a terminal;
//   * both flags are accepted by every command and in any position.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const infra = new URL('./fixtures/infra', import.meta.url).pathname;
const CLOSED = 'http://127.0.0.1:9';
const ESC = '\x1b[';

function run(args, env = {}) {
  return new Promise((resolve) => {
    const e = { ...process.env, TROOTH_WEB: CLOSED, TROOTH_API: CLOSED, ...env };
    delete e.FORCE_COLOR; delete e.NO_COLOR;
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete e[k]; else e[k] = v;
    const p = spawn(process.execPath, [cli, ...args], { env: e });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
    p.stdin.end();
  });
}

test('--quiet prints nothing and keeps the exit code', async () => {
  const loud = await run(['lint', infra]);
  assert.ok(loud.out.length > 0);
  for (const args of [['lint', infra, '--quiet'], ['lint', '-q', infra], ['-q', 'lint', infra], ['--quiet', 'lint', infra]]) {
    const q = await run(args);
    assert.equal(q.code, loud.code, args.join(' '));
    assert.equal(q.out, '', args.join(' '));
    assert.equal(q.err, '', args.join(' '));
  }
});

test('an error under --quiet still prints one line and its exit code', async () => {
  const r = await run(['check', '--quiet']);
  assert.equal(r.code, 2);
  assert.equal(r.out, '');
  assert.equal(r.err.trim().split('\n').length, 1);
  const up = await run(['check', 'example.com', '--quiet', '--no-fallback']);
  assert.equal(up.code, 3);
  assert.equal(up.out, '');
});

test('--quiet with --json, and on guard hook, is a usage error', async () => {
  const a = await run(['lint', infra, '--quiet', '--json']);
  assert.equal(a.code, 2);
  assert.match(a.err, /--quiet prints nothing and --json/);
  assert.equal(a.out, '');
  const b = await run(['guard', 'hook', '--policy', 'x.yaml', '-q']);
  assert.equal(b.code, 2);
  assert.match(b.err, /does not take --quiet/);
});

test('help and --version print under --quiet', async () => {
  assert.match((await run(['--version', '-q'])).out, /^\d+\.\d+\.\d+/);
  assert.match((await run(['--help', '--quiet'])).out, /--quiet, -q/);
  const h = await run(['lint', '--help', '-q']);
  assert.equal(h.code, 0);
  assert.ok(h.out.length > 0);
});

test('color: off when piped, on with FORCE_COLOR=1, off again with FORCE_COLOR=0, NO_COLOR or --no-color', async () => {
  assert.ok(!(await run(['--help'])).out.includes(ESC));
  assert.ok((await run(['--help'], { FORCE_COLOR: '1' })).out.includes(ESC));
  assert.ok(!(await run(['--help'], { FORCE_COLOR: '0' })).out.includes(ESC));
  assert.ok(!(await run(['--help'], { FORCE_COLOR: 'false' })).out.includes(ESC));
  assert.ok(!(await run(['--help'], { FORCE_COLOR: '1', NO_COLOR: '1' })).out.includes(ESC));
  assert.ok(!(await run(['--help', '--no-color'], { FORCE_COLOR: '1' })).out.includes(ESC));
});

test('every command accepts --quiet and --no-color without an unknown-flag error', async () => {
  for (const c of ['check', 'profile', 'lint', 'verify', 'log', 'mirror', 'public-record', 'mcp-tools', 'declare', 'evidence', 'delegation']) {
    const r = await run([c, '--no-color', '--quiet']);
    assert.ok(!/unknown flag/.test(r.err), `${c}: ${r.err}`);
  }
});
