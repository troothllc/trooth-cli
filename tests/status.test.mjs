// tests/status.test.mjs - WC22 (cli7): `trooth status` against loopback servers, network-free.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { statusState, STATUS_SLOW_MS } from '../bin/lib/agent.mjs';

const BIN = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const run = (args, env) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, TROOTH_CONFIG_DIR: mkdtempSync(join(tmpdir(), 'trooth-')), TROOTH_NO_UPDATE_NOTIFIER: '1', CI: '1', ...env } });
  let out = '', err = '';
  p.stdout.on('data', (d) => (out += d));
  p.stderr.on('data', (d) => (err += d));
  p.on('close', (code) => resolve({ code, out, err }));
});
async function server(handler) {
  const s = http.createServer((req, res) => { const [st, body] = handler(req); res.writeHead(st, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, close: () => { s.closeAllConnections(); s.close(); } };
}

test('WC22: the states: under 500 and quick is operational, slow is degraded, a 5xx or no answer is down', () => {
  assert.equal(statusState(200, 10), 'operational');
  assert.equal(statusState(404, 10), 'operational');
  assert.equal(statusState(200, STATUS_SLOW_MS + 1), 'degraded');
  assert.equal(statusState(503, 10), 'down');
  assert.equal(statusState(null, 10), 'down');
});

test('WC22: trooth status reads each part and the incident feed, prints one line each, and exits 0 when all answer', async () => {
  const recent = new Date().toISOString();
  const s = await server((req) => (req.url === '/status/history.json' ? [200, { items: [{ title: 'API slow in us-east', date_published: recent, date_modified: recent }, { title: 'Old', date_published: '2020-01-01T00:00:00Z' }] }] : [200, { ok: true }]));
  try {
    const env = { TROOTH_SITE_BASE: s.url, TROOTH_API_BASE: s.url, TROOTH_SEMANTO_MCP: s.url };
    const r = await run(['status'], env);
    assert.equal(r.code, 0, r.err);
    for (const name of ['trooth.co', 'API', 'Semanto signed copies', 'MCP server']) assert.match(r.out, new RegExp(`^${name.replace('.', '\\.')}\\s+operational\\s+200`, 'm'));
    assert.match(r.out, /incident\s+API slow in us-east/);
    assert.doesNotMatch(r.out, /Old/);
    const j = JSON.parse((await run(['status', '--json'], env)).out);
    assert.equal(j.object, 'trooth.status');
    assert.deepEqual(j.parts.map((p) => p.key), ['website', 'api', 'semanto', 'mcp']);
    assert.equal(j.incidents_last_7_days.length, 1);
  } finally { s.close(); }
});

test('WC22: a part that answers 5xx is down and the command exits 4', async () => {
  const s = await server((req) => (req.url === '/health' ? [503, { ok: false }] : [200, { items: [] }]));
  try {
    const r = await run(['status', '--json'], { TROOTH_SITE_BASE: s.url, TROOTH_API_BASE: s.url, TROOTH_SEMANTO_MCP: s.url });
    assert.equal(r.code, 4);
    assert.equal(JSON.parse(r.out).parts.find((p) => p.key === 'api').state, 'down');
  } finally { s.close(); }
});

test('RG40: the GitHub Action builds a new version through the API and never signs or publishes', () => {
  const a = readFileSync(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(a, /using: composite/);
  assert.match(a, /api -X POST "\/os\/semanto\/\$\{TROOTH_ID\}\/build"/);
  const steps = a.slice(a.indexOf('runs:'));
  assert.doesNotMatch(steps, /\/sign\b|\/publish|semanto_sign/i);
  const v = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  assert.match(a, new RegExp(`default: "${v.replace(/\./g, '\\.')}"`), 'the action runs the CLI version it ships with');
  assert.match(a, new RegExp(`troothllc/trooth-cli@v${v.replace(/\./g, '\\.')}`));
});
