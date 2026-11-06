// tests/agent.test.mjs - the agent commands (tracker K1 to K9, 0.23.0) against loopback MCP and API servers.
// Network-free: every address points at 127.0.0.1, and the keychain is the in-memory one (TROOTH_KEYCHAIN=memory).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { jq, resolveConfig, completionScript, toolExit, newer, updateNotice, AGENT_EXIT } from '../bin/lib/agent.mjs';

const BIN = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const ALIAS = new URL('../bin/semanto.mjs', import.meta.url).pathname;

function run(args, env = {}, bin = BIN) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [bin, ...args], { env: { PATH: process.env.PATH, TROOTH_CONFIG_DIR: env.TROOTH_CONFIG_DIR ?? mkdtempSync(join(tmpdir(), 'trooth-')), TROOTH_NO_UPDATE_NOTIFIER: '1', ...env } });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
  });
}

async function server(handler) {
  const seen = [];
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      let msg = null;
      try { msg = body ? JSON.parse(body) : null; } catch { msg = null; }
      seen.push({ url: req.url, method: req.method, auth: req.headers.authorization ?? null, msg });
      const [status, out] = handler(req, msg);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    });
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, seen, close: () => { s.closeAllConnections(); s.close(); } };
}

const mcpReply = (msg, result) => [200, { jsonrpc: '2.0', id: msg.id, result }];

test('K1: trooth semanto <tool> calls the Semanto MCP tool with the arguments, and semanto <tool> is the same', async () => {
  const s = await server((req, msg) => {
    if (msg.method === 'tools/list') return mcpReply(msg, { tools: [{ name: 'semanto_status', title: 'Setup status and next step', annotations: { readOnlyHint: true }, _meta: { 'co.trooth/route': 'GET /os/semanto/{trooth_id}/setup', 'co.trooth/cli': 'trooth semanto status', 'co.trooth/access': 'read' } }] });
    return mcpReply(msg, { content: [{ type: 'text', text: '{"step":"done"}' }], structuredContent: { step: 'done', args: msg.params.arguments }, isError: false });
  });
  const env = { TROOTH_SEMANTO_MCP: `${s.url}/os/semanto/mcp`, TROOTH_API_KEY: 'tsk_test_only' };
  const r = await run(['semanto', 'status', '--trooth-id', 'acme', '--json'], env);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(JSON.parse(r.out), { step: 'done', args: { trooth_id: 'acme' } });
  assert.equal(s.seen.at(-1).msg.params.name, 'semanto_status');
  assert.equal(s.seen.at(-1).auth, 'Bearer tsk_test_only');
  const a = await run(['status', '--json'], env, ALIAS);
  assert.equal(a.code, 0, a.err);
  const list = await run(['semanto', '--json'], env);
  assert.equal(JSON.parse(list.out).tools[0].command, 'trooth semanto status');
  assert.match(s.seen.find((x) => x.msg && x.msg.method === 'tools/list').url, /tools=all/);
  s.close();
});

test('K3: exit 3 when a person must approve, 2 when refused, 4 when the service cannot be reached', async () => {
  const s = await server((req, msg) => {
    const n = msg.params.name;
    if (n === 'semanto_key_revoke') return mcpReply(msg, { content: [{ type: 'text', text: 'A person approves this on trooth.co.' }], structuredContent: { status: 'human_action_required', url: 'https://trooth.co/dashboard/semanto/keys' }, isError: false });
    return mcpReply(msg, { content: [{ type: 'text', text: 'semanto_lei takes no x.' }], structuredContent: { status: 'invalid_request' }, isError: true });
  });
  const env = { TROOTH_SEMANTO_MCP: `${s.url}/os/semanto/mcp`, TROOTH_API_KEY: 'tsk_test_only' };
  assert.equal((await run(['semanto', 'key-revoke', '--kid', 'k1'], env)).code, AGENT_EXIT.APPROVAL);
  assert.equal((await run(['semanto', 'lei', '--x', '1'], env)).code, AGENT_EXIT.REFUSED);
  s.close();
  assert.equal((await run(['semanto', 'status'], { TROOTH_SEMANTO_MCP: 'http://127.0.0.1:9/mcp', TROOTH_TIMEOUT_MS: '2000' })).code, AGENT_EXIT.UNREACHABLE);
  assert.equal(toolExit({ resultType: 'input_required' }), 3);
});

test('K3: --no-input fails instead of opening a browser, and no keychain means no stored token', async () => {
  const r = await run(['login', '--no-input']);
  assert.equal(r.code, 2);
  assert.match(r.err, /TROOTH_API_KEY/);
  const ci = await run(['login'], { CI: '1' });
  assert.equal(ci.code, 2);
});

test('K4: trooth api passes the call through with the key and filters with --jq', async () => {
  const s = await server(() => [200, { data: [{ name: 'a' }, { name: 'b' }], total: 2 }]);
  const r = await run(['api', '/os/semanto/acme/receipts', '--jq', '.data[].name'], { TROOTH_API_BASE: s.url, TROOTH_API_KEY: 'tra_test_only' });
  assert.equal(r.code, 0, r.err);
  assert.equal(r.out.trim(), 'a\nb');
  assert.equal(s.seen[0].auth, 'Bearer tra_test_only');
  const post = await run(['api', '-X', 'POST', '/os/semanto/acme/build', '--data', '{"reason":"x"}'], { TROOTH_API_BASE: s.url, TROOTH_API_KEY: 'tra_test_only' });
  assert.equal(post.code, 0);
  assert.equal(s.seen[1].method, 'POST');
  s.close();
  assert.deepEqual(jq('.a | keys', { a: { y: 1, x: 2 } }), [['x', 'y']]);
  assert.deepEqual(jq('.a | length', { a: [1, 2, 3] }), [3]);
  assert.deepEqual(jq('.a[1]', { a: [1, 2, 3] }), [2]);
});

test('K5: no escape codes and no spinner when the output is not a terminal', async () => {
  const s = await server((req, msg) => mcpReply(msg, { content: [{ type: 'text', text: 'ok' }], isError: false }));
  const r = await run(['semanto', 'guide'], { TROOTH_SEMANTO_MCP: `${s.url}/mcp`, FORCE_COLOR: '1' });
  assert.doesNotMatch(r.err, /\r[|/\\-] /);
  s.close();
  assert.match(readFileSync(new URL('../bin/lib/agent.mjs', import.meta.url), 'utf8'), /if \(!process\.stderr\.isTTY \|\| io\.asJson \|\| io\.quiet \|\| process\.env\.CI\) return \{ stop\(\) \{\} \};/);
});

test('K6: completion scripts for bash, zsh, fish and PowerShell name every command', async () => {
  for (const sh of ['bash', 'zsh', 'fish', 'powershell']) {
    const s = completionScript(sh);
    assert.ok(s && s.includes('semanto') && s.includes('completion'), sh);
  }
  const r = await run(['completion', 'bash']);
  assert.equal(r.code, 0);
  assert.match(r.out, /complete -F _trooth trooth/);
  assert.equal((await run(['completion', 'tcsh'])).code, 2);
});

test('K7: settings come from flags, then the environment, then the file; a key is never a setting', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-'));
  writeFileSync(join(dir, 'config.json'), JSON.stringify({ api_base: 'https://file.example', site_base: 'https://site.example' }));
  const env = { TROOTH_CONFIG_DIR: dir, TROOTH_API_BASE: 'https://env.example' };
  const c = resolveConfig({}, env);
  assert.equal(c.api_base.value, 'https://env.example');
  assert.match(c.api_base.source, /environment/);
  assert.equal(c.site_base.value, 'https://site.example');
  assert.match(c.site_base.source, /^file/);
  assert.equal(resolveConfig({ api_base: 'https://flag.example' }, env).api_base.source, 'flag');
  const list = await run(['config', 'list', '--json'], env);
  assert.equal(JSON.parse(list.out).settings.api_base.value, 'https://env.example');
  assert.equal((await run(['config', 'set', 'api_key', 'tra_x'], env)).code, 2);
  assert.equal((await run(['config', 'set', 'site_base', 'http://evil.example'], env)).code, 2);
  assert.equal((await run(['config', 'set', 'timeout_ms', '5000'], env)).code, 0);
  assert.equal(JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')).timeout_ms, '5000');
});

test('K8: the update notice is once a day, on a terminal only, and never with --json', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'trooth-'));
  const lines = [];
  const io = { asJson: false, quiet: false, errLine: (s) => lines.push(s) };
  const fetcher = async () => ({ json: async () => ({ version: '9.0.0' }) });
  const tty = process.stderr.isTTY;
  Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
  try {
    assert.equal(await updateNotice(io, '0.23.0', { TROOTH_CONFIG_DIR: dir }, 1_000_000, fetcher), '9.0.0');
    assert.equal(await updateNotice(io, '0.23.0', { TROOTH_CONFIG_DIR: dir }, 1_000_000 + 3600_000, fetcher), null);
    assert.equal(await updateNotice({ ...io, asJson: true }, '0.23.0', { TROOTH_CONFIG_DIR: mkdtempSync(join(tmpdir(), 'trooth-')) }, 1, fetcher), null);
    assert.equal(await updateNotice(io, '0.23.0', { TROOTH_CONFIG_DIR: mkdtempSync(join(tmpdir(), 'trooth-')), CI: '1' }, 1, fetcher), null);
  } finally { Object.defineProperty(process.stderr, 'isTTY', { value: tty, configurable: true }); }
  assert.equal(lines.length, 1);
  assert.ok(newer('0.23.1', '0.23.0') && !newer('0.22.9', '0.23.0'));
});

test('K9: trooth tools --json lists every operation with its MCP name, REST route, CLI command and approval class', async () => {
  const s = await server((req, msg) => mcpReply(msg, { tools: [{ name: req.url.includes('semanto') ? 'semanto_sign' : 'trooth_get_fact', annotations: { readOnlyHint: !req.url.includes('semanto'), destructiveHint: false }, _meta: req.url.includes('semanto') ? { 'co.trooth/route': 'POST /os/semanto/{trooth_id}/sign', 'co.trooth/cli': 'trooth semanto sign', 'co.trooth/access': 'write' } : {} }] }));
  const r = await run(['tools', '--json'], { TROOTH_SEMANTO_MCP: `${s.url}/os/semanto/mcp`, TROOTH_NETWORK_MCP: `${s.url}/public/mcp` });
  assert.equal(r.code, 0, r.err);
  const ops = JSON.parse(r.out).operations;
  assert.deepEqual(ops.map((o) => o.cli), ['trooth semanto sign', 'trooth network get-fact']);
  assert.equal(ops[0].rest, 'POST /os/semanto/{trooth_id}/sign');
  assert.equal(ops[0].approval, 'write: asks first in most clients');
  assert.equal(ops[1].approval, 'read: runs alone');
  s.close();
});

test('K2: login stores the token in the keychain through the device flow, and logout removes it', async () => {
  let polls = 0;
  const s = await server((req) => {
    if (req.url.startsWith('/.well-known/oauth-protected-resource')) return [200, { resource: 'x', authorization_servers: [`http://${req.headers.host}`] }];
    if (req.url === '/.well-known/oauth-authorization-server') return [200, { issuer: 'x', token_endpoint: `http://${req.headers.host}/token`, device_authorization_endpoint: `http://${req.headers.host}/device` }];
    if (req.url === '/device') return [200, { device_code: 'dc', user_code: 'BCDF-GHJK', verification_uri: 'https://example.test/device', expires_in: 30, interval: 0.01 }];
    if (req.url === '/token') return ++polls < 2 ? [400, { error: 'authorization_pending' }] : [200, { access_token: 'at-1', refresh_token: 'rt-1', expires_in: 3600 }];
    return [404, {}];
  });
  const env = { TROOTH_SEMANTO_MCP: `${s.url}/os/semanto/mcp`, TROOTH_KEYCHAIN: 'memory', TROOTH_CLIENT_ID: 'client_test' };
  // The in-memory keychain lives in one process, so the login runs here rather than in a child.
  const { agentMain } = await import('../bin/lib/agent.mjs');
  const err = [];
  const io = { out: () => {}, diag: () => {}, errLine: (x) => err.push(x), emitJson: () => {}, outAlways: () => {}, asJson: false, quiet: false };
  assert.equal(await agentMain('login', [], io, env), 0, err.join('\n'));
  assert.match(err.join('\n'), /BCDF-GHJK/);
  assert.match(globalThis.__troothKeychain.get(`${s.url}/os/semanto/mcp`), /"access_token":"at-1"/);
  assert.equal(await agentMain('logout', [], io, env), 0);
  assert.equal(globalThis.__troothKeychain.get(`${s.url}/os/semanto/mcp`), undefined);
  s.close();
});
