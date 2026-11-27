// CA-D-007, CA-D-008, CA-D-034, CA-D-039 (cli62): `--help` on every command prints usage, exits 0, and reads,
// writes and sends nothing; the tool list names each tool once and the command words lead back to the tool.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { AGENT_HELP, commandWords, resolveToolName, updateNotice, _test } from '../bin/lib/agent.mjs';

const bin = fileURLToPath(new URL('../bin/trooth.mjs', import.meta.url));
// Any network call fails fast here: a closed local port for every server and the API.
const env = { ...process.env, TROOTH_SEMANTO_MCP: 'http://127.0.0.1:9', TROOTH_NETWORK_MCP: 'http://127.0.0.1:9', TROOTH_API_BASE: 'http://127.0.0.1:9', TROOTH_SITE_BASE: 'http://127.0.0.1:9', TROOTH_API_KEY: 'tra_test_only', NO_COLOR: '1' };
const run = (args) => spawnSync(process.execPath, [bin, ...args], { env, encoding: 'utf8', timeout: 15000 });

const commands = ['check', 'profile', 'lint', 'verify', 'log', 'mirror', 'public-record', 'mcp-tools', 'guard', 'declare', 'evidence', 'delegation', 'semanto', 'network', 'api', 'tools', 'status', 'login', 'logout', 'config', 'completion'];
for (const c of commands) {
  for (const flag of ['--help', '-h']) {
    const r = run([c, flag]);
    assert.equal(r.status, 0, `${c} ${flag} exits 0 (got ${r.status}: ${r.stderr})`);
    assert.match(r.stdout, /usage|Usage/, `${c} ${flag} prints usage`);
    assert.doesNotMatch(r.stdout + r.stderr, /There was no stored sign-in|keychain was found|ECONNREFUSED|fetch failed|not reachable/, `${c} ${flag} acts on nothing`);
  }
  const h = run(['help', c]);
  assert.equal(h.status, 0, `trooth help ${c} exits 0`);
}
for (const c of Object.keys(AGENT_HELP)) assert.match(AGENT_HELP[c], /Exit/, `${c} help names its exit codes`);

// The one server lists trooth_semanto_* tools: the words printed lead back to the tool.
assert.equal(commandWords('semanto', 'trooth_semanto_status'), 'status');
assert.equal(commandWords('semanto', 'semanto_page'), 'page');
assert.equal(commandWords('network', 'trooth_profile_get'), 'profile-get');
assert.equal(resolveToolName('semanto', 'status', ['trooth_semanto_status', 'trooth_status']), 'trooth_semanto_status');
assert.equal(resolveToolName('network', 'profile-get', ['trooth_profile_get']), 'trooth_profile_get');
// Help never checks for an update, even on a terminal (the check is the only call a help run could make).
{
  let called = 0;
  const spy = async () => { called++; return { json: async () => ({ version: '99.0.0' }) }; };
  const tty = process.stderr.isTTY; Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
  try {
    const r = await updateNotice({ help: true, asJson: false, quiet: false, errLine: () => {} }, '0.0.1', { TROOTH_CONFIG_DIR: '/nonexistent' }, Date.now(), spy);
    assert.equal(r, null); assert.equal(called, 0, 'help made no update request');
  } finally { Object.defineProperty(process.stderr, 'isTTY', { value: tty, configurable: true }); }
}
// After --, every word is an argument: no empty-named flag reaches a tool.
{
  const p = _test.parse(['sign', '--', '--help', 'x']);
  assert.deepEqual(p.pos, ['sign', '--help', 'x']); assert.equal(Object.prototype.hasOwnProperty.call(p.kv, ''), false);
}
console.log('help-2026-11: ok');
