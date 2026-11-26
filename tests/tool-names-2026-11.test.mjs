// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Trooth, LLC
// `trooth semanto <tool>` runs the tool the list names (cli61), and a page checked against its signed copy fails the
// command unless it matches. The server here is a local fixture; no request leaves the machine.
//   node tests/tool-names-2026-11.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { resolveToolName, agentMain, toolExit } from '../bin/lib/agent.mjs';

const LISTED = ['trooth_verify', 'trooth_semanto_status', 'call_tool', 'search_tools', 'enable_toolset', 'semanto_legacy'];
const PAGE = 'https://fixture-signed-copy.xyz/';

test('each name the list prints leads back to the tool the server lists', () => {
  assert.equal(resolveToolName('semanto', 'trooth-verify', LISTED), 'trooth_verify');
  assert.equal(resolveToolName('semanto', 'trooth-semanto-status', LISTED), 'trooth_semanto_status');
  assert.equal(resolveToolName('semanto', 'call-tool', LISTED), 'call_tool');
  assert.equal(resolveToolName('semanto', 'legacy', LISTED), 'semanto_legacy');
  assert.equal(resolveToolName('trooth', 'verify', LISTED), 'trooth_verify');
  assert.equal(resolveToolName('trooth', 'semanto-status', LISTED), 'trooth_semanto_status');
  // No list to read: the prefix is added, as before.
  assert.equal(resolveToolName('semanto', 'status', []), 'semanto_status');
  assert.equal(resolveToolName('semanto', 'semanto_status', []), 'semanto_status');
});

test('only a page that matches its signed copy passes', () => {
  const r = (status) => ({ structuredContent: { object: 'semanto.verify', url: PAGE, status } });
  assert.equal(toolExit(r('matches')), 0);
  for (const s of ['differs', 'not_served', 'unknown_url', 'not_signed']) assert.equal(toolExit(r(s)), 9, s);
  // A token check keeps its own answers.
  assert.equal(toolExit({ structuredContent: { status: 'valid' } }), 0);
});

async function fixture(status) {
  const calls = [];
  const s = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      const j = JSON.parse(body);
      let result;
      if (j.method === 'tools/list') result = { tools: LISTED.map((name) => ({ name, title: name })) };
      else {
        calls.push(j.params);
        const sc = { object: 'semanto.verify', status, url: j.params.arguments.url, hash: 'sha256:' + '1'.repeat(64), version: 1 };
        result = { structuredContent: sc, content: [{ type: 'text', text: JSON.stringify(sc) }] };
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: j.id, result }));
    });
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, calls, close: () => { s.closeAllConnections(); s.close(); } };
}
const io = (out, err) => ({ out: (x) => out.push(x), diag: () => {}, errLine: (x) => err.push(x), emitJson: () => {}, outAlways: () => {}, asJson: false, quiet: false });

for (const [status, code] of [['matches', 0], ['differs', 9], ['not_served', 9]]) {
  test(`trooth semanto trooth-verify --url on a .xyz page: ${status} exits ${code}`, async () => {
    const s = await fixture(status);
    const out = [], err = [];
    const got = await agentMain('semanto', ['trooth-verify', '--url', PAGE], io(out, err), { TROOTH_SEMANTO_MCP: s.url, TROOTH_KEYCHAIN: 'memory' });
    s.close();
    assert.equal(got, code, err.join('\n'));
    assert.equal(s.calls.length, 1);
    assert.equal(s.calls[0].name, 'trooth_verify');
    assert.deepEqual(s.calls[0].arguments, { url: PAGE });
  });
}
