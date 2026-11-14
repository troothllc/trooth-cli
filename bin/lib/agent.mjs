// bin/lib/agent.mjs - THE AGENT COMMANDS: semanto, network, api, tools, login, logout, config, completion
// (tracker K1 to K9, golive213).
//
// One binary, `trooth`, reads the record (check, profile, verify and the rest) and now also runs Semanto and the
// Trooth Network for a person or an agent, the way GitHub's gh does for GitHub:
//   trooth semanto <tool> [args]     a Semanto MCP tool (`semanto <tool>` is the same, through the semanto alias)
//   trooth network <tool> [args]     a Trooth Network MCP tool
//   trooth api [-X METHOD] <path>    any api.trooth.co or trooth.co route, signed in, with --jq (gh api)
//   trooth tools --json              every operation: its MCP name, REST route, CLI command and approval class
//   trooth login | logout            sign in: the device flow (RFC 8628) when the server offers it, else the browser
//                                    with PKCE and a loopback redirect (RFC 8252); the token goes in the OS keychain
//   trooth config list|get|set|unset settings, read in the order flags, then environment, then the config file
//   trooth completion <shell>        bash, zsh, fish or powershell
//   trooth status [--json]           whether each public part of Trooth answers, and the last week's incidents (WC22)
//
// Agent mode (K3, clig.dev): TROOTH_API_KEY is the credential (an agent key, tra_ or tsk_); --json prints one JSON
// document; --no-input (or TROOTH_NO_INPUT, or CI) fails instead of prompting. These commands exit 0 on success,
// 2 when the request was refused (with the fix in the message), 3 when it needs a person's approval, and 4 when the
// service could not be reached. The read commands keep the exit codes they have published since 0.6.0, because
// scripts depend on them; that difference is deliberate and stated in `trooth --help`.
//
// A token is never written to a plain file. Where the OS keychain is not available, login refuses and says to use
// TROOTH_API_KEY, as gh refuses to store a token in plain text unless asked.

import { spawnSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';

export const AGENT_COMMANDS = new Set(['semanto', 'network', 'api', 'tools', 'login', 'logout', 'config', 'completion', 'status']);
export const AGENT_EXIT = { OK: 0, REFUSED: 2, APPROVAL: 3, UNREACHABLE: 4 };

const DEFAULTS = {
  api_base: 'https://api.trooth.co',
  site_base: 'https://trooth.co',
  // OM1 (2026-11-09): one Trooth MCP server for both products; the two old addresses are gone.
  semanto_mcp: 'https://mcp.trooth.co',
  network_mcp: 'https://mcp.trooth.co',
  timeout_ms: '20000',
};
const ENV = { api_base: 'TROOTH_API_BASE', site_base: 'TROOTH_SITE_BASE', semanto_mcp: 'TROOTH_SEMANTO_MCP', network_mcp: 'TROOTH_NETWORK_MCP', timeout_ms: 'TROOTH_TIMEOUT_MS' };
export const CONFIG_KEYS = Object.keys(DEFAULTS);

class Stop {
  constructor(code) { this.code = code; }
}

// ------------------------------------------------------------------ config (K7)

export function configDir(env = process.env) {
  if (env.TROOTH_CONFIG_DIR) return env.TROOTH_CONFIG_DIR;
  if (platform() === 'win32') return join(env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'trooth');
  return join(env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'trooth');
}
function configFile(env) { return join(configDir(env), 'config.json'); }
export function readConfigFile(env = process.env) {
  try { return JSON.parse(readFileSync(configFile(env), 'utf8')); } catch { return {}; }
}
function writeConfigFile(obj, env) {
  mkdirSync(configDir(env), { recursive: true, mode: 0o700 });
  writeFileSync(configFile(env), JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
}

/** Every setting with the value in force and where it came from: flag, then environment, then file, then default. */
export function resolveConfig(flags = {}, env = process.env) {
  const file = readConfigFile(env);
  const out = {};
  for (const k of CONFIG_KEYS) {
    const flag = flags[k];
    if (flag !== undefined) out[k] = { value: flag, source: 'flag' };
    else if (env[ENV[k]]) out[k] = { value: env[ENV[k]], source: `environment ${ENV[k]}` };
    else if (file[k] !== undefined) out[k] = { value: String(file[k]), source: `file ${configFile(env)}` };
    else out[k] = { value: DEFAULTS[k], source: 'default' };
  }
  return out;
}

// ------------------------------------------------------------------ the keychain (K2)

const SERVICE = 'trooth-cli';
export function keychain(env = process.env) {
  if (env.TROOTH_KEYCHAIN === 'memory') {
    const mem = (globalThis.__troothKeychain ??= new Map());
    return { name: 'memory (tests)', get: (a) => mem.get(a) ?? null, set: (a, v) => { mem.set(a, v); return true; }, del: (a) => mem.delete(a) };
  }
  const os = platform();
  if (os === 'darwin') {
    return {
      name: 'macOS Keychain',
      get: (a) => { const r = spawnSync('security', ['find-generic-password', '-s', SERVICE, '-a', a, '-w'], { encoding: 'utf8' }); return r.status === 0 ? r.stdout.trim() : null; },
      set: (a, v) => spawnSync('security', ['add-generic-password', '-U', '-s', SERVICE, '-a', a, '-w', v], { encoding: 'utf8' }).status === 0,
      del: (a) => spawnSync('security', ['delete-generic-password', '-s', SERVICE, '-a', a], { encoding: 'utf8' }).status === 0,
    };
  }
  if (os === 'linux' && spawnSync('sh', ['-c', 'command -v secret-tool'], { encoding: 'utf8' }).status === 0) {
    return {
      name: 'Secret Service (secret-tool)',
      get: (a) => { const r = spawnSync('secret-tool', ['lookup', 'service', SERVICE, 'account', a], { encoding: 'utf8' }); return r.status === 0 && r.stdout ? r.stdout.trim() : null; },
      set: (a, v) => spawnSync('secret-tool', ['store', '--label', 'Trooth CLI', 'service', SERVICE, 'account', a], { input: v, encoding: 'utf8' }).status === 0,
      del: (a) => spawnSync('secret-tool', ['clear', 'service', SERVICE, 'account', a], { encoding: 'utf8' }).status === 0,
    };
  }
  return null;
}

// ------------------------------------------------------------------ small jq (K4)

/** A subset of jq: .a.b, .a[0], .[], .a[], keys, length, and pipes between them. Enough for gh-style scripting. */
export function jq(expr, input) {
  let vals = [input];
  for (const stage of expr.split('|').map((s) => s.trim()).filter(Boolean)) {
    if (stage === 'length') { vals = vals.map((v) => (Array.isArray(v) || typeof v === 'string' ? v.length : v && typeof v === 'object' ? Object.keys(v).length : 0)); continue; }
    if (stage === 'keys') { vals = vals.map((v) => (v && typeof v === 'object' ? Object.keys(v).sort() : [])); continue; }
    if (!stage.startsWith('.')) throw new Error(`--jq supports .path, .[], keys and length; not "${stage}"`);
    const parts = stage === '.' ? [] : stage.slice(1).match(/[^.[\]]+|\[\d*\]/g) || [];
    for (const p of parts) {
      const next = [];
      for (const v of vals) {
        if (p === '[]') { if (Array.isArray(v)) next.push(...v); else if (v && typeof v === 'object') next.push(...Object.values(v)); }
        else if (/^\[\d+\]$/.test(p)) next.push(Array.isArray(v) ? v[Number(p.slice(1, -1))] ?? null : null);
        else next.push(v && typeof v === 'object' ? v[p] ?? null : null);
      }
      vals = next;
    }
  }
  return vals;
}

// ------------------------------------------------------------------ the command line

function parse(args) {
  const flags = {}; const pos = []; const kv = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json' || a === '--no-input' || a === '--all') { flags[a.slice(2)] = true; continue; }
    if (a === '-X' || a === '--method') { flags.method = args[++i]; continue; }
    if (a.startsWith('--') && a.includes('=')) { const [k, ...v] = a.slice(2).split('='); kv[k] = v.join('='); continue; }
    if (a.startsWith('--') && i + 1 < args.length && !args[i + 1].startsWith('--')) { kv[a.slice(2)] = args[++i]; continue; }
    if (a.startsWith('--')) { kv[a.slice(2)] = 'true'; continue; }
    pos.push(a);
  }
  return { flags, pos, kv };
}

function coerce(v) {
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^-?\d+$/.test(v)) return Number(v);
  if (/^[[{]/.test(v)) { try { return JSON.parse(v); } catch { /* text */ } }
  return v;
}

function noInput(flags, env) { return !!(flags['no-input'] || env.TROOTH_NO_INPUT || env.CI); }

/** A spinner on stderr, only on a terminal and never with --json or --quiet (K5). */
export function spinner(io, text) {
  if (!process.stderr.isTTY || io.asJson || io.quiet || process.env.CI) return { stop() {} };
  const frames = ['|', '/', '-', '\\']; let i = 0;
  const t = setInterval(() => process.stderr.write(`\r${frames[i++ % 4]} ${text}`), 120);
  return { stop() { clearInterval(t); process.stderr.write('\r\x1b[K'); } };
}

async function http(io, url, init, timeoutMs) {
  const s = spinner(io, `${init.method || 'GET'} ${new URL(url).host}`);
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    io.errLine(`error ${new URL(url).host} could not be reached (${e && e.name === 'TimeoutError' ? 'timed out' : e && e.message ? e.message : e}). Check the network and try again.`);
    throw new Stop(AGENT_EXIT.UNREACHABLE);
  } finally { s.stop(); }
}

// ------------------------------------------------------------------ credentials

function storedToken(resource, env) {
  const kc = keychain(env);
  const raw = kc && kc.get(resource);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function credentialFor(io, resource, cfg, env) {
  if (env.TROOTH_API_KEY) return env.TROOTH_API_KEY;
  const t = storedToken(resource, env);
  if (!t) return null;
  if (t.expires_at && Date.now() < t.expires_at - 30_000) return t.access_token;
  if (!t.refresh_token || !t.token_endpoint) return t.access_token;
  const res = await http(io, t.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: t.client_id, resource }) }, Number(cfg.timeout_ms.value));
  if (!res.ok) return null;
  const j = await res.json();
  const next = { ...t, access_token: j.access_token, refresh_token: j.refresh_token ?? t.refresh_token, expires_at: j.expires_in ? Date.now() + j.expires_in * 1000 : null };
  keychain(env)?.set(resource, JSON.stringify(next));
  return next.access_token;
}

// ------------------------------------------------------------------ MCP

async function mcp(io, server, method, params, cfg, env) {
  const token = await credentialFor(io, server, cfg, env);
  const res = await http(io, server, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) }, Number(cfg.timeout_ms.value));
  if (res.status === 401) {
    io.errLine(`error ${new URL(server).host} needs you signed in. Run \`trooth login\`, or set TROOTH_API_KEY to an agent key.`);
    throw new Stop(AGENT_EXIT.REFUSED);
  }
  if (res.status >= 500) { io.errLine(`error ${new URL(server).host} answered ${res.status}. Try again shortly.`); throw new Stop(AGENT_EXIT.UNREACHABLE); }
  const j = await res.json().catch(() => null);
  if (!j) { io.errLine('error the server did not answer JSON.'); throw new Stop(AGENT_EXIT.UNREACHABLE); }
  if (j.error) { io.errLine(`error ${j.error.message}`); throw new Stop(AGENT_EXIT.REFUSED); }
  return j.result;
}

/** The exit code a tool's answer earns (K3): approval 3, refusal 2, unreachable 4, else 0. */
export function toolExit(result) {
  if (result && result.resultType === 'input_required') return AGENT_EXIT.APPROVAL;
  const sc = result && result.structuredContent;
  const status = sc && typeof sc === 'object' ? sc.status : undefined;
  if (['human_action_required', 'approval_required', 'input_required'].includes(status)) return AGENT_EXIT.APPROVAL;
  if (['upstream_unavailable', 'session_unavailable'].includes(status)) return AGENT_EXIT.UNREACHABLE;
  if (result && result.isError) return AGENT_EXIT.REFUSED;
  return AGENT_EXIT.OK;
}

const toolName = (prefix, cmd) => (cmd.startsWith(`${prefix}_`) ? cmd : `${prefix}_${cmd.replace(/-/g, '_')}`);

async function toolCommand(io, which, args, env) {
  const { flags, pos, kv } = parse(args);
  const cfg = resolveConfig({}, env);
  const server = which === 'semanto' ? cfg.semanto_mcp.value : cfg.network_mcp.value;
  const prefix = which === 'semanto' ? 'semanto' : 'trooth';
  if (!pos.length) {
    const r = await mcp(io, `${server}${server.includes('?') ? '&' : '?'}tools=all`, 'tools/list', {}, cfg, env);
    const tools = (r.tools || []).map((t) => ({ name: t.name, command: `trooth ${which} ${t.name.replace(new RegExp(`^${prefix}_`), '').replace(/_/g, '-')}`, title: t.title, read_only: !!(t.annotations && t.annotations.readOnlyHint) }));
    if (io.asJson) io.emitJson({ server, tools });
    else for (const t of tools) io.out(`${t.command.padEnd(52)} ${t.title || ''}`);
    return AGENT_EXIT.OK;
  }
  const name = toolName(prefix, pos[0]);
  let args2 = {};
  if (kv.args) { try { args2 = JSON.parse(kv.args); } catch { io.errLine('error --args must be one JSON object.'); return AGENT_EXIT.REFUSED; } delete kv.args; }
  for (const [k, v] of Object.entries(kv)) args2[k.replace(/-/g, '_')] = coerce(v);
  const result = await mcp(io, server, 'tools/call', { name, arguments: args2 }, cfg, env);
  const code = toolExit(result);
  if (io.asJson) io.emitJson(result.structuredContent ?? result);
  else {
    const text = (result.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
    if (code === AGENT_EXIT.OK) io.out(text);
    else io.errLine(text);
  }
  if (code === AGENT_EXIT.APPROVAL && !io.asJson) io.errLine('This needs a person: open the link above, approve it, then run the command again.');
  void flags;
  return code;
}

async function apiCommand(io, args, env) {
  const { flags, pos, kv } = parse(args);
  const cfg = resolveConfig({}, env);
  const path = pos[0];
  if (!path || !path.startsWith('/')) { io.errLine('error usage: trooth api [-X METHOD] /path [--data JSON] [--jq EXPR]. Paths under /os and /public go to api.trooth.co; /api goes to trooth.co.'); return AGENT_EXIT.REFUSED; }
  const base = path.startsWith('/api/') ? cfg.site_base.value : cfg.api_base.value;
  const method = (flags.method || (kv.data ? 'POST' : 'GET')).toUpperCase();
  const token = env.TROOTH_API_KEY || (await credentialFor(io, cfg.semanto_mcp.value, cfg, env));
  const res = await http(io, base + path, { method, headers: { accept: 'application/json', ...(kv.data ? { 'content-type': 'application/json' } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}) }, ...(kv.data ? { body: kv.data } : {}) }, Number(cfg.timeout_ms.value));
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch { /* text */ }
  if (kv.jq) {
    let vals;
    try { vals = jq(kv.jq, body); } catch (e) { io.errLine(`error ${e.message}`); return AGENT_EXIT.REFUSED; }
    for (const v of vals) io.out(typeof v === 'string' ? v : JSON.stringify(v));
  } else io.out(typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  if (res.status >= 500) return AGENT_EXIT.UNREACHABLE;
  if (res.status === 202 && body && typeof body === 'object' && /approval/.test(JSON.stringify(body))) return AGENT_EXIT.APPROVAL;
  return res.status >= 400 ? AGENT_EXIT.REFUSED : AGENT_EXIT.OK;
}

/** K9: every operation on both servers, with its MCP name, REST route, CLI command and approval class. */
async function toolsCommand(io, args, env) {
  const cfg = resolveConfig({}, env);
  const rows = [];
  for (const [which, prefix, server] of [['semanto', 'semanto', cfg.semanto_mcp.value], ['network', 'trooth', cfg.network_mcp.value]]) {
    let list = [];
    try { list = (await mcp(io, `${server}?tools=all`, 'tools/list', {}, cfg, env)).tools || []; } catch (e) { if (!(e instanceof Stop)) throw e; continue; }
    for (const t of list) {
      const a = t.annotations || {};
      const meta = t._meta || {};
      rows.push({
        mcp: { server, name: t.name },
        rest: typeof meta['co.trooth/route'] === 'string' ? meta['co.trooth/route'] : null,
        cli: meta['co.trooth/cli'] || `trooth ${which} ${t.name.replace(new RegExp(`^${prefix}_`), '').replace(/_/g, '-')}`,
        approval: a.readOnlyHint ? 'read: runs alone' : a.destructiveHint ? 'destructive: asks first' : 'write: asks first in most clients',
        access: meta['co.trooth/access'] ?? null,
      });
    }
  }
  if (io.asJson) io.emitJson({ operations: rows });
  else for (const r of rows) io.out(`${r.cli.padEnd(48)} ${(r.rest || '').padEnd(48)} ${r.approval}`);
  return rows.length ? AGENT_EXIT.OK : AGENT_EXIT.UNREACHABLE;
}

// ------------------------------------------------------------------ login (K2)

const b64url = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function loginCommand(io, args, env) {
  const { flags, kv } = parse(args);
  const cfg = resolveConfig({}, env);
  const resource = kv.server === 'network' ? cfg.network_mcp.value : cfg.semanto_mcp.value;
  if (noInput(flags, env)) { io.errLine('error signing in needs a person at a browser, and --no-input (or CI) is set. For an agent, set TROOTH_API_KEY to an agent key made on trooth.co.'); return AGENT_EXIT.REFUSED; }
  const kc = keychain(env);
  if (!kc) { io.errLine('error no OS keychain was found (macOS Keychain or Secret Service), and Trooth never writes a token to a plain file. Set TROOTH_API_KEY to an agent key instead.'); return AGENT_EXIT.REFUSED; }
  const t = Number(cfg.timeout_ms.value);
  const u = new URL(resource);
  const prm = await (await http(io, `${u.origin}/.well-known/oauth-protected-resource${u.pathname}`, { method: 'GET' }, t)).json().catch(() => null);
  const issuer = prm && prm.authorization_servers && prm.authorization_servers[0];
  if (!issuer) { io.errLine(`error ${u.host} does not name a sign-in server. Use TROOTH_API_KEY.`); return AGENT_EXIT.REFUSED; }
  const as = await (await http(io, `${issuer.replace(/\/$/, '')}/.well-known/oauth-authorization-server`, { method: 'GET' }, t)).json().catch(() => null);
  if (!as || !as.token_endpoint) { io.errLine('error the sign-in server did not publish its metadata.'); return AGENT_EXIT.UNREACHABLE; }
  const save = (tok, client_id) => kc.set(resource, JSON.stringify({ access_token: tok.access_token, refresh_token: tok.refresh_token ?? null, expires_at: tok.expires_in ? Date.now() + tok.expires_in * 1000 : null, client_id, token_endpoint: as.token_endpoint }));
  // RFC 8628 when the server offers it: the user code is the pairing code the person types on the page.
  if (as.device_authorization_endpoint) {
    const client_id = kv['client-id'] || env.TROOTH_CLIENT_ID;
    if (!client_id) { io.errLine('error the device flow needs the CLI client id (TROOTH_CLIENT_ID).'); return AGENT_EXIT.REFUSED; }
    const d = await (await http(io, as.device_authorization_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id, resource }) }, t)).json();
    io.errLine(`Open ${d.verification_uri} and enter the code ${d.user_code}. Waiting for you to approve it there.`);
    let wait = (d.interval || 5) * 1000; const until = Date.now() + (d.expires_in || 300) * 1000;
    while (Date.now() < until) {
      await new Promise((r) => setTimeout(r, wait));
      const r = await http(io, as.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code, client_id }) }, t);
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.access_token) { save(j, client_id); io.errLine(`Signed in. The token is in the ${kc.name}.`); return AGENT_EXIT.OK; }
      if (j.error === 'slow_down') wait += 5000;
      else if (j.error !== 'authorization_pending') { io.errLine(`error sign-in ended: ${j.error || r.status}.`); return AGENT_EXIT.REFUSED; }
    }
    io.errLine('error the code expired before it was approved. Run `trooth login` again.');
    return AGENT_EXIT.REFUSED;
  }
  // The browser: dynamic registration (RFC 7591), PKCE S256 and a loopback redirect (RFC 8252), as MCP clients sign in.
  if (!as.registration_endpoint || !as.authorization_endpoint) { io.errLine('error the sign-in server offers neither the device flow nor client registration. Use TROOTH_API_KEY.'); return AGENT_EXIT.REFUSED; }
  const srv = createServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const redirect_uri = `http://127.0.0.1:${port}/callback`;
  try {
    const reg = await (await http(io, as.registration_endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Trooth CLI', redirect_uris: [redirect_uri], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }) }, t)).json();
    const verifier = b64url(randomBytes(32));
    const state = b64url(randomBytes(16));
    const pairing = state.slice(0, 4).toUpperCase() + '-' + state.slice(4, 8).toUpperCase();
    const authUrl = new URL(as.authorization_endpoint);
    for (const [k, v] of Object.entries({ response_type: 'code', client_id: reg.client_id, redirect_uri, code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256', state, resource })) authUrl.searchParams.set(k, v);
    const code = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), 5 * 60_000);
      srv.on('request', (req, res) => {
        const q = new URL(req.url, redirect_uri).searchParams;
        const ok = q.get('state') === state && q.get('code');
        res.writeHead(ok ? 200 : 400, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(ok ? `Signed in to Trooth (${pairing}). You can close this tab.` : 'This sign-in did not match. Run trooth login again.');
        clearTimeout(timer);
        resolve(ok ? q.get('code') : null);
      });
      io.errLine(`Opening your browser to sign in. Check that this window shows ${pairing} when you finish. If no browser opens, visit:\n${authUrl}`);
      const opener = platform() === 'darwin' ? 'open' : platform() === 'win32' ? 'explorer' : 'xdg-open';
      try { spawn(opener, [authUrl.toString()], { stdio: 'ignore', detached: true }).unref(); } catch { /* the link is printed */ }
    });
    if (!code) { io.errLine('error sign-in did not finish. Run `trooth login` again.'); return AGENT_EXIT.REFUSED; }
    const r = await http(io, as.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri, client_id: reg.client_id, code_verifier: verifier, resource }) }, t);
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.access_token) { io.errLine(`error the token exchange failed: ${j.error || r.status}.`); return AGENT_EXIT.REFUSED; }
    if (!save(j, reg.client_id)) { io.errLine('error the keychain refused the token; nothing was stored.'); return AGENT_EXIT.REFUSED; }
    io.errLine(`Signed in (${pairing}). The token is in the ${kc.name}.`);
    return AGENT_EXIT.OK;
  } finally { srv.close(); }
}

function logoutCommand(io, args, env) {
  const { kv } = parse(args);
  const cfg = resolveConfig({}, env);
  const resource = kv.server === 'network' ? cfg.network_mcp.value : cfg.semanto_mcp.value;
  const kc = keychain(env);
  const had = kc ? kc.del(resource) : false;
  io.errLine(had ? 'Signed out: the token is gone from the keychain.' : 'There was no stored sign-in.');
  return AGENT_EXIT.OK;
}

// ------------------------------------------------------------------ config and completion

function configCommand(io, args, env) {
  const { pos } = parse(args);
  const [sub, key, value] = pos;
  if (!sub || sub === 'list') {
    const cfg = resolveConfig({}, env);
    if (io.asJson) io.emitJson({ file: configFile(env), settings: cfg });
    else for (const k of CONFIG_KEYS) io.out(`${k.padEnd(12)} ${String(cfg[k].value).padEnd(44)} (${cfg[k].source})`);
    return AGENT_EXIT.OK;
  }
  if (!CONFIG_KEYS.includes(key || '')) { io.errLine(`error the settings are ${CONFIG_KEYS.join(', ')}. A key or token is never a setting: use TROOTH_API_KEY or trooth login.`); return AGENT_EXIT.REFUSED; }
  if (sub === 'get') { io.out(resolveConfig({}, env)[key].value); return AGENT_EXIT.OK; }
  const file = readConfigFile(env);
  if (sub === 'set') {
    if (value === undefined) { io.errLine('error usage: trooth config set <key> <value>'); return AGENT_EXIT.REFUSED; }
    if (key.endsWith('_mcp') || key.endsWith('_base')) { try { if (new URL(value).protocol !== 'https:' && !/^http:\/\/(127\.0\.0\.1|localhost)/.test(value)) throw 0; } catch { io.errLine('error an address must be https (or http on localhost).'); return AGENT_EXIT.REFUSED; } }
    file[key] = value;
  } else if (sub === 'unset') delete file[key];
  else { io.errLine('error usage: trooth config list|get|set|unset'); return AGENT_EXIT.REFUSED; }
  writeConfigFile(file, env);
  return AGENT_EXIT.OK;
}

export const COMMANDS_FOR_COMPLETION = ['check', 'profile', 'lint', 'verify', 'log', 'mirror', 'public-record', 'mcp-tools', 'guard', 'declare', 'evidence', 'delegation', 'semanto', 'network', 'api', 'tools', 'status', 'login', 'logout', 'config', 'completion', 'help', 'version'];

export function completionScript(shell) {
  const words = COMMANDS_FOR_COMPLETION.join(' ');
  if (shell === 'bash') return `# trooth completion for bash: add to ~/.bashrc:  eval "$(trooth completion bash)"\n_trooth() { local cur="\${COMP_WORDS[COMP_CWORD]}"; if [ "$COMP_CWORD" -eq 1 ]; then COMPREPLY=( $(compgen -W "${words}" -- "$cur") ); else COMPREPLY=( $(compgen -W "--json --no-input --quiet --no-color --help" -- "$cur") ); fi; }\ncomplete -F _trooth trooth\ncomplete -F _trooth semanto`;
  if (shell === 'zsh') return `#compdef trooth semanto\n# trooth completion for zsh: add to ~/.zshrc:  eval "$(trooth completion zsh)"\n_trooth() { if (( CURRENT == 2 )); then compadd -- ${words}; else compadd -- --json --no-input --quiet --no-color --help; fi }\ncompdef _trooth trooth semanto`;
  if (shell === 'fish') return `# trooth completion for fish: trooth completion fish > ~/.config/fish/completions/trooth.fish\ncomplete -c trooth -f -n '__fish_use_subcommand' -a '${words}'\ncomplete -c trooth -l json -d 'one JSON document on stdout'\ncomplete -c trooth -l no-input -d 'fail instead of prompting'`;
  if (shell === 'powershell') return `# trooth completion for PowerShell: add to $PROFILE:  trooth completion powershell | Out-String | Invoke-Expression\nRegister-ArgumentCompleter -Native -CommandName trooth -ScriptBlock { param($wordToComplete) '${COMMANDS_FOR_COMPLETION.join("','")}' | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) } }`;
  return null;
}

// ------------------------------------------------------------------ update notice (K8)

/** At most once a day, on a terminal, never with --json, --quiet or in CI: a newer trooth on npm. */
export async function updateNotice(io, version, env = process.env, now = Date.now(), fetcher = fetch) {
  if (io.asJson || io.quiet || !process.stderr.isTTY || env.CI || env.TROOTH_NO_UPDATE_NOTIFIER) return null;
  const file = join(configDir(env), 'update-check.json');
  let last = {};
  try { last = JSON.parse(readFileSync(file, 'utf8')); } catch { /* first check */ }
  if (last.checked_at && now - last.checked_at < 24 * 3600_000) return null;
  let latest = null;
  try { latest = (await (await fetcher('https://registry.npmjs.org/trooth/latest', { signal: AbortSignal.timeout(1500) })).json()).version; } catch { return null; }
  try { mkdirSync(configDir(env), { recursive: true, mode: 0o700 }); writeFileSync(file, JSON.stringify({ checked_at: now, latest }) + '\n', { mode: 0o600 }); } catch { /* no notice cache */ }
  if (latest && newer(latest, version)) { io.errLine(`A newer trooth is out: ${version} to ${latest}. Update with: npm install -g trooth`); return latest; }
  return null;
}
export function newer(a, b) {
  const p = (v) => v.split('.').map((x) => parseInt(x, 10) || 0);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
}

// ------------------------------------------------------------------ status (WC22, cli7)

/** What `trooth status` reads: each public part of Trooth, called directly, as `gh status` and the Stripe CLI
 *  read their own services. A part is operational when it answers below 500 within the time limit; slow past
 *  SLOW_MS, it is degraded; a 5xx or no answer is down. */
export const STATUS_SLOW_MS = 3000;
export function statusParts(cfg) {
  return [
    { key: 'website', name: 'trooth.co', url: `${cfg.site_base.value}/` },
    { key: 'api', name: 'API', url: `${cfg.api_base.value}/health` },
    { key: 'semanto', name: 'Semanto signed copies', url: `${cfg.api_base.value}/public/semanto/trooth/keys.json` },
    { key: 'mcp', name: 'MCP server', url: `${cfg.semanto_mcp.value.replace(/\/+$/, '')}/.well-known/oauth-protected-resource` },
  ];
}
export function statusState(httpStatus, ms) {
  if (!httpStatus || httpStatus >= 500) return 'down';
  return ms > STATUS_SLOW_MS ? 'degraded' : 'operational';
}

async function statusCommand(io, args, env) {
  if (args.includes('--help') || args.includes('-h')) {
    io.outAlways('usage: trooth status [--json]\n\nCalls trooth.co, the API, Semanto and the MCP server directly and reads the incident feed.\nExit 0 when every part answers; 4 when one is down (a 5xx or no answer).');
    return AGENT_EXIT.OK;
  }
  const { kv } = parse(args);
  const cfg = resolveConfig(kv, env);
  const timeoutMs = Number(cfg.timeout_ms.value) || 20000;
  const probe = async (p) => {
    const t0 = Date.now();
    try {
      const res = await fetch(p.url, { method: 'GET', signal: AbortSignal.timeout(timeoutMs), redirect: 'manual' });
      try { await res.body?.cancel(); } catch {}
      const ms = Date.now() - t0;
      return { key: p.key, name: p.name, url: p.url, http_status: res.status, ms, state: statusState(res.status, ms) };
    } catch (e) {
      return { key: p.key, name: p.name, url: p.url, http_status: null, ms: Date.now() - t0, state: 'down', error: e && e.name === 'TimeoutError' ? 'timed out' : 'no answer' };
    }
  };
  const s = spinner(io, 'reading Trooth status');
  let parts, incidents = null;
  try {
    const feed = `${cfg.site_base.value}/status/history.json`;
    [parts, incidents] = await Promise.all([
      Promise.all(statusParts(cfg).map(probe)),
      fetch(feed, { signal: AbortSignal.timeout(timeoutMs) }).then((r) => (r.ok ? r.json() : null)).catch(() => null),
    ]);
  } finally { s.stop(); }
  const week = Date.now() - 7 * 24 * 3600 * 1000;
  const recent = incidents && Array.isArray(incidents.items)
    ? incidents.items.filter((i) => Date.parse(i.date_modified || i.date_published) >= week).map((i) => ({ title: i.title, updated: i.date_modified || i.date_published }))
    : null;
  const page = `${cfg.site_base.value}/status`;
  if (io.asJson) io.emitJson({ object: 'trooth.status', read_at: new Date().toISOString(), parts, incidents_last_7_days: recent, page });
  else {
    for (const p of parts) io.out(`${p.name.padEnd(24)} ${p.state.padEnd(12)} ${p.http_status ?? (p.error || 'no answer')}  ${p.ms} ms`);
    if (recent === null) io.out('incidents                could not be read');
    else if (!recent.length) io.out('incidents                none in the last 7 days');
    else for (const i of recent) io.out(`incident                 ${i.title} (updated ${i.updated})`);
    io.out(`\nThe full page: ${page}`);
  }
  return parts.some((p) => p.state === 'down') ? AGENT_EXIT.UNREACHABLE : AGENT_EXIT.OK;
}

// ------------------------------------------------------------------ entry

export async function agentMain(cmd, args, io, env = process.env) {
  try {
    if (cmd === 'semanto' || cmd === 'network') return await toolCommand(io, cmd, args, env);
    if (cmd === 'api') return await apiCommand(io, args, env);
    if (cmd === 'tools') return await toolsCommand(io, args, env);
    if (cmd === 'login') return await loginCommand(io, args, env);
    if (cmd === 'logout') return logoutCommand(io, args, env);
    if (cmd === 'config') return configCommand(io, args, env);
    if (cmd === 'status') return await statusCommand(io, args, env);
    if (cmd === 'completion') {
      const s = completionScript(args[0]);
      if (!s) { io.errLine('error usage: trooth completion bash|zsh|fish|powershell'); return AGENT_EXIT.REFUSED; }
      io.outAlways(s);
      return AGENT_EXIT.OK;
    }
  } catch (e) {
    if (e instanceof Stop) return e.code;
    throw e;
  }
  return AGENT_EXIT.REFUSED;
}

export const _test = { parse, coerce, toolName, existsSync };
