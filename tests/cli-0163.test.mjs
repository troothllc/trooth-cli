// tests/cli-0163.test.mjs - what 0.16.3 fixed, held without the network:
//   * `trooth <command> [<subcommand>] --help` (and -h, and `trooth help ...`)
//     prints that command's usage and exits 0, for every command;
//   * every exit code a help lists is one the CLI defines, and the README's
//     table has a row for each;
//   * a Trooth slug is accepted where the server API accepts one (check,
//     verify, public-record), resolved on the record projection, and anything
//     else gets a usage error that names the domain to pass;
//   * public-record waits 45 seconds by default, --timeout changes it, and a
//     note says a reading is in progress after 5 seconds.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';

const cli = new URL('../bin/trooth.mjs', import.meta.url).pathname;
const CLOSED = 'http://127.0.0.1:9';

function run(args, env = {}) {
  return new Promise((resolve) => {
    const e = { ...process.env, TROOTH_WEB: CLOSED, TROOTH_API: CLOSED, NO_COLOR: '1', ...env };
    for (const [k, v] of Object.entries(e)) if (v === undefined) delete e[k];
    const p = spawn(process.execPath, [cli, ...args], { env: e });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code, out, err }));
    p.stdin.end();
  });
}

/* ---------------------------------------------------------------- help ---- */

const COMMANDS = {
  check: [], profile: [], lint: [], verify: [], mirror: [], 'public-record': [], 'mcp-tools': [],
  log: ['checkpoint', 'monitor', 'receipt'],
  guard: ['decide', 'hook', 'ci', 'cache'],
  declare: ['init', 'sign', 'check'],
};
const ALL = Object.entries(COMMANDS).flatMap(([c, subs]) => [[c], ...subs.map((s) => [c, s])]);

test('--help and -h work for every command and subcommand: its own usage on stdout, exit 0, nothing on stderr', async () => {
  for (const words of ALL) {
    for (const flag of ['--help', '-h']) {
      const r = await run([...words, flag]);
      const label = `trooth ${words.join(' ')} ${flag}`;
      assert.equal(r.code, 0, `${label}: ${r.err}`);
      assert.equal(r.err, '', label);
      assert.match(r.out, new RegExp(`^trooth ${words.join(' ')} v\\d`, 'm'), label);
      assert.match(r.out, /^Usage$/m, label);
      assert.match(r.out, /^Exit codes$/m, label);
      assert.ok(r.out.includes(`trooth ${words.join(' ')}`), label);
    }
  }
});

test('--help wins over every other argument: with --json, required flags missing, flags with values, in any position', async () => {
  const cases = [
    [['log', 'monitor', '--json', '--help'], 'log monitor'],
    [['log', '--help', 'receipt'], 'log receipt'],
    [['guard', 'decide', '--policy', 'nope.yaml', '--help'], 'guard decide'],
    [['guard', '--policy', 'x.yaml', '-h', 'cache'], 'guard cache'],
    [['declare', 'check', '--file', 'missing.json', '--help'], 'declare check'],
    [['mirror', '--check', '--help'], 'mirror'],
    [['verify', '--bundle', 'nope.json', '--offline', '--help'], 'verify'],
    [['public-record', '--cik', 'abc', '--help'], 'public-record'],
    [['check', 'not a domain', '--bogus-flag', '--help'], 'check'],
    [['guard', 'nope', '--help'], 'guard'],
  ];
  for (const [args, key] of cases) {
    const r = await run(args);
    assert.equal(r.code, 0, `${args.join(' ')}: ${r.err}`);
    assert.match(r.out, new RegExp(`^trooth ${key} v`, 'm'), args.join(' '));
  }
  // After `--`, --help is an argument, not a request for help.
  const r = await run(['check', '--', '--help']);
  assert.equal(r.code, 2);
  // As the value of a flag that takes one, it is that flag's value.
  const v = await run(['guard', 'decide', '--tool', '--help']);
  assert.equal(v.code, 2); assert.match(v.err, /--tool needs a value/);
});

test('trooth help <command> [<subcommand>] and trooth --help <command> print the same; an unknown topic exits 2', async () => {
  for (const words of ALL) {
    const a = await run(['help', ...words]);
    const b = await run([...words, '--help']);
    assert.equal(a.code, 0, words.join(' '));
    assert.equal(a.out, b.out, words.join(' '));
  }
  assert.equal((await run(['--help', 'log', 'monitor'])).out, (await run(['log', 'monitor', '--help'])).out);
  const general = await run(['help']);
  assert.equal(general.code, 0); assert.match(general.out, /trooth <command> --help/);
  const bogus = await run(['help', 'bogus']);
  assert.equal(bogus.code, 2); assert.match(bogus.err, /no help for bogus/);
  const unknown = await run(['bogus', '--help']);
  assert.equal(unknown.code, 2); assert.match(unknown.err, /unknown command: bogus/);
  const retired = await run(['scan', '--help']);
  assert.equal(retired.code, 2); assert.match(retired.err, /retired/);
});

test('a usage error points at the command\'s own help', async () => {
  const r = await run(['log', 'monitor', '--bogus']);
  assert.equal(r.code, 2); assert.match(r.err, /Run `trooth log --help`/);
});

const EXIT_CODES = (() => {
  const src = readFileSync(cli, 'utf8');
  const m = /const EXIT = \{([^}]+)\}/.exec(src);
  return new Set([...m[1].matchAll(/:\s*(\d+)/g)].map((x) => Number(x[1])));
})();
const codesIn = (text) => [...text.slice(text.indexOf('Exit codes')).matchAll(/^ {2}(\d{1,2})\s/gm)].map((x) => Number(x[1]));

test('every exit code a help lists is one the CLI defines, and every defined code is in the README table and the general help', async () => {
  for (const words of ALL) {
    const r = await run([...words, '--help']);
    const codes = codesIn(r.out);
    assert.ok(codes.length >= 2, words.join(' '));
    for (const c of codes) assert.ok(EXIT_CODES.has(c), `${words.join(' ')} lists ${c}`);
  }
  const general = (await run(['--help'])).out;
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const table = readme.slice(readme.indexOf('## Exit codes'), readme.indexOf('## `trooth check`'));
  for (const c of EXIT_CODES) {
    assert.match(table, new RegExp(`^\\| ${c} \\|`, 'm'), `README exit code table has ${c}`);
    assert.ok(codesIn(general).includes(c), `general help lists ${c}`);
  }
});

test('verify --help agrees with the verdict table in docs/VERIFY.md', async () => {
  const doc = readFileSync(new URL('../docs/VERIFY.md', import.meta.url), 'utf8');
  const help = (await run(['verify', '--help'])).out;
  const listed = new Set(codesIn(help));
  const table = doc.slice(doc.indexOf('## 5. The verdict'), doc.indexOf('## 6.'));
  for (const m of table.matchAll(/\| (\d+) \|\s*$/gm)) assert.ok(listed.has(Number(m[1])), `verify --help lists ${m[1]}`);
  for (const c of [1, 2, 3, 5, 6, 7]) assert.match(table, new RegExp(`\\b${c}\\b`), `docs/VERIFY.md names exit ${c}`);
});

/* ---------------------------------------------------------------- slugs ---- */

const RECORD = JSON.parse(readFileSync(new URL('./fixtures/projection/record-v2.json', import.meta.url), 'utf8')).body; // slug acme-cloud, domain acme.example
const READING = (domain) => JSON.stringify({ ...JSON.parse(readFileSync(new URL('./fixtures/public-record/apple.com.json', import.meta.url), 'utf8')), domain, bindings: [], sec: null, lei: null });

function stand(handler) {
  return new Promise((resolve) => {
    const seen = [];
    const srv = http.createServer((req, res) => { seen.push(req.url); handler(req, res); });
    srv.seen = seen;
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
const base = (srv) => `http://127.0.0.1:${srv.address().port}`;

function projection() {
  return stand((req, res) => {
    const q = new URL(req.url, 'http://x').searchParams.get('q');
    if (q === 'acme-cloud' || q === 'acme.example') return json(res, 200, RECORD);
    if (q === 'acme') return json(res, 200, RECORD); // a name match: the record's slug is acme-cloud
    if (q === 'twins') return json(res, 200, { found: false, ambiguous: true, candidates: [{ domain: 'twin-a.example' }, { domain: 'twin-b.example' }] });
    return json(res, 200, { found: false });
  });
}

test('check, verify and public-record accept a Trooth slug: resolved on the projection, then read by its domain', async () => {
  const web = await projection();
  const api = await stand((req, res) => json(res, 200, READING(decodeURIComponent(/^\/scan\/public-record\/([^?]+)/.exec(req.url)?.[1] || ''))));
  const env = { TROOTH_WEB: base(web), TROOTH_API: base(api) };
  try {
    let r = await run(['check', 'acme-cloud', '--json'], env);
    assert.equal(r.code, 5, r.err); // the fixture record is listed, not witnessed
    assert.equal(JSON.parse(r.out).domain, 'acme.example');
    assert.match(r.err, /acme-cloud is a Trooth slug: the record for acme\.example/);
    assert.deepEqual(web.seen.splice(0), ['/api/network/profile?q=acme-cloud&contract=2', '/api/network/profile?q=acme.example&contract=2']);

    r = await run(['check', 'Acme-Cloud'], env);
    assert.equal(r.code, 5, r.err); assert.match(r.out, /acme\.example/);
    web.seen.length = 0;

    r = await run(['verify', 'acme-cloud', '--json'], env);
    assert.equal(r.code, 5, r.err); // no signed statement in the fixture
    assert.equal(JSON.parse(r.out).domain, 'acme.example');

    r = await run(['public-record', 'acme-cloud', '--json'], env);
    assert.equal(r.code, 1, r.err); // the reading names no SEC filer or LEI
    assert.equal(JSON.parse(r.out).domain, 'acme.example');
    assert.deepEqual(api.seen.splice(0), ['/scan/public-record/acme.example']);

    // A domain is never read as a slug: one request, no resolution.
    web.seen.length = 0;
    r = await run(['check', 'acme.example', '--json'], env);
    assert.deepEqual(web.seen, ['/api/network/profile?q=acme.example&contract=2']);
    assert.doesNotMatch(r.err, /slug/);
  } finally { web.close(); api.close(); }
});

test('a name that is not a slug a record carries is a usage error that says what to pass; an unreadable projection is exit 3', async () => {
  const web = await projection();
  const env = { TROOTH_WEB: base(web) };
  try {
    let r = await run(['check', 'nosuchco'], env);
    assert.equal(r.code, 2); assert.match(r.err, /no Trooth record has the slug nosuchco\. Pass the company's domain, for example: trooth check stripe\.com/);
    r = await run(['verify', 'acme', '--json'], env);
    assert.equal(r.code, 2);
    assert.match(r.err, /no Trooth record has the slug acme\. The closest record is Acme Cloud, acme\.example: trooth verify acme\.example/);
    assert.equal(JSON.parse(r.out).exit, 2);
    r = await run(['public-record', 'twins'], env);
    assert.equal(r.code, 2); assert.match(r.err, /matches more than one Trooth record \(twin-a\.example, twin-b\.example\)/);
  } finally { web.close(); }
  let r = await run(['check', 'acme-cloud', '--json']);
  assert.equal(r.code, 3); assert.match(r.err, /read as a Trooth slug, and the record projection could not be read/);
  // Not a slug: a reserved single label, a URL, a name with a space.
  for (const bad of ['localhost', 'https://acme', 'acme cloud', '-acme']) {
    r = await run(['check', bad]);
    assert.equal(r.code, 2, bad);
  }
  // Offline there is nothing to resolve a slug against.
  r = await run(['verify', 'acme-cloud', '--offline', '--file', 'x.json', '--keys', 'k.json']);
  assert.equal(r.code, 2); assert.match(r.err, /offline, pass the domain/);
  // declare check reads the site itself, so it takes a domain only.
  r = await run(['declare', 'check', 'acme-cloud', '--no-dns']);
  assert.equal(r.code, 2); assert.match(r.err, /is not a domain name/);
});

/* -------------------------------------------------- public-record timing ---- */

test('public-record: --timeout is validated, a slow answer past it is exit 3 with what to do, and the deadline is in --json', async () => {
  for (const bad of ['0', 'abc', '601', '1.5', '-3']) {
    const r = await run(['public-record', 'acme.example', '--timeout', bad]);
    assert.equal(r.code, 2, bad);
  }
  const slow = await stand((req, res) => setTimeout(() => json(res, 200, READING('acme.example')), 2500));
  try {
    const r = await run(['public-record', 'acme.example', '--timeout', '1', '--json'], { TROOTH_API: base(slow), TROOTH_TIMEOUT_MS: undefined });
    assert.equal(r.code, 3);
    assert.match(r.err, /did not answer within 1000 ms\. A first reading can take longer than that; .* --timeout <seconds> waits longer\./);
    assert.equal(JSON.parse(r.out).timeout_ms, 1000);
  } finally { slow.close(); }
});

test('public-record waits past 15 seconds by default, and says a reading is in progress after 5 (TROOTH_PROGRESS=1 stands in for a terminal)', async () => {
  const slow = await stand((req, res) => setTimeout(() => json(res, 200, READING('acme.example')), 16500));
  try {
    const r = await run(['public-record', 'acme.example'], { TROOTH_API: base(slow), TROOTH_TIMEOUT_MS: undefined, TROOTH_PROGRESS: '1' });
    assert.equal(r.code, 1, r.err);
    assert.equal(r.err.match(/reading in progress/g)?.length, 1, r.err);
    assert.match(r.err, /Waiting up to 45 seconds \(--timeout <seconds> to change\)/);
  } finally { slow.close(); }
  // Not on a terminal, and a quick answer: no note.
  const quick = await stand((req, res) => json(res, 200, READING('acme.example')));
  try {
    const r = await run(['public-record', 'acme.example'], { TROOTH_API: base(quick), TROOTH_PROGRESS: undefined });
    assert.equal(r.code, 1, r.err);
    assert.doesNotMatch(r.err, /reading in progress/);
  } finally { quick.close(); }
});
