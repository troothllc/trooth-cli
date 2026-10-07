// scripts/guard-results.mjs - write docs/GUARD-RESULTS.md from an actual run
// of the guard's test files (and, with --tlc <tla2tools.jar>, of TLC on
// spec/GuardDecision.tla). Nothing in that file is written by hand.
//
//   node scripts/guard-results.mjs [--tlc /path/to/tla2tools.jar]
import { spawnSync } from 'node:child_process';
import { writeFileSync, readFileSync, mkdtempSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('../', import.meta.url);
const files = ['tests/guard-policy.test.mjs', 'tests/guard.test.mjs', 'tests/guard-cli.test.mjs', 'tests/guard-adapters.test.mjs', 'tests/guard-adversarial.test.mjs', 'tests/guard-model.test.mjs', 'tests/guard-fuzz.test.mjs'];
const runs = {};
for (const f of files) {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ['--test', '--test-reporter=tap', f], { cwd: root.pathname, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const out = r.stdout || '';
  const num = (k) => Number((new RegExp(`^# ${k} (\\d+)$`, 'm').exec(out) || [])[1] ?? NaN);
  const cases = [...out.matchAll(/^\s*(ok|not ok) \d+ - (.*)$/gm)].map((m) => ({ ok: m[1] === 'ok', name: m[2].replace(/\s+#\s*(SKIP|TODO).*$/, '') })).filter((c) => !/\.mjs$/.test(c.name));
  runs[f] = { status: r.status, tests: num('tests'), pass: num('pass'), fail: num('fail'), skipped: num('skipped'), todo: num('todo'), cases, seconds: ((Date.now() - t0) / 1000).toFixed(1), model: (/# model: (.*)$/m.exec(out) || [])[1] ?? null, fuzz: [...out.matchAll(/^#\s*(?:\\#\s*)?fuzz: (.*)$/gm)].map((m) => m[1]) };
}

let tlc = null;
const i = process.argv.indexOf('--tlc');
if (i > 0) {
  const jar = process.argv[i + 1];
  if (!jar || !existsSync(jar)) { console.error('--tlc needs the path of tla2tools.jar'); process.exit(2); }
  const dir = mkdtempSync(join(tmpdir(), 'guard-tlc-'));
  for (const f of ['GuardDecision.tla', 'GuardDecision.cfg']) copyFileSync(new URL(`spec/${f}`, root), join(dir, f));
  const r = spawnSync('java', ['-XX:+UseParallelGC', '-cp', jar, 'tlc2.TLC', '-workers', 'auto', '-config', 'GuardDecision.cfg', 'GuardDecision.tla'], { cwd: dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const lines = (r.stdout + r.stderr).split('\n').filter((l) => /^TLC2 Version|^Finished computing initial states|^Model checking completed|^Error:|is violated|states generated, .* distinct states found|^The depth of the complete state graph|^Finished in/.test(l));
  tlc = { status: r.status, lines };
  // A mutant with the absolute-rule branch removed must be caught, or the invariants check nothing.
  const mdir = mkdtempSync(join(tmpdir(), 'guard-tlc-mutant-'));
  const src = readFileSync(new URL('spec/GuardDecision.tla', root), 'utf8');
  const mutated = src.replace('ELSE IF AbsoluteFailed THEN "deny"', 'ELSE IF FALSE THEN "deny"');
  if (mutated === src) throw new Error('the mutant did not change the spec');
  writeFileSync(join(mdir, 'GuardDecision.tla'), mutated);
  writeFileSync(join(mdir, 'GuardDecision.cfg'), readFileSync(new URL('spec/GuardDecision.cfg', root), 'utf8').replace('MaxRules = 3', 'MaxRules = 1'));
  const m = spawnSync('java', ['-cp', jar, 'tlc2.TLC', '-workers', 'auto', '-config', 'GuardDecision.cfg', 'GuardDecision.tla'], { cwd: mdir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  tlc.mutant = { status: m.status, lines: (m.stdout + m.stderr).split('\n').filter((l) => /^Error: Invariant .* is violated/.test(l)).slice(0, 3) };
}

const date = new Date().toISOString();
const total = Object.values(runs).reduce((a, r) => ({ tests: a.tests + r.tests, pass: a.pass + r.pass, fail: a.fail + r.fail, skipped: a.skipped + r.skipped }), { tests: 0, pass: 0, fail: 0, skipped: 0 });
const adv = runs['tests/guard-adversarial.test.mjs'];
let md = `# Guard results

Written by \`node scripts/guard-results.mjs${tlc ? ' --tlc <tla2tools.jar>' : ''}\` on ${date} (Node ${process.version}), from an actual run of the files below. Do not edit by hand; run the script again.

## Test files

| File | Tests | Pass | Fail | Skipped | Seconds |
|---|---|---|---|---|---|
${files.map((f) => `| ${f} | ${runs[f].tests} | ${runs[f].pass} | ${runs[f].fail} | ${runs[f].skipped} | ${runs[f].seconds} |`).join('\n')}
| all | ${total.tests} | ${total.pass} | ${total.fail} | ${total.skipped} | |

## Adversarial suite (tests/guard-adversarial.test.mjs)

Each case is an attack on a pre-execution guardrail, in the style of AgentDojo's injection tasks: real Ed25519 signatures, a real RFC 9162 Merkle log with a signed checkpoint, and real witness cosignatures, made with keys generated for the run. A case passes only when the guard reaches the decision and reason code the case states.

| Result | Case |
|---|---|
${adv.cases.map((c) => `| ${c.ok ? 'pass' : 'FAIL'} | ${c.name.replace(/\|/g, '\\|')} |`).join('\n')}

${adv.pass} of ${adv.tests} cases passed${adv.fail ? `; ${adv.fail} failed` : ''}. These are tasks written by Trooth against its own guard; they are not the AgentDojo benchmark itself, and no outside party has run them.

## Model check

JavaScript, exhaustive (tests/guard-model.test.mjs): ${runs['tests/guard-model.test.mjs'].model ?? 'no count reported'}. Result: ${runs['tests/guard-model.test.mjs'].fail === 0 && runs['tests/guard-model.test.mjs'].pass === runs['tests/guard-model.test.mjs'].tests ? `all ${runs['tests/guard-model.test.mjs'].tests} tests passed` : 'FAILED'}.

TLA+ (spec/GuardDecision.tla with spec/GuardDecision.cfg): ${tlc ? `TLC exit status ${tlc.status}. The lines TLC printed:\n\n\`\`\`\n${tlc.lines.join('\n')}\n\`\`\`\n\nAs a check that the invariants can fail, the same run model-checked a mutant of the spec with the absolute-rule branch removed (MaxRules = 1). TLC exit status ${tlc.mutant.status}:\n\n\`\`\`\n${tlc.mutant.lines.join('\n') || '(no violation reported)'}\n\`\`\`` : 'TLC was not run when this file was written (run the script with --tlc <tla2tools.jar>).'}

The invariants, in both: allow implies every required check held; source unreachable never yields allow; deny happens only for a failed proof or an absolute rule (or where the customer's policy itself chose deny for no record or no source); missing, stale or disputed evidence alone never denies (TLA+); the same inputs always give the same decision.

## Malformed-input testing (tests/guard-fuzz.test.mjs)

A seeded, deterministic generator (seed ${(/seed (\d+)/.exec(runs['tests/guard-fuzz.test.mjs'].fuzz.join(' ')) || [])[1] ?? 'not reported'}) makes malformed and mutated policies, facts, tool calls, cached bundles and hook input, and checks that parsePolicy returns a policy inside its schema or throws PolicyError within a per-case time bound, that decideFrom never allows facts lacking required evidence, that an offline guard with no cached bundle never allows, that a bundle with its signed bytes changed never allows, and that the hook exits only 0 or 2. Result: ${runs['tests/guard-fuzz.test.mjs'].fail === 0 && runs['tests/guard-fuzz.test.mjs'].pass === runs['tests/guard-fuzz.test.mjs'].tests ? `all ${runs['tests/guard-fuzz.test.mjs'].tests} tests passed` : 'FAILED'}. The lines the run printed:

\`\`\`
${runs['tests/guard-fuzz.test.mjs'].fuzz.join('\n') || '(none)'}
\`\`\`

## What these results do not show

They show that the guard, as written, reaches the stated decisions on these inputs. They come from Trooth's internal review gate (docs/GUARD-THREAT-MODEL.md, "Review status"); they are not an outside security review and not evidence of use in production by teams outside Trooth. Both of those are launch-phase items.
`;
writeFileSync(new URL('docs/GUARD-RESULTS.md', root), md);
console.log(`wrote docs/GUARD-RESULTS.md: ${total.pass}/${total.tests} passed${tlc ? `; TLC exit ${tlc.status}` : ''}`);
if (total.fail || (tlc && tlc.status !== 0)) process.exit(1);
