// The GitHub Action's two scripts, and the shape of action.yml, without GitHub.
//
//   node tests/action.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.message ?? e)); }
}
const run = (args) => spawnSync(process.execPath, args, { encoding: "utf8" });
const dir = mkdtempSync(join(tmpdir(), "trooth-action-"));

// A real lint over the fixture, the way the action runs it.
const lint = spawnSync(process.execPath, ["bin/trooth.mjs", "lint", "tests/fixtures/infra", "--json"], { encoding: "utf8", env: { ...process.env, TROOTH_API: "http://127.0.0.1:9" } });
const report = join(dir, "report.json");
writeFileSync(report, lint.stdout);
const stderrFile = join(dir, "stderr.txt");
writeFileSync(stderrFile, lint.stderr);

console.log("summary");
t("the summary is a table of counts with no verdict, no pass mark and no file name", () => {
  const r = run(["action/summary.mjs", report, String(lint.status), stderrFile]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^## Trooth lint \(advisory\)/);
  assert.match(r.stdout, /\| Declaration files read \| 2 \(terraform 1 · kubernetes 1\) \|/);
  assert.match(r.stdout, /\| Inline credential literals \| 0 \(a count; the literals are never printed\) \|/);
  assert.match(r.stdout, /\| Digest \| `sha256:[a-f0-9]{64}` \|/);
  assert.match(r.stdout, /nothing is sent to Trooth/);
  assert.ok(!/main\.tf|deploy\.yaml/.test(r.stdout), "no file name in the summary");
  assert.ok(!/\b(pass|fail|score|grade|verdict:)\b/i.test(r.stdout.replace(/no verdict/gi, "")), "no verdict word");
});
t("nothing read is described as a fact about the directory, not the infrastructure", () => {
  const empty = join(dir, "empty.json");
  writeFileSync(empty, JSON.stringify({ ok: false, error: "no infrastructure declarations found under ./x.", exit: 1, files_opened: 0, root: "./x" }));
  const r = run(["action/summary.mjs", empty, "1", stderrFile]);
  assert.match(r.stdout, /No infrastructure declarations were found/);
  assert.match(r.stdout, /not about your infrastructure/);
});
t("a usage error is reported as the action's fault", () => {
  const err = join(dir, "err.txt"); writeFileSync(err, "trooth: path not found: ./nope\n");
  const r = run(["action/summary.mjs", join(dir, "missing.json"), "2", err]);
  assert.match(r.stdout, /could not run: trooth: path not found/);
});

console.log("outputs");
t("outputs carry the digest, the count read and the credential count, in GITHUB_OUTPUT form", () => {
  const r = run(["action/outputs.mjs", report, "0"]);
  const kv = Object.fromEntries(r.stdout.trim().split("\n").map((l) => l.split("=")));
  assert.match(kv.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(kv["declarations-read"], "2");
  assert.equal(kv["inline-credential-literals"], "0");
  assert.equal(kv["exit-code"], "0");
});
t("a missing report yields empty and zero outputs rather than an error", () => {
  const r = run(["action/outputs.mjs", join(dir, "missing.json"), "1"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^digest=\n/);
  assert.match(r.stdout, /declarations-read=0/);
});

console.log("action.yml");
const yml = readFileSync("action.yml", "utf8");
t("advisory by default: both gates default to false and there is no other way to fail", () => {
  assert.match(yml, /fail-on-inline-credentials:[\s\S]*?default: "false"/);
  assert.match(yml, /fail-if-nothing-read:[\s\S]*?default: "false"/);
  const exits = [...yml.matchAll(/exit (\d)/g)].map((m) => m[1]);
  assert.deepEqual(exits.sort(), ["0", "1", "1", "2"]);
});
t("the CLI version is pinned and lint is pointed at an unroutable API", () => {
  assert.match(yml, /default: "0\.4\.4"/);
  assert.match(yml, /TROOTH_API: "http:\/\/127\.0\.0\.1:9"/);
});
t("it asks for no token and no write permission", () => {
  assert.ok(!/GITHUB_TOKEN|github-token|pull-requests: write/.test(yml));
});

console.log("the run block, executed the way a runner executes it");
// The composite step's own bash, lifted out of action.yml, with the install
// skipped and the bin pointed at this checkout (no network here), and the
// runner's files pointed at a scratch directory. The self-test workflow does
// the same with the real install; this proves the gate logic without it.
const runBlock = yml.split(/^      run: \|\n/m)[1].split("\n").map((l) => l.replace(/^ {8}/, "")).join("\n");
assert.ok(runBlock.includes('TROOTH_BIN="$CLI_DIR/node_modules/trooth/bin/trooth.mjs"'), "the bin line is where the test expects it");
const sim = join(dir, "sim");
const step = (path, opts = {}) => {
  const env = {
    ...process.env, RUNNER_TEMP: sim, GITHUB_ACTION_PATH: process.cwd(),
    GITHUB_STEP_SUMMARY: join(sim, "summary.md"), GITHUB_OUTPUT: join(sim, "output.txt"),
    TROOTH_LINT_PATH: path, TROOTH_CLI_VERSION: "local", TROOTH_API: "http://127.0.0.1:9",
    TROOTH_FAIL_ON_INLINE_CREDENTIALS: opts.creds || "false", TROOTH_FAIL_IF_NOTHING_READ: opts.nothing || "false",
  };
  const bin = opts.bin || join(process.cwd(), "bin", "trooth.mjs");
  const script = runBlock.replace(/^TROOTH_BIN=.*$/m, `TROOTH_BIN=${JSON.stringify(bin)}`);
  const r = spawnSync("bash", ["-c", script], { encoding: "utf8", env });
  return { status: r.status, stdout: r.stdout, summary: readFileSync(join(sim, "summary.md"), "utf8"), output: readFileSync(join(sim, "output.txt"), "utf8") };
};
mkdirSync(sim, { recursive: true });
const reset = () => { writeFileSync(join(sim, "summary.md"), ""); writeFileSync(join(sim, "output.txt"), ""); };
t("the fixture: exit 0, the summary table, the outputs", () => {
  reset(); const r = step("tests/fixtures/infra");
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.summary, /\| Declaration files read \| 2 \(terraform 1 · kubernetes 1\) \|/);
  assert.match(r.output, /^digest=sha256:[a-f0-9]{64}$/m);
  assert.match(r.output, /^declarations-read=2$/m);
  assert.match(r.output, /^report=.*trooth-lint\.json$/m);
});
t("a directory with nothing to read: exit 0 unless asked, exit 1 when asked", () => {
  reset(); assert.equal(step(".github").status, 0);
  reset(); const r = step(".github", { nothing: "true" });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /::error title=Trooth lint::no infrastructure declarations were found under \.github/);
});
t("a path that does not exist: exit 2, and the annotation says why", () => {
  reset(); const r = step("/nope/nowhere");
  assert.equal(r.status, 2);
  assert.match(r.stdout, /::error title=Trooth lint::.*path not found: \/nope\/nowhere/);
  assert.match(r.summary, /could not run: .*path not found: \/nope\/nowhere/);
});
t("a CLI that exits with a code lint does not define is a failure, not a green step", () => {
  const broken = join(dir, "exit127.mjs"); writeFileSync(broken, "process.stderr.write('sh: 1: trooth: not found\\n'); process.exit(127);\n");
  reset(); const r = step("tests/fixtures/infra", { bin: broken });
  assert.equal(r.status, 2);
  assert.match(r.stdout, /::error title=Trooth lint::trooth: the CLI exited with code 127 before producing a report/);
  assert.match(r.summary, /could not run: trooth: the CLI exited with code 127/);
  assert.match(r.output, /^declarations-read=0$/m);
});
t("the CLI is run by path from its own directory, never through npx", () => {
  const commands = runBlock.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  assert.ok(!/\bnpx\b/.test(commands), "no npx command in the run block");
  assert.match(runBlock, /npm install --prefix "\$CLI_DIR" --no-save --no-audit --no-fund --no-package-lock --loglevel=error "trooth@\$V"/);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
