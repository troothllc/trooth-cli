// The GitHub Action's two scripts, and the shape of action.yml, without GitHub.
//
//   node tests/action.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
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
  assert.ok(!/\b(pass|fail|score|grade|verdict:)\b/i.test(r.stdout.replace(/no verdict|No score/g, "")), "no verdict word");
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
  assert.match(yml, /default: "0\.4\.2"/);
  assert.match(yml, /TROOTH_API: "http:\/\/127\.0\.0\.1:9"/);
});
t("it asks for no token and no write permission", () => {
  assert.ok(!/GITHUB_TOKEN|github-token|pull-requests: write/.test(yml));
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
