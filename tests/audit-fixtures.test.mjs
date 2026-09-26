// The 22 cases from the 2026-09-26 remediation guide, held as a release gate.
//
//   node tests/audit-fixtures.test.mjs
//
// Each case is the guide's input, run through the real CLI, with the result the
// guide requires (not the result 0.4.4 produced). Cases that 0.4.4 already got
// right are kept so a later parser change cannot silently undo them. Every
// credential is a dummy string. Lookup cases run against a local server that
// stands in for api.trooth.co; nothing here touches the network.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BIN = "bin/trooth.mjs";
let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.message ?? e)); }
}
const scratch = mkdtempSync(join(tmpdir(), "trooth-audit-"));
let n = 0;
function tree(files) {
  const d = join(scratch, `c${n++}`);
  mkdirSync(d, { recursive: true });
  for (const [name, body] of Object.entries(files)) writeFileSync(join(d, name), body);
  return d;
}
function lint(dir, extra = []) {
  const r = spawnSync(process.execPath, [BIN, "lint", dir, "--json", ...extra], { encoding: "utf8", env: { ...process.env, TROOTH_API: "http://127.0.0.1:9" } });
  let doc = null; try { doc = JSON.parse(r.stdout); } catch {}
  return { status: r.status, doc, stderr: r.stderr };
}
const facts = (r) => r.doc.facts;

console.log("encryption declarations (F20)");
await t("1. multiline false: 0 credited, exit 0", () => {
  const r = lint(tree({ "a.tf": 'resource "aws_ebs_volume" "one" {\n  size      = 8\n  encrypted = false\n}\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_declaring_encryption_off, 1);
});
await t("2. explicit true: 1 credited", () => {
  const r = lint(tree({ "a.tf": 'resource "aws_ebs_volume" "one" {\n  encrypted = true\n}\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 1);
});
await t("3. inline false: 0 credited", () => {
  const r = lint(tree({ "false.tf": 'resource "aws_ebs_volume" "one" { encrypted = false }\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_declaring_encryption_off, 1);
});
await t("6. no encryption setting: 0 credited, reported as not declared", () => {
  const r = lint(tree({ "a.tf": 'resource "aws_ebs_volume" "one" {\n  size = 8\n}\n' }));
  assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_encryption_not_declared, 1);
});
await t("7. YAML encryption false: 0 credited", () => {
  const r = lint(tree({ "pv.yaml": 'apiVersion: v1\nkind: PersistentVolume\nmetadata:\n  name: a\nspec:\n  csi:\n    volumeAttributes:\n      encrypted: false\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_declaring_encryption_off, 1);
});
await t("10. Terraform JSON false string: not promoted", () => {
  const r = lint(tree({ "a.tf.json": '{"resource":{"aws_ebs_volume":{"one":{"encrypted":"false"}}}}' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0);
});
await t("14. commented encryption assignment: 0 credited", () => {
  const r = lint(tree({ "comment-setting.tf": 'resource "aws_ebs_volume" "one" {\n# encrypted = true\nsize = 8\n}\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_encryption_not_declared, 1);
});
await t("15. unresolved encryption variable: unknown, not true", () => {
  const r = lint(tree({ "variable.tf": 'resource "aws_ebs_volume" "one" {\nencrypted = var.encrypt_enabled\n}\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_encryption_unresolved, 1);
});
await t("16. false with a trailing comment: 0 credited", () => {
  const r = lint(tree({ "comment-false.tf": 'resource "aws_ebs_volume" "one" {\nencrypted = false # explicitly disabled\n}\n' }));
  assert.equal(r.status, 0); assert.equal(facts(r).storage_declaring_encryption, 0); assert.equal(facts(r).storage_declaring_encryption_off, 1);
});

console.log("parsing (F22)");
await t("4. comment-only resource: nothing counts", () => {
  const r = lint(tree({ "a.tf": '# resource "aws_s3_bucket" "x" {\n#   region = "eu-west-1"\n#   password = "dummy-password-one"\n# }\nlocals {}\n' }));
  assert.equal(r.status, 0);
  assert.equal(facts(r).storage_declarations, 0);
  assert.deepEqual(facts(r).resource_types, []);
  assert.deepEqual(facts(r).regions_and_zones_declared, []);
  assert.equal(facts(r).inline_credential_literals, 0);
});
await t("5. two indented resources: two types and two stores", () => {
  const r = lint(tree({ "a.tf": '  resource "aws_s3_bucket" "a" {\n    bucket = "a"\n  }\n\n    resource "aws_ebs_volume" "b" {\n      size = 8\n    }\n' }));
  assert.equal(r.status, 0);
  assert.equal(facts(r).resource_types.length, 2);
  assert.equal(facts(r).storage_declarations, 2);
});
await t("8. malformed Terraform JSON: invalid, exit 4, not a successful read", () => {
  const r = lint(tree({ "bad.tf.json": '{"resource":{"aws_ebs_volume": this is invalid}' }));
  assert.equal(r.status, 4);
  assert.equal(r.doc.coverage.completeness, "incomplete");
  assert.equal(r.doc.coverage.files_invalid, 1);
  assert.equal(r.doc.coverage.files_read, 0);
});
await t("9. malformed YAML: invalid, no storage counted", () => {
  const r = lint(tree({ "bad.yaml": "apiVersion: v1\nkind: PersistentVolume\nspec: [this is not closed\n" }));
  assert.equal(r.status, 4);
  assert.equal(r.doc.coverage.files_invalid, 1);
  assert.equal(r.doc.facts?.storage_declarations ?? 0, 0);
});
await t("11. two JSON passwords on separate lines: 2", () => {
  const r = lint(tree({ "p.tf.json": '{\n "resource": {\n  "aws_db_instance": {\n   "one": {"password": "dummy-password-one"},\n   "two": {"password": "dummy-password-two"}\n  }\n }\n}\n' }));
  assert.equal(facts(r).inline_credential_literals, 2);
});
await t("12. two JSON passwords on one line: 2, independent of layout", () => {
  const r = lint(tree({ "password.tf.json": '{"resource":{"aws_db_instance":{"one":{"password":"dummy-password-one"},"two":{"password":"dummy-password-two"}}}}' }));
  assert.equal(facts(r).inline_credential_literals, 2);
});
await t("13. plan with two resources: storage 2, encryption 1, regions 2, credentials 2", () => {
  const plan = { format_version: "1.2", terraform_version: "1.9.0", planned_values: { root_module: { resources: [
    { address: "aws_db_instance.a", mode: "managed", type: "aws_db_instance", name: "a", values: { availability_zone: "us-east-1a", storage_encrypted: true, password: "dummy-password-one" } },
    { address: "aws_db_instance.b", mode: "managed", type: "aws_db_instance", name: "b", values: { availability_zone: "us-west-2b", storage_encrypted: false, password: "dummy-password-two" } },
  ] } } };
  const r = lint(tree({ "plan.json": JSON.stringify(plan) }));
  assert.equal(r.status, 0);
  assert.equal(facts(r).storage_declarations, 2);
  assert.equal(facts(r).storage_declaring_encryption, 1);
  assert.equal(facts(r).regions_and_zones_declared.length, 2);
  assert.equal(facts(r).inline_credential_literals, 2);
});

console.log("incomplete reads (F23)");
await t("17. a file above 4 MiB: explicit skipped state, exit 4, not 'nothing to read'", () => {
  const r = lint(tree({ "big.tf.json": " ".repeat(4 * 1024 * 1024 + 1) }));
  assert.equal(r.status, 4);
  assert.equal(r.doc.coverage.files_skipped, 1);
  assert.match(r.doc.coverage_details.skipped.entries[0].reason, /larger than/);
});
await t("--allow-incomplete reports the same coverage and exits 0 when something was read", () => {
  const r = lint(tree({ "ok.tf": 'resource "aws_s3_bucket" "a" {}\n', "bad.tf": 'resource "aws_s3_bucket" "b" {\n' }), ["--allow-incomplete"]);
  assert.equal(r.status, 0);
  assert.equal(r.doc.coverage.completeness, "incomplete");
  assert.equal(r.doc.facts.completeness, "incomplete");
  assert.equal(r.doc.coverage.files_invalid, 1);
});
await t("an unreadable file is reported, not silently read as success", () => {
  if (process.getuid && process.getuid() === 0) return; // root reads everything
  const d = tree({ "ok.tf": 'resource "aws_s3_bucket" "a" {}\n', "locked.tf": 'resource "aws_s3_bucket" "b" {}\n' });
  chmodSync(join(d, "locked.tf"), 0o000);
  const r = lint(d);
  assert.equal(r.status, 4);
  assert.equal(r.doc.coverage.files_unreadable, 1);
});
await t("the walk limit is reported as truncation", () => {
  const d = tree({ "a.tf": 'resource "aws_s3_bucket" "a" {}\n', "b.tf": 'resource "aws_s3_bucket" "b" {}\n', "c.tf": 'resource "aws_s3_bucket" "c" {}\n' });
  const r = spawnSync(process.execPath, [BIN, "lint", d, "--json"], { encoding: "utf8", env: { ...process.env, TROOTH_LINT_MAX_FILES: "2" } });
  const doc = JSON.parse(r.stdout);
  assert.equal(r.status, 4);
  assert.equal(doc.coverage.traversal_truncated, true);
  assert.equal(doc.facts.declarations_read, 2);
});
await t("a templated manifest is excluded by a stated rule and does not make the read incomplete", () => {
  const r = lint(tree({ "t.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n", "a.tf": 'resource "aws_s3_bucket" "a" {}\n' }));
  assert.equal(r.status, 0);
  assert.equal(r.doc.coverage.files_excluded, 1);
});

console.log("the digest (F24)");
await t("the digest is named an aggregate and says what it does not identify", () => {
  const r = lint("tests/fixtures/infra");
  assert.equal(r.doc.facts_digest, r.doc.digest);
  assert.match(r.doc.digest_scope, /aggregate/);
  assert.match(r.doc.digest_scope, /does not identify file contents, a repository, a commit or a deployment/);
});

console.log("lookup (F25, F26)");
let handler = () => {};
const server = createServer((req, res) => handler(req, res));
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const api = `http://127.0.0.1:${server.address().port}`;
const json = (res, status, body) => { res.statusCode = status; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(body)); };
const check = (args, env = {}) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, "check", ...args], { env: { ...process.env, TROOTH_API: api, ...env } });
  let stdout = "", stderr = "";
  p.stdout.on("data", (b) => (stdout += b)); p.stderr.on("data", (b) => (stderr += b));
  p.on("close", (status) => resolve({ status, stdout, stderr }));
});
await t("18. a matching company with no witness evidence: listed, evidence unknown, exit 5", async () => {
  handler = (req, res) => json(res, 200, { domain: "trooth.co", company_name: "Trooth" });
  const r = await check(["trooth.co", "--json"]);
  assert.equal(r.status, 5);
  const d = JSON.parse(r.stdout);
  assert.equal(d.listed, true); assert.equal(d.state, "listed_evidence_unknown"); assert.equal(d.witnessed_at, null);
  const h = await check(["trooth.co"]);
  assert.ok(!/witnessed a reading/.test(h.stdout), h.stdout);
});
await t("19. an explicit not-witnessed company keeps that state", async () => {
  handler = (req, res) => json(res, 200, { domain: "trooth.co", company_name: "Trooth", standing: "not_witnessed", probes: { passed: 0, total: 12 }, passed_at: "2026-09-26T05:00:25.618Z" });
  const r = await check(["trooth.co", "--json"]);
  assert.equal(r.status, 5);
  assert.equal(JSON.parse(r.stdout).state, "listed_not_witnessed");
});
await t("a witnessed record: exit 0, state listed_witnessed, signature not claimed as checked", async () => {
  handler = (req, res) => json(res, 200, { domain: "trooth.co", company_name: "Trooth", passed_at: "2026-09-26T05:00:25.618Z", probes: { passed: 63, total: 65 } });
  const r = await check(["trooth.co", "--json"]);
  assert.equal(r.status, 0);
  const d = JSON.parse(r.stdout);
  assert.equal(d.state, "listed_witnessed"); assert.equal(d.signature_checked, false);
  const h = await check(["trooth.co"]);
  assert.match(h.stdout, /did not check the record's signature/);
});
await t("20. a wrong-shape single-record 200: exit 3", async () => {
  handler = (req, res) => json(res, 200, { error: "upstream temporarily unavailable" });
  assert.equal((await check(["trooth.co"])).status, 3);
});
await t("21. a plain 404 then a wrong-shape 200: a contract error, exit 3, never unlisted", async () => {
  let k = 0;
  handler = (req, res) => { if (k++ === 0) { res.statusCode = 404; res.setHeader("content-type", "text/plain"); res.end("Not found"); } else json(res, 200, { error: "upstream temporarily unavailable" }); };
  const r = await check(["trooth.co", "--json"]);
  assert.equal(r.status, 3);
  assert.equal(JSON.parse(r.stdout).state, "service_error");
  assert.equal(k, 1, "no second request: the list fallback is gone");
});
await t("the documented not-listed answer is the only 'not listed'", async () => {
  handler = (req, res) => json(res, 404, { domain: "nobody.example", listed: false, error: "No vendor with this domain in the directory feed." });
  const r = await check(["nobody.example", "--json"]);
  assert.equal(r.status, 1); assert.equal(JSON.parse(r.stdout).state, "not_listed");
});
await t("22. a full URL with the default HTTPS port normalizes to the domain", async () => {
  const seen = [];
  handler = (req, res) => { seen.push(req.url); json(res, 200, { domain: "trooth.co", company_name: "Trooth", passed_at: "2026-09-26T05:00:25.618Z", probes: { passed: 63, total: 65 } }); };
  const r = await check(["https://trooth.co:443/path"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(seen, ["/directory/api/vendors/trooth.co"]);
});
await t("casing, www and an internationalized name normalize; ambiguous input is a usage error", async () => {
  const seen = [];
  handler = (req, res) => { seen.push(req.url); json(res, 404, { listed: false }); };
  await check(["WWW.Trooth.CO."]);
  await check(["bücher.example"]);
  assert.deepEqual(seen, ["/directory/api/vendors/trooth.co", "/directory/api/vendors/xn--bcher-kva.example"]);
  for (const bad of ["https://user:pw@trooth.co", "trooth.co:8443", "10.0.0.1", "localhost", "ftp://trooth.co"]) {
    assert.equal((await check([bad])).status, 2, bad);
  }
});
await t("a body over the size limit and a slow answer are service errors", async () => {
  handler = (req, res) => { res.setHeader("content-type", "application/json"); res.end('{"domain":"trooth.co","pad":"' + "x".repeat(1024 * 1024 + 10) + '"}'); };
  assert.equal((await check(["trooth.co"])).status, 3);
  handler = () => {};
  const r = await check(["trooth.co"], { TROOTH_TIMEOUT_MS: "1000" });
  assert.equal(r.status, 3); assert.match(r.stderr, /did not answer within/);
});
await t("a non-JSON 200 is a service error", async () => {
  handler = (req, res) => { res.setHeader("content-type", "text/html"); res.end("<html>"); };
  assert.equal((await check(["trooth.co"])).status, 3);
});
server.close();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
