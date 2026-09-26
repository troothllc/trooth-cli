// What `trooth lint` counts and what `trooth check` and `trooth --help` print,
// held as properties, without the network.
//
//   node tests/lint.test.mjs
//
// The lint trees are written to a scratch directory, so the fixture the action
// self-test reads (tests/fixtures/infra, two declaration files) never changes.
// `check` runs against a local HTTP server standing in for the public feed.
// That server answers as the directory worker in two versions: "current" serves the one-record
// route /directory/api/vendors/<domain>, and "legacy" answers that route with a
// plain-text 404 the way a worker without the route does, so the CLI falls back
// to the list.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BIN = "bin/trooth.mjs";
let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.message ?? e)); }
}
const scratch = mkdtempSync(join(tmpdir(), "trooth-lint-"));
let n = 0;
function tree(files) {
  const d = join(scratch, `t${n++}`);
  mkdirSync(d, { recursive: true });
  for (const [name, body] of Object.entries(files)) writeFileSync(join(d, name), typeof body === "string" ? body : JSON.stringify(body, null, 2));
  return d;
}
function lintJson(dir) {
  const r = spawnSync(process.execPath, [BIN, "lint", dir, "--json"], { encoding: "utf8", env: { ...process.env, TROOTH_API: "http://127.0.0.1:9" } });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}
const types = (doc) => doc.facts.resource_types.map((x) => x.type);
// Words the house rules keep out of reader-facing output. "no verdict" is the
// one negation the output uses on purpose, so it is removed before the check.
const RETIRED = /\b(score|scores|tier|tiers|certified|certification|verified|verification|standing|scan|scanned|scanning|passed|passing|judgement)\b/i;
const DASH = /[–—]| - /;

console.log("lint: storage is counted once per store");
await t("the fixture's one bucket is one storage declaration, and its encryption setting credits it", () => {
  const d = lintJson("tests/fixtures/infra");
  assert.equal(d.facts.storage_declarations, 1);
  assert.equal(d.facts.storage_declaring_encryption, 1);
  assert.equal(d.facts.declarations_open_to_any_address, 1);
  assert.ok(types(d).includes("aws_s3_bucket_server_side_encryption_configuration"), "the setting is still listed as a resource type");
});
await t("a bucket policy is not a second bucket, and it does not declare encryption for it", () => {
  const d = lintJson(tree({ "main.tf": `resource "aws_s3_bucket" "a" {\n  bucket = "a"\n}\n\nresource "aws_s3_bucket_policy" "a" {\n  bucket = aws_s3_bucket.a.id\n  policy = "{}"\n}\n` }));
  assert.equal(d.facts.storage_declarations, 1);
  assert.equal(d.facts.storage_declaring_encryption, 0);
});
await t("an encryption setting credits only the store it names, not one whose address it merely starts", () => {
  const d = lintJson(tree({ "main.tf": `resource "aws_s3_bucket" "logs" {\n  bucket = "l"\n}\n\nresource "aws_s3_bucket" "logs2" {\n  bucket = "l2"\n}\n\nresource "aws_s3_bucket_server_side_encryption_configuration" "x" {\n  bucket = aws_s3_bucket.logs2.id\n  rule {\n    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }\n  }\n}\n` }));
  assert.equal(d.facts.storage_declarations, 2);
  assert.equal(d.facts.storage_declaring_encryption, 1);
});
await t("an encryption attribute set to false does not count as declaring encryption", () => {
  const off = lintJson(tree({ "db.tf": `resource "aws_db_instance" "d" {\n  engine            = "postgres"\n  storage_encrypted = false\n}\n` }));
  assert.equal(off.facts.storage_declarations, 1);
  assert.equal(off.facts.storage_declaring_encryption, 0);
  const on = lintJson(tree({ "db.tf": `resource "aws_db_instance" "d" {\n  engine            = "postgres"\n  storage_encrypted = true\n}\n` }));
  assert.equal(on.facts.storage_declaring_encryption, 1);
});

console.log("lint: classification reads a type, never the words around it");
await t("words in a .tf file outside any resource block are not resource types", () => {
  const d = lintJson(tree({ "vars.tf": `variable "log_role" {\n  description = "role used by the log volume"\n}\n` }));
  assert.equal(d.facts.logging_declarations, 0);
  assert.equal(d.facts.identity_declarations, 0);
  assert.equal(d.facts.storage_declarations, 0);
});
await t("Kubernetes: a Deployment that mentions volumes, logs and a service account is none of those", () => {
  const d = lintJson(tree({ "app.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: log-shipper\nspec:\n  template:\n    spec:\n      serviceAccountName: shipper-role\n      volumes:\n        - name: data\n" }));
  assert.equal(d.facts.sources.kubernetes, 1);
  assert.equal(d.facts.storage_declarations, 0);
  assert.equal(d.facts.logging_declarations, 0);
  assert.equal(d.facts.identity_declarations, 0);
});
await t("Kubernetes: each document is classified by its own top-level kind", () => {
  const d = lintJson(tree({ "rbac.yaml": "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: a\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: b\nsubjects:\n  - kind: ServiceAccount\n    name: a\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata:\n  name: c\n" }));
  assert.equal(d.facts.identity_declarations, 2, "ServiceAccount and RoleBinding; the nested subject kind is not a third");
  assert.equal(d.facts.storage_declarations, 1);
});
await t("a Dockerfile declares no resource types, whatever words it contains", () => {
  const d = lintJson(tree({ "Dockerfile": "FROM node:22\nVOLUME /var/log\nRUN useradd role && echo audit\n" }));
  assert.equal(d.facts.sources.container, 1);
  assert.equal(d.facts.storage_declarations + d.facts.logging_declarations + d.facts.identity_declarations, 0);
});

console.log("lint: JSON sources are parsed");
await t(".tf.json: resource types, storage, encryption by reference, identity, region and open ingress are counted", () => {
  const d = lintJson(tree({ "main.tf.json": {
    provider: { aws: { region: "eu-west-1" } },
    resource: {
      aws_s3_bucket: { b: { bucket: "b" } },
      aws_s3_bucket_server_side_encryption_configuration: { b: { bucket: "${aws_s3_bucket.b.id}", rule: [{ apply_server_side_encryption_by_default: { sse_algorithm: "aws:kms" } }] } },
      aws_iam_role: { r: { name: "r" } },
      aws_security_group_rule: { i: { type: "ingress", cidr_blocks: ["0.0.0.0/0"] } },
    },
  } }));
  assert.equal(d.facts.sources.terraform, 1);
  for (const ty of ["aws_s3_bucket", "aws_iam_role", "aws_security_group_rule"]) assert.ok(types(d).includes(ty), ty);
  assert.equal(d.facts.storage_declarations, 1);
  assert.equal(d.facts.storage_declaring_encryption, 1);
  assert.equal(d.facts.identity_declarations, 1);
  assert.deepEqual(d.facts.regions_and_zones_declared, ["eu-west-1"]);
  assert.equal(d.facts.declarations_open_to_any_address, 1);
});
await t("plan JSON: planned managed resources are counted, unset attributes declare nothing, data sources are skipped", () => {
  const d = lintJson(tree({ "plan.json": {
    format_version: "1.2", terraform_version: "1.9.0",
    planned_values: { root_module: {
      resources: [
        { address: "aws_s3_bucket.b", mode: "managed", type: "aws_s3_bucket", name: "b", values: { bucket: "plan-bucket", server_side_encryption_configuration: [] } },
        { address: "aws_s3_bucket_server_side_encryption_configuration.b", mode: "managed", type: "aws_s3_bucket_server_side_encryption_configuration", name: "b", values: { bucket: "plan-bucket", rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: "AES256" }] }] } },
        { address: "data.aws_iam_role.x", mode: "data", type: "aws_iam_role", name: "x", values: {} },
      ],
      child_modules: [{ resources: [
        { address: "module.db.aws_db_instance.d", mode: "managed", type: "aws_db_instance", name: "d", values: { engine: "postgres", storage_encrypted: false } },
      ] }],
    } },
  } }));
  assert.equal(d.facts.sources["terraform-plan"], 1);
  assert.equal(d.facts.storage_declarations, 2);
  assert.equal(d.facts.storage_declaring_encryption, 1);
  assert.equal(d.facts.identity_declarations, 0);
  assert.ok(types(d).includes("aws_db_instance"));
});
await t("the human output states how each source was read, and uses none of the retired words", () => {
  const r = spawnSync(process.execPath, [BIN, "lint", "tests/fixtures/infra"], { encoding: "utf8" });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /How this was read/);
  assert.match(r.stdout, /not a Terraform evaluator/);
  assert.ok(!RETIRED.test(r.stdout), r.stdout.match(RETIRED)?.[0]);
  assert.ok(!DASH.test(r.stdout), "no dash used as punctuation");
  const note = lintJson("tests/fixtures/infra").note;
  assert.ok(!/score/i.test(note), note);
});

console.log("help");
await t("help carries the signing line exactly, and a CI example that writes one JSON document", () => {
  const r = spawnSync(process.execPath, [BIN, "--help"], { encoding: "utf8" });
  assert.ok(r.stdout.includes("Trooth signs what it witnessed. It never signs on a company's behalf."));
  assert.ok(!/Trooth automates/.test(r.stdout));
  assert.match(r.stdout, /trooth lint --json > trooth-lint\.json/);
  assert.ok(!/>>/.test(r.stdout), "no appending redirect");
  assert.ok(!RETIRED.test(r.stdout), r.stdout.match(RETIRED)?.[0]);
});

console.log("check, against a stand-in feed");
const events = [
  { type: "scan_completed", at: "2026-08-01T00:00:00Z", detail: "64 of 65 live probes passed" },
  { type: "standing_published", at: "2026-08-01T00:00:00Z", detail: "point-in-time" },
  { type: "rewitnessed", at: "2026-08-10T00:00:00Z", detail: "a" },
  { type: "rewitnessed", at: "2026-08-20T00:00:00Z", detail: "b" },
  { type: "some_new_event", at: "2026-08-30T00:00:00Z", detail: "c" },
];
const feed = { vendors: [{ domain: "example.com", company_name: "Example", passed_at: "2026-08-30T00:00:00Z", first_published_at: "2026-08-01T00:00:00Z", badge_id: "b-1", authority_key_id: "k-1", receipt_signature: "sig", probes: { passed: 64, total: 65 }, attested: { passed: 27, total: 35 }, events }] };
let mode = "current";
const requests = [];
const server = createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  requests.push(path);
  const one = path.match(/^\/directory\/api\/vendors\/([^/]+)$/);
  if (one && mode === "current") {
    const d = decodeURIComponent(one[1]);
    const v = feed.vendors.find((x) => x.domain === d);
    res.statusCode = v ? 200 : 404;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(v ?? { domain: d, listed: false, error: "No vendor with this domain in the directory feed." }));
    return;
  }
  if (path === "/directory/api/vendors") { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(feed)); return; }
  res.statusCode = 404;
  res.setHeader("content-type", "text/plain");
  res.end("Not found");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const api = `http://127.0.0.1:${server.address().port}`;
const check = (args, base = api) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, "check", ...args], { env: { ...process.env, TROOTH_API: base } });
  let stdout = "", stderr = "";
  p.stdout.on("data", (b) => (stdout += b)); p.stderr.on("data", (b) => (stderr += b));
  p.on("close", (status) => resolve({ status, stdout, stderr }));
});

await t("a listed record: listing state, two counts in the website's form, no ratio", async () => {
  const r = await check(["example.com"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^Listing state: listed and witnessed/m);
  assert.match(r.stdout, /Live probes: 65 read; 64 as expected/);
  assert.match(r.stdout, /Self-attestations: 35 asked; 27 attested/);
  assert.ok(!/\b\d+\/\d+\b/.test(r.stdout), "no N/M bar");
  assert.ok(!RETIRED.test(r.stdout), r.stdout.match(RETIRED)?.[0]);
  assert.ok(!DASH.test(r.stdout), "no dash used as punctuation");
});
await t("the ledger section prints the three most recent events, newest first", async () => {
  const r = await check(["example.com"]);
  const section = r.stdout.split(/Latest ledger events, newest first\n/)[1] || "";
  const dates = [...section.matchAll(/•\s+(\d{4}-\d{2}-\d{2})/g)].map((m) => m[1]);
  assert.deepEqual(dates, ["2026-08-30", "2026-08-20", "2026-08-10"]);
  assert.match(section, /some new event/, "an unknown type is printed as received");
});
await t("--json keeps the feed's field names and the whole ledger, in the feed's order", async () => {
  const r = await check(["example.com", "--json"]);
  const doc = JSON.parse(r.stdout);
  assert.deepEqual(doc.probes, { passed: 64, total: 65 });
  assert.deepEqual(doc.attested, { passed: 27, total: 35 });
  assert.deepEqual(doc.events.map((e) => e.type), events.map((e) => e.type));
});
await t("a domain the feed does not carry: exit 1, and the text claims nothing about the company", async () => {
  const r = await check(["nobody.example"]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /not listed in the Trooth Network's public feed/);
  assert.match(r.stdout, /says nothing about the/);
  assert.ok(!RETIRED.test(r.stdout), r.stdout.match(RETIRED)?.[0]);
  assert.ok(!DASH.test(r.stdout), "no dash used as punctuation");
});

console.log("check, one-record route and the fallback to the list");
async function inMode(m, args) {
  mode = m;
  requests.length = 0;
  const r = await check(args);
  return { ...r, requests: [...requests] };
}
await t("a listed record is read from /directory/api/vendors/<domain>, without the list", async () => {
  const r = await inMode("current", ["example.com"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.requests, ["/directory/api/vendors/example.com"]);
});
await t("a JSON 404 with listed:false is not listed: exit 1, the same text, no list request", async () => {
  const cur = await inMode("current", ["nobody.example"]);
  const old = await inMode("legacy", ["nobody.example"]);
  assert.equal(cur.status, 1);
  assert.deepEqual(cur.requests, ["/directory/api/vendors/nobody.example"]);
  assert.equal(cur.stdout, old.stdout);
  assert.equal(cur.status, old.status);
});
await t("a worker without the route (plain-text 404) falls back to the list", async () => {
  const r = await inMode("legacy", ["example.com"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.requests, ["/directory/api/vendors/example.com", "/directory/api/vendors"]);
});
await t("the printed output and --json are identical through the route and through the fallback", async () => {
  for (const args of [["example.com"], ["example.com", "--json"], ["nobody.example", "--json"], ["https://www.Example.com/x"]]) {
    const cur = await inMode("current", args);
    const old = await inMode("legacy", args);
    assert.equal(cur.status, old.status, args.join(" "));
    assert.equal(cur.stdout, old.stdout, args.join(" "));
  }
});
await t("a 200 carrying some other domain's record is an upstream error, exit 3", async () => {
  const saved = feed.vendors[0].domain;
  const srv = createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ ...feed.vendors[0], domain: "other.example" })); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const r = await check(["example.com"], `http://127.0.0.1:${srv.address().port}`);
  srv.close();
  assert.equal(feed.vendors[0].domain, saved);
  assert.equal(r.status, 3);
});
server.close();

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
