// The eighteen local fixtures from the fresh audit of 2026-09-28 (T14 to T19),
// held as a release gate, with the regression cases the audit asked for beside
// them.
//
//   node tests/audit-0928.test.mjs
//
// Every input is synthetic and every credential is a dummy string. Each case
// asserts the behaviour the audit requires, not what 0.5.0 produced. Five of
// the eighteen were already right in 0.5.0 and are kept so a later change
// cannot undo them.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

const BIN = "bin/trooth.mjs";
let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.message ?? e)); }
}
const scratch = mkdtempSync(join(tmpdir(), "trooth-0928-"));
let n = 0;
function tree(files) {
  const d = join(scratch, `c${n++}`);
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(dirname(join(d, name)), { recursive: true });
    writeFileSync(join(d, name), body);
  }
  return d;
}
function lint(dir, extra = []) {
  const r = spawnSync(process.execPath, [BIN, "lint", dir, "--json", ...extra], { encoding: "utf8", env: { ...process.env, TROOTH_API: "http://127.0.0.1:9" } });
  let doc = null; try { doc = JSON.parse(r.stdout); } catch {}
  return { status: r.status, doc, stdout: r.stdout, stderr: r.stderr };
}
const F = (r) => { assert.ok(r.doc, `no JSON report (exit ${r.status}): ${r.stderr.slice(0, 300)}`); return r.doc.facts; };
const C = (r) => r.doc.coverage;
const SECRET = "dummy-only-value";
const noLeak = (r, ...values) => { for (const v of values) { assert.ok(!r.stdout.includes(v), `stdout carries ${v}`); assert.ok(!r.stderr.includes(v), `stderr carries ${v}`); } };
/** The storage counts partition the storage declarations. */
const partition = (f) => assert.equal(
  f.storage_declaring_encryption + f.storage_declaring_encryption_off + f.storage_encryption_not_declared + f.storage_encryption_unresolved + f.storage_encryption_unsupported,
  f.storage_declarations, "storage-state counts do not partition the storage declarations");

console.log("the audit's eighteen fixtures");
t("explicit false: off 1, declared 0, exit 0", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "test" { encrypted = false }\n' }));
  assert.equal(r.status, 0); assert.equal(F(r).storage_declaring_encryption_off, 1); assert.equal(F(r).storage_declaring_encryption, 0); partition(F(r));
});
t("comment only: no storage, exit 0 is not required but nothing counts", () => {
  const r = lint(tree({ "main.tf": '# resource "aws_ebs_volume" "test" { encrypted = true }\n' }));
  assert.equal(F(r).storage_declarations, 0); assert.equal(F(r).resource_types.length, 0);
});
t("unresolved: storage_encryption_unresolved 1", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "test" { encrypted = var.enabled }\n' }));
  assert.equal(r.status, 0); assert.equal(F(r).storage_encryption_unresolved, 1); partition(F(r));
});
t("malformed .tf.json: files_invalid 1, incomplete, exit 4, a JSON report", () => {
  const r = lint(tree({ "main.tf.json": '{"resource":' }));
  assert.equal(r.status, 4); assert.equal(C(r).files_invalid, 1); assert.equal(C(r).completeness, "incomplete");
});
t("minified credentials: two literals", () => {
  const r = lint(tree({ "main.tf.json": '{"resource":{"aws_db_instance":{"one":{"password":"dummy-only-one"},"two":{"password":"dummy-only-two"}}}}' }));
  assert.equal(r.status, 0); assert.equal(F(r).inline_credential_literals, 2); noLeak(r, "dummy-only-one", "dummy-only-two");
});
t("T14 tag encryption: a tag does not declare encryption", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "test" { tags = { encrypted = true } }\n' }));
  assert.equal(F(r).storage_declaring_encryption, 0); assert.equal(F(r).storage_encryption_not_declared, 1); partition(F(r));
});
t("T14 tag public ingress: a tag is not a network rule", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_s3_bucket" "test" { tags = { note = "0.0.0.0/0" } }\n' }));
  assert.equal(F(r).declarations_open_to_any_address, 0);
});
t("T17 token endpoint URL: not a credential", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_instance" "test" { token_endpoint = "https://example.invalid/oauth/token" }\n' }));
  assert.equal(F(r).inline_credential_literals, 0);
});
t("Kubernetes Secret stringData: one literal, not printed", () => {
  const r = lint(tree({ "secret.yaml": `apiVersion: v1\nkind: Secret\nmetadata:\n  name: example\nstringData:\n  password: ${SECRET}\n` }));
  assert.equal(r.status, 0); assert.equal(F(r).inline_credential_literals, 1); noLeak(r, SECRET);
});
t("T17 Kubernetes env name/value: one literal, not printed", () => {
  const r = lint(tree({ "deploy.yaml": `apiVersion: v1\nkind: Pod\nmetadata:\n  name: example\nspec:\n  containers:\n    - name: example\n      image: example.invalid/test\n      env:\n        - name: API_TOKEN\n          value: ${SECRET}\n` }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, SECRET);
});
t("T16 flow-style YAML is recognized", () => {
  const r = lint(tree({ "store.yaml": "{apiVersion: v1, kind: PersistentVolume, metadata: {name: disk}}\n" }));
  assert.equal(r.status, 0); assert.equal(C(r).files_not_applicable, 0); assert.equal(F(r).storage_declarations, 1);
});
t("T16 quoted apiVersion and kind keys are recognized", () => {
  const r = lint(tree({ "store.yaml": '"apiVersion": v1\n"kind": PersistentVolume\nmetadata:\n  name: disk\n' }));
  assert.equal(r.status, 0); assert.equal(C(r).files_not_applicable, 0); assert.equal(F(r).storage_declarations, 1);
});
t("T16 a List's member is counted, the List is not a resource", () => {
  const r = lint(tree({ "list.yaml": "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: PersistentVolume\n    metadata:\n      name: disk\n" }));
  assert.equal(r.status, 0); assert.equal(F(r).storage_declarations, 1);
  assert.ok(!F(r).resource_types.some((x) => x.type === "List"), "List counted as a resource type");
  assert.ok(F(r).resource_types.some((x) => x.type === "PersistentVolume" && x.count === 1));
});
t("T19 bounded alias expansion: an invalid file in a JSON report, exit 4", () => {
  const r = lint(tree({ "sample.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: example}\ndata:\n  a: &a [x,x,x,x,x,x,x,x,x,x]\n  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n" }));
  assert.equal(r.status, 4); assert.equal(C(r).files_invalid, 1); assert.equal(C(r).completeness, "incomplete");
  assert.match(r.doc.coverage_details.invalid.entries[0].reason, /alias/i);
});
t("T18 an earlier Dockerfile literal is not hidden by a later reference", () => {
  const r = lint(tree({ "Dockerfile": "FROM example.invalid/base\nENV API_TOKEN=dummy-first-value\nENV API_TOKEN=$REPLACEMENT\n" }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, "dummy-first-value");
});
t("T19 a .tf.json with an array root is invalid", () => {
  const r = lint(tree({ "main.tf.json": '[{"resource":{"aws_ebs_volume":{"disk":{"encrypted":true}}}}]' }));
  assert.equal(r.status, 4); assert.equal(C(r).files_invalid, 1); assert.equal(F(r).storage_declarations, 0);
});
t("T14 an empty encryption block does not declare encryption", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "test" {\n  encryption {}\n}\n' }));
  assert.equal(F(r).storage_declaring_encryption, 0); partition(F(r));
});
t("T15 independent modules: only folder a's bucket is linked", () => {
  const r = lint(tree({
    "a/main.tf": 'resource "aws_s3_bucket" "shared" {}\nresource "aws_s3_bucket_server_side_encryption_configuration" "cfg" {\n  bucket = aws_s3_bucket.shared.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n',
    "b/main.tf": 'resource "aws_s3_bucket" "shared" {}\n',
  }));
  assert.equal(F(r).storage_declarations, 2); assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(F(r).storage_encryption_not_declared, 1); partition(F(r));
});

console.log("T14 regression: metadata never changes a configuration count");
t("labels, annotations and descriptions do not declare encryption or exposure", () => {
  const a = lint(tree({ "main.tf": 'resource "google_storage_bucket" "b" {\n  labels = { encrypted = "true", cidr = "0.0.0.0/0" }\n  description = "encrypted = true, 0.0.0.0/0"\n}\n' }));
  assert.equal(F(a).storage_declaring_encryption, 0); assert.equal(F(a).declarations_open_to_any_address, 0);
  const k = lint(tree({ "pv.yaml": "apiVersion: v1\nkind: PersistentVolume\nmetadata:\n  name: d\n  annotations:\n    encrypted: \"true\"\n    note: 0.0.0.0/0\n  labels:\n    encrypted: \"true\"\n" }));
  assert.equal(F(k).storage_declaring_encryption, 0); assert.equal(F(k).declarations_open_to_any_address, 0);
});
t("a real top-level switch and a real nested block still count", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "a" { encrypted = true }\nresource "aws_s3_bucket" "b" {\n  server_side_encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "aws:kms"\n      }\n    }\n  }\n}\n' }));
  assert.equal(F(r).storage_declaring_encryption, 2); partition(F(r));
});
t("a real ingress rule to the whole internet still counts", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  cidr_blocks = ["0.0.0.0/0"]\n}\nresource "google_compute_firewall" "f" {\n  source_ranges = ["::/0"]\n}\n' }));
  assert.equal(F(r).declarations_open_to_any_address, 2);
});
t("the same resource with and without tags gives the same facts", () => {
  const a = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "v" { encrypted = false }\n' }));
  const b = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n  tags = { encrypted = true, open = "0.0.0.0/0", password = "dummy-in-a-tag" }\n}\n' }));
  for (const k of ["storage_declaring_encryption", "storage_declaring_encryption_off", "declarations_open_to_any_address", "inline_credential_literals"]) assert.equal(F(b)[k], F(a)[k], k);
});
t("an encryption block that holds only unknown keys is unsupported, not declared", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "v" {\n  encryption {\n    colour = "blue"\n  }\n}\n' }));
  assert.equal(F(r).storage_declaring_encryption, 0); assert.equal(F(r).storage_encryption_unsupported, 1); partition(F(r));
});

console.log("T15 regression: module identity");
t("same-name nested modules and separate environments are resolved within their own folder", () => {
  const r = lint(tree({
    "envs/prod/main.tf": 'resource "aws_s3_bucket" "logs" {}\nresource "aws_s3_bucket_server_side_encryption_configuration" "c" {\n  bucket = aws_s3_bucket.logs.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n',
    "envs/staging/main.tf": 'resource "aws_s3_bucket" "logs" {}\n',
    "modules/x/main.tf": 'resource "aws_s3_bucket" "logs" {}\n',
  }));
  assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(F(r).storage_encryption_not_declared, 2);
});
t("a reference split across two files in one folder still links", () => {
  const r = lint(tree({
    "m/bucket.tf": 'resource "aws_s3_bucket" "shared" {}\n',
    "m/sse.tf": 'resource "aws_s3_bucket_server_side_encryption_configuration" "c" {\n  bucket = aws_s3_bucket.shared.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n',
  }));
  assert.equal(F(r).storage_declaring_encryption, 1);
});
t("count and for_each addresses link to their store", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_s3_bucket" "b" { count = 2 }\nresource "aws_s3_bucket_server_side_encryption_configuration" "c" {\n  count  = 2\n  bucket = aws_s3_bucket.b[count.index].id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n' }));
  assert.equal(F(r).storage_declaring_encryption, 1);
});
t("a reference to a module output stays unlinked", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_s3_bucket" "b" {}\nresource "aws_s3_bucket_server_side_encryption_configuration" "c" {\n  bucket = module.storage.bucket_id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n' }));
  assert.equal(F(r).storage_declaring_encryption, 0); assert.equal(F(r).storage_encryption_not_declared, 1);
});
t("file order does not change the result", () => {
  const files = {
    "z/a.tf": 'resource "aws_s3_bucket" "s" {}\n',
    "z/b.tf": 'resource "aws_s3_bucket_server_side_encryption_configuration" "c" {\n  bucket = aws_s3_bucket.s.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}\n',
    "y/a.tf": 'resource "aws_s3_bucket" "s" {}\n',
  };
  const flipped = { "z/b.tf": files["z/a.tf"], "z/a.tf": files["z/b.tf"], "y/a.tf": files["y/a.tf"] };
  assert.equal(lint(tree(files)).doc.facts_digest, lint(tree(flipped)).doc.facts_digest);
  assert.equal(F(lint(tree(files))).storage_declaring_encryption, 1);
});

console.log("T16 regression: parsed YAML");
t("block, flow, quoted and multi-document forms give the same facts", () => {
  const block = lint(tree({ "a.yaml": "apiVersion: v1\nkind: PersistentVolume\nmetadata:\n  name: d\n" }));
  const flow = lint(tree({ "a.yaml": "{apiVersion: v1, kind: PersistentVolume, metadata: {name: d}}\n" }));
  const quoted = lint(tree({ "a.yaml": "'apiVersion': v1\n'kind': PersistentVolume\nmetadata:\n  name: d\n" }));
  const multi = lint(tree({ "a.yaml": "---\napiVersion: v1\nkind: PersistentVolume\nmetadata:\n  name: d\n---\n" }));
  for (const r of [flow, quoted, multi]) assert.deepEqual(F(r).resource_types, F(block).resource_types);
});
t("an object alone and inside a List give the same storage count", () => {
  const alone = lint(tree({ "a.yaml": "apiVersion: v1\nkind: PersistentVolume\nmetadata:\n  name: d\n" }));
  const listed = lint(tree({ "a.yaml": "apiVersion: v1\nkind: PersistentVolumeList\nitems:\n  - apiVersion: v1\n    kind: PersistentVolume\n    metadata:\n      name: d\n" }));
  assert.equal(F(listed).storage_declarations, F(alone).storage_declarations);
});
t("a List member with no apiVersion and kind is reported, and the read is incomplete", () => {
  const r = lint(tree({ "a.yaml": "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: PersistentVolume\n    metadata:\n      name: d\n  - just: a mapping\n" }));
  assert.equal(r.status, 4); assert.equal(F(r).storage_declarations, 1); assert.equal(C(r).list_members_not_read, 1);
});
t("a YAML file that is not a manifest stays not applicable", () => {
  const r = lint(tree({ "ci.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-24.04\n", "main.tf": 'resource "aws_ebs_volume" "v" {}\n' }));
  assert.equal(r.status, 0); assert.equal(C(r).files_not_applicable, 1);
});

console.log("T17 regression: credential context");
t("valueFrom, secretKeyRef, interpolation and empty values are not literals", () => {
  const r = lint(tree({ "d.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: example.invalid/x\n      env:\n        - name: API_TOKEN\n          valueFrom:\n            secretKeyRef:\n              name: s\n              key: token\n        - name: DB_PASSWORD\n          value: $(FROM_ELSEWHERE)\n        - name: SECRET_KEY\n          value: \"\"\n",
    "main.tf": 'resource "aws_db_instance" "d" {\n  password = var.db_password\n  master_password = "${var.p}"\n  secret_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:x"\n  password_length = "32"\n}\n' }));
  assert.equal(F(r).inline_credential_literals, 0);
});
t("a short literal password is still a literal", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_db_instance" "d" { password = "pw1" }\n' }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, "pw1\"");
});
t("URL-valued token settings are not literals; a URL with a password in it is", () => {
  const r = lint(tree({ "main.tf": 'resource "x_client" "c" {\n  token_url = "https://example.invalid/token"\n  auth_token = "https://example.invalid/t"\n  database_password = "postgres://u:dummy-in-url@example.invalid/db"\n}\n' }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, "dummy-in-url");
});
t("every value in a Secret's data is a literal, whatever its key", () => {
  const r = lint(tree({ "s.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  conn: ZHVtbXk=\n  other: ZHVtbXky\n" }));
  assert.equal(F(r).inline_credential_literals, 2);
});

console.log("T18 regression: Dockerfile occurrences");
t("reference then literal, duplicate literals, and multiline assignments are each counted", () => {
  const a = lint(tree({ "Dockerfile": "FROM x\nENV API_TOKEN=$A\nENV API_TOKEN=dummy-later-value\n" }));
  assert.equal(F(a).inline_credential_literals, 1);
  const b = lint(tree({ "Dockerfile": "FROM x\nENV API_TOKEN=dummy-one-value\nENV API_TOKEN=dummy-two-value\n" }));
  assert.equal(F(b).inline_credential_literals, 2);
  const c = lint(tree({ "Dockerfile": "FROM x\nENV A=1 \\\n    DB_PASSWORD=dummy-multi-line \\\n    B=2\nARG SECRET_KEY=dummy-arg-value\n" }));
  assert.equal(F(c).inline_credential_literals, 2); noLeak(c, "dummy-multi-line", "dummy-arg-value");
});

console.log("T19 regression: bounded failures inside the file boundary");
t("an invalid file does not stop the rest of the read", () => {
  const r = lint(tree({ "bad.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: e}\ndata:\n  a: &a [x,x,x,x,x,x,x,x,x,x]\n  b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n  c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n", "main.tf": 'resource "aws_ebs_volume" "v" { encrypted = true }\n' }));
  assert.equal(r.status, 4); assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(C(r).files_invalid, 1); assert.equal(F(r).files_not_read, 1);
});
t("--allow-incomplete returns 0 with the same report", () => {
  const r = lint(tree({ "main.tf.json": "[1]", "ok.tf": 'resource "aws_ebs_volume" "v" {}\n' }), ["--allow-incomplete"]);
  assert.equal(r.status, 0); assert.equal(C(r).files_invalid, 1);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
