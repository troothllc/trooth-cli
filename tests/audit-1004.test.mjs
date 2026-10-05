// The declaration fixtures from the audit of 2026-10-04 (N01 to N04), held as
// a release gate, verbatim, with the positive controls and regression cases
// the audit asked for beside them.
//
//   node tests/audit-1004.test.mjs
//
// Every input is synthetic and every credential is a dummy string. No value
// may appear on stdout or stderr.
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
const scratch = mkdtempSync(join(tmpdir(), "trooth-1004-"));
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
const partition = (f) => assert.equal(
  f.storage_declaring_encryption + f.storage_declaring_encryption_off + f.storage_encryption_not_declared + f.storage_encryption_unresolved + f.storage_encryption_unsupported,
  f.storage_declarations, "storage-state counts do not partition the storage declarations");
/** Invalid, incomplete, exit 4, with a reason in the per-file report. */
function invalid(r, reason) {
  assert.equal(r.status, 4, `exit ${r.status}`);
  assert.equal(C(r).completeness, "incomplete");
  assert.equal(C(r).files_invalid, 1);
  const e = r.doc.coverage_details.invalid.entries[0];
  assert.ok(e && e.reason, "no per-file reason");
  if (reason) assert.match(e.reason, reason);
  return e;
}
/** The facts of two runs, without the fields that name the tree. */
const sameFacts = (a, b) => assert.deepEqual(F(a), F(b));

/* ------------------------------------------------------------------ N01 -- */
console.log("N01 malformed nested declarations (audit fixtures, verbatim)");
t("list missing items: invalid, incomplete, exit 4", () => {
  const r = lint(tree({ "manifest.yaml": "apiVersion: v1\nkind: List\nmetadata: {}\n" }));
  invalid(r, /items array/); assert.equal(F(r).declarations_read, 0);
});
t("list invalid items: invalid, incomplete, exit 4", () => {
  const r = lint(tree({ "manifest.yaml": "apiVersion: v1\nkind: List\nitems: not-an-array\n" }));
  invalid(r, /items array/);
  assert.ok(!r.stdout.includes("not-an-array"), "the reason echoes a value");
});
t("tfjson resource wrong shape: invalid, incomplete, exit 4", () => {
  const r = lint(tree({ "main.tf.json": '{"resource": "not-an-object"}' }));
  invalid(r, /^resource must be an object/);
  assert.ok(!r.stdout.includes("not-an-object"), "the reason echoes a value");
});
t("tfjson resource scalar body: invalid, incomplete, exit 4, no storage counted", () => {
  const r = lint(tree({ "main.tf.json": '{"resource":{"aws_ebs_volume":{"disk":true}}}' }));
  invalid(r, /resource\.aws_ebs_volume\.disk must be an object/); assert.equal(F(r).storage_declarations, 0);
});
t("hcl duplicate attribute: invalid, exit 4, never counted as encrypted", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_ebs_volume" "test" {\nencrypted = false\nencrypted = true\n}\n' }));
  invalid(r, /line 3: duplicate attribute "encrypted"/);
  assert.equal(F(r).storage_declaring_encryption, 0); assert.equal(F(r).storage_declarations, 0);
});
console.log("N01 further malformed shapes");
t("a nested List with non-array items inside a List: invalid", () => {
  invalid(lint(tree({ "m.yaml": "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: List\n  items: 3\n" })), /items array/);
});
t("kind List with items: null: invalid", () => {
  invalid(lint(tree({ "m.yaml": "apiVersion: v1\nkind: List\nitems: null\n" })), /found null/);
});
t("a *List kind whose items is a mapping: invalid", () => {
  invalid(lint(tree({ "m.yaml": "apiVersion: v1\nkind: PodList\nitems: {a: 1}\n" })), /PodList needs an items array/);
});
t("tfjson resource type that is an array of scalars: invalid", () => {
  invalid(lint(tree({ "main.tf.json": '{"resource":{"aws_ebs_volume":[1]}}' })), /resource\.aws_ebs_volume must be an object or an array of objects/);
});
t("tfjson resource body null: invalid", () => {
  invalid(lint(tree({ "main.tf.json": '{"resource":{"aws_ebs_volume":{"disk":null}}}' })), /found null/);
});
t("tfjson repeated key in one object: invalid, never counted as encrypted", () => {
  const r = lint(tree({ "main.tf.json": '{"resource":{"aws_ebs_volume":{"d":{"encrypted":false,"encrypted":true}}}}' }));
  invalid(r, /repeated/); assert.equal(F(r).storage_declaring_encryption, 0);
});
t("hcl repeated key in one object constructor: invalid", () => {
  invalid(lint(tree({ "main.tf": 'resource "aws_s3_bucket" "b" {\n  tags = { a = "1", a = "2" }\n}\n' })), /duplicate key "a"/);
});
t("hcl duplicate attribute in a nested block: invalid", () => {
  invalid(lint(tree({ "main.tf": 'resource "aws_db_instance" "d" {\n  x {\n    y = 1\n    y = 2\n  }\n}\n' })), /duplicate attribute "y"/);
});
t("a malformed file beside a valid one: the valid one is read, the read is incomplete, --allow-incomplete exits 0", () => {
  const d = tree({ "a/main.tf": 'resource "aws_ebs_volume" "v" { encrypted = true }\n', "b/main.tf.json": '{"resource":{"aws_ebs_volume":{"disk":true}}}' });
  const r = lint(d);
  invalid(r); assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(F(r).declarations_read, 1);
  assert.equal(lint(d, ["--allow-incomplete"]).status, 0);
});
console.log("N01 positive controls");
t("valid empty List: read, complete, exit 0", () => {
  const r = lint(tree({ "m.yaml": "apiVersion: v1\nkind: List\nitems: []\n" }));
  assert.equal(r.status, 0); assert.equal(C(r).completeness, "complete"); assert.equal(C(r).files_read, 1);
});
t("valid flow-style List with a member: read, complete", () => {
  const r = lint(tree({ "m.yaml": '{apiVersion: v1, kind: List, items: [{apiVersion: v1, kind: Secret, metadata: {name: s}, stringData: {k: "dummy-only-value"}}]}\n' }));
  assert.equal(r.status, 0); assert.equal(C(r).completeness, "complete"); assert.equal(F(r).inline_credential_literals, 1); noLeak(r, SECRET);
});
t("valid flow YAML ConfigMap: read, complete", () => {
  const r = lint(tree({ "m.yaml": '{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "c"}, "data": {"region": "eu-west-1"}}\n' }));
  assert.equal(r.status, 0); assert.deepEqual(F(r).regions_and_zones_declared, ["eu-west-1"]);
});
t("mixed valid and invalid List members: the valid member is read, the read is incomplete", () => {
  const r = lint(tree({ "m.yaml": "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: ConfigMap\n  metadata: {name: a}\n- just: a mapping\n" }));
  assert.equal(r.status, 4); assert.equal(C(r).list_members_not_read, 1); assert.equal(C(r).files_invalid, 0);
  assert.deepEqual(F(r).resource_types, [{ type: "ConfigMap", count: 1 }]);
});
t("valid resource maps: object form, array-of-objects form and // comment keys", () => {
  const r = lint(tree({
    "a/main.tf.json": '{"//":"note","resource":{"//":"note","aws_ebs_volume":{"//":"note","a":{"encrypted":true}}}}',
    "b/main.tf.json": '{"resource":[{"aws_ebs_volume":[{"b":[{"encrypted":false}]}]}]}',
  }));
  assert.equal(r.status, 0, r.stderr); assert.equal(C(r).completeness, "complete");
  assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(F(r).storage_declaring_encryption_off, 1); partition(F(r));
});
t("tfjson escaped boolean key still works", () => {
  const r = lint(tree({ "main.tf.json": '{"resource":{"aws_ebs_volume":{"d":{"\\u0065ncrypted":true}}}}' }));
  assert.equal(r.status, 0); assert.equal(F(r).storage_declaring_encryption, 1);
});
t("repeated blocks of one type are not duplicate attributes", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_security_group" "g" {\n  ingress {\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n' }));
  assert.equal(r.status, 0); assert.equal(F(r).declarations_open_to_any_address, 1);
});
t("independent modules with one local name: only the root that declares encryption is credited", () => {
  const r = lint(tree({
    "a/main.tf": 'resource "aws_s3_bucket" "shared" {}\nresource "aws_s3_bucket_server_side_encryption_configuration" "e" {\n  bucket = aws_s3_bucket.shared.id\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "aws:kms"\n    }\n  }\n}\n',
    "b/main.tf": 'resource "aws_s3_bucket" "shared" {}\n',
  }));
  assert.equal(r.status, 0); assert.equal(F(r).storage_declarations, 2);
  assert.equal(F(r).storage_declaring_encryption, 1); assert.equal(F(r).storage_encryption_not_declared, 1);
});

/* ------------------------------------------------------------------ N02 -- */
console.log("N02 Terraform plan unknown values");
t("json plan unknown encryption (audit fixture, verbatim): one unresolved, none not declared, none declared", () => {
  const r = lint(tree({ "plan.json": '{"terraform_version":"1.0.0","resource_changes":[{"address":"aws_ebs_volume.disk","type":"aws_ebs_volume","name":"disk","change":{"after":{},"after_unknown":{"encrypted":true}}}]}' }));
  assert.equal(r.status, 0); const f = F(r);
  assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_encryption_not_declared, 0); assert.equal(f.storage_declaring_encryption, 0); partition(f);
});
t("the fuller planned_values / format_version / actions / encrypted=null control: one unresolved", () => {
  const plan = {
    format_version: "1.2", terraform_version: "1.9.0",
    planned_values: { root_module: { resources: [{ address: "aws_ebs_volume.disk", mode: "managed", type: "aws_ebs_volume", name: "disk", values: { encrypted: null, size: 8 } }] } },
    resource_changes: [{ address: "aws_ebs_volume.disk", mode: "managed", type: "aws_ebs_volume", name: "disk", change: { actions: ["create"], before: null, after: { encrypted: null, size: 8 }, after_unknown: { encrypted: true } } }],
  };
  const f = F(lint(tree({ "plan.json": JSON.stringify(plan) })));
  assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_encryption_not_declared, 0); assert.equal(f.storage_declaring_encryption, 0);
});
const CASES = { true: [{ encrypted: true }, undefined, "storage_declaring_encryption"], false: [{ encrypted: false }, undefined, "storage_declaring_encryption_off"], absent: [{}, undefined, "storage_encryption_not_declared"], null: [{ encrypted: null }, undefined, "storage_encryption_not_declared"], unknown: [{}, { encrypted: true }, "storage_encryption_unresolved"] };
for (const [label, [after, unknown, field]] of Object.entries(CASES)) {
  t(`resource_changes-only form, encrypted ${label}: ${field} 1`, () => {
    const change = { actions: ["create"], after, ...(unknown ? { after_unknown: unknown } : { after_unknown: {} }) };
    const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [{ address: "aws_ebs_volume.d", mode: "managed", type: "aws_ebs_volume", name: "d", change }] }) })));
    assert.equal(f[field], 1); assert.equal(f.storage_declarations, 1); partition(f);
  });
  t(`planned_values form, encrypted ${label}: ${field} 1`, () => {
    const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0",
      planned_values: { root_module: { resources: [{ address: "aws_ebs_volume.d", mode: "managed", type: "aws_ebs_volume", name: "d", values: after }] } },
      resource_changes: [{ address: "aws_ebs_volume.d", mode: "managed", type: "aws_ebs_volume", name: "d", change: { actions: ["create"], after, after_unknown: unknown || {} } }] }) })));
    assert.equal(f[field], 1); assert.equal(f.storage_declarations, 1); partition(f);
  });
}
t("nested modules keep their identity: module.a unknown and module.a.module.b off are two stores", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0",
    planned_values: { root_module: { child_modules: [{ address: "module.a", resources: [{ address: "module.a.aws_ebs_volume.disk", mode: "managed", type: "aws_ebs_volume", name: "disk", values: {} }],
      child_modules: [{ address: "module.a.module.b", resources: [{ address: "module.a.module.b.aws_ebs_volume.disk", mode: "managed", type: "aws_ebs_volume", name: "disk", values: { encrypted: false } }] }] }] } },
    resource_changes: [
      { address: "module.a.aws_ebs_volume.disk", module_address: "module.a", mode: "managed", type: "aws_ebs_volume", name: "disk", change: { actions: ["create"], after: {}, after_unknown: { encrypted: true } } },
      { address: "module.a.module.b.aws_ebs_volume.disk", module_address: "module.a.module.b", mode: "managed", type: "aws_ebs_volume", name: "disk", change: { actions: ["create"], after: { encrypted: false }, after_unknown: {} } },
    ] }) })));
  assert.equal(f.storage_declarations, 2); assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_declaring_encryption_off, 1); partition(f);
});
t("nested modules in the resource_changes-only form: the unknown mark stays with its own address", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [
    { address: "module.a.aws_ebs_volume.disk", type: "aws_ebs_volume", name: "disk", change: { after: {}, after_unknown: { encrypted: true } } },
    { address: "module.b.aws_ebs_volume.disk", type: "aws_ebs_volume", name: "disk", change: { after: {}, after_unknown: {} } },
  ] }) })));
  assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_encryption_not_declared, 1);
});
t("unknown nested attribute (an encryption block's algorithm): unresolved, not declared", () => {
  const after = { bucket: "logs-bucket", server_side_encryption_configuration: [{ rule: [{ apply_server_side_encryption_by_default: [{}] }] }] };
  const unknown = { server_side_encryption_configuration: [{ rule: [{ apply_server_side_encryption_by_default: [{ sse_algorithm: true }] }] }] };
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [{ address: "aws_s3_bucket.logs", mode: "managed", type: "aws_s3_bucket", name: "logs", change: { after, after_unknown: unknown } }] }) })));
  assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_declaring_encryption, 0);
});
t("a whole unknown encryption block: unresolved", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [{ address: "aws_s3_bucket.logs", type: "aws_s3_bucket", name: "logs", change: { after: { bucket: "x-bucket" }, after_unknown: { server_side_encryption_configuration: true } } }] }) })));
  assert.equal(f.storage_encryption_unresolved, 1);
});
t("proposed_unknown marks an unknown setting the planned values omit: unresolved", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0",
    planned_values: { root_module: { resources: [{ address: "aws_ebs_volume.d", mode: "managed", type: "aws_ebs_volume", name: "d", values: {} }] } },
    proposed_unknown: { root_module: { resources: [{ address: "aws_ebs_volume.d", values: { encrypted: true } }] } } }) })));
  assert.equal(f.storage_encryption_unresolved, 1); assert.equal(f.storage_encryption_not_declared, 0);
});
t("a false mark in proposed_unknown leaves a known value known", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0",
    planned_values: { root_module: { resources: [{ address: "aws_ebs_volume.d", mode: "managed", type: "aws_ebs_volume", name: "d", values: { encrypted: false } }] } },
    proposed_unknown: { root_module: { resources: [{ address: "aws_ebs_volume.d", values: { encrypted: false } }] } } }) })));
  assert.equal(f.storage_declaring_encryption_off, 1);
});
t("an unknown attribute unrelated to encryption infers nothing: explicit true stays declared", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [{ address: "aws_ebs_volume.d", type: "aws_ebs_volume", name: "d", change: { after: { encrypted: true }, after_unknown: { id: true, arn: true } } }] }) })));
  assert.equal(f.storage_declaring_encryption, 1); assert.equal(f.storage_encryption_unresolved, 0);
});
t("an explicit false outranks an unknown key id", () => {
  const f = F(lint(tree({ "plan.json": JSON.stringify({ terraform_version: "1.9.0", resource_changes: [{ address: "aws_ebs_volume.d", type: "aws_ebs_volume", name: "d", change: { after: { encrypted: false }, after_unknown: { kms_key_id: true } } }] }) })));
  assert.equal(f.storage_declaring_encryption_off, 1);
});

/* ------------------------------------------------------------------ N03 -- */
console.log("N03 HCL string escapes");
t("hcl escaped literal credential (audit fixture, verbatim): counted once", () => {
  const r = lint(tree({ "main.tf": 'resource "aws_db_instance" "test" { password = "$${literal}" }' }));
  assert.equal(r.status, 0); assert.equal(F(r).inline_credential_literals, 1);
  assert.ok(!r.stdout.includes("${literal}"));
});
t("hcl unicode escape region (audit fixture, verbatim): us-east-1 reported", () => {
  const r = lint(tree({ "main.tf": 'provider "aws" { region = "us-east-\\u0031" }' }));
  assert.equal(r.status, 0); assert.deepEqual(F(r).regions_and_zones_declared, ["us-east-1"]);
});
t("escaped and unescaped regions agree, four- and eight-digit forms", () => {
  const plain = lint(tree({ "main.tf": 'provider "aws" { region = "us-east-1" }' }));
  sameFacts(lint(tree({ "main.tf": 'provider "aws" { region = "us-east-\\u0031" }' })), plain);
  sameFacts(lint(tree({ "main.tf": 'provider "aws" { region = "us-east-\\U00000031" }' })), plain);
});
t("plain password control: counted, value never printed", () => {
  const r = lint(tree({ "main.tf": `resource "aws_db_instance" "t" { password = "${SECRET}" }` }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, SECRET);
});
t("$${ and %%{ literal markers make constants that are counted, value never printed", () => {
  for (const v of ["$${dummy-only-value}", "%%{dummy-only-value}", "pa$$word-dummy-only-value", "$dummy-only-value", "$$${dummy-only-value}"]) {
    const r = lint(tree({ "main.tf": `resource "aws_db_instance" "t" { password = "${v}" }` }));
    assert.equal(r.status, 0, v); assert.equal(F(r).inline_credential_literals, 1, v); noLeak(r, SECRET);
  }
});
t("a heredoc with $${ is a constant and is counted; one with ${ } is unresolved", () => {
  const lit = lint(tree({ "main.tf": `resource "aws_db_instance" "t" {\n  password = <<EOT\n$\${${SECRET}}\nEOT\n}\n` }));
  assert.equal(F(lit).inline_credential_literals, 1); noLeak(lit, SECRET);
  const expr = lint(tree({ "main.tf": 'resource "aws_db_instance" "t" {\n  password = <<-EOT\n    ${var.db_password}\n    EOT\n}\n' }));
  assert.equal(F(expr).inline_credential_literals, 0);
});
t("backslashes are literal in a heredoc, as Terraform documents: no region decoded there", () => {
  const r = lint(tree({ "main.tf": 'provider "aws" {\n  region = <<EOT\nus-east-\\u0031\nEOT\n}\n' }));
  assert.equal(r.status, 0); assert.deepEqual(F(r).regions_and_zones_declared, []);
});
t("real interpolation stays unresolved: no credential, no region", () => {
  const r = lint(tree({ "main.tf": 'provider "aws" { region = "${var.region}" }\nresource "aws_db_instance" "t" { password = "${var.db_password}" }\nresource "aws_db_instance" "u" { password = "$${a}${var.b}" }\n' }));
  assert.equal(r.status, 0); assert.equal(F(r).inline_credential_literals, 0); assert.deepEqual(F(r).regions_and_zones_declared, []);
});
t("tfjson: $${ is a literal and counted, ${ } is an expression and not", () => {
  const lit = lint(tree({ "main.tf.json": `{"resource":{"aws_db_instance":{"t":{"password":"$\${${SECRET}}"}}}}` }));
  assert.equal(F(lit).inline_credential_literals, 1); noLeak(lit, SECRET);
  const expr = lint(tree({ "main.tf.json": '{"resource":{"aws_db_instance":{"t":{"password":"${var.p}"}}}}' }));
  assert.equal(F(expr).inline_credential_literals, 0);
});
t("invalid escapes are rejected without evaluation, and the digits are not echoed", () => {
  for (const esc of ["\\u00G1", "\\uD800", "\\U00110000", "\\u12", "\\q"]) {
    const r = lint(tree({ "main.tf": `resource "aws_db_instance" "t" { password = "x${esc}y-${SECRET}" }` }));
    invalid(r, /invalid/); noLeak(r, SECRET, "00G1", "D800", "00110000");
  }
});
t("standard escapes decode: a quoted constant with \\\" and \\\\ is still one literal", () => {
  const r = lint(tree({ "main.tf": `resource "aws_db_instance" "t" { password = "a\\"b\\\\c\\t${SECRET}" }` }));
  assert.equal(F(r).inline_credential_literals, 1); noLeak(r, SECRET);
});

/* ------------------------------------------------------------------ N04 -- */
console.log("N04 Dockerfile logical lines");
const dock = (body) => lint(tree({ Dockerfile: body }));
const one = (body, expected = 1) => { const r = dock(body); assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`); assert.equal(F(r).inline_credential_literals, expected); noLeak(r, SECRET); return r; };
t("docker line continuation comment (audit fixture, verbatim): counted once", () => {
  one("FROM example.invalid/base\nENV API_TOKEN=\\\n# keep a synthetic token below\ndummy-only-value\n");
});
t("the same without the intervening comment: counted once", () => {
  one("FROM example.invalid/base\nENV API_TOKEN=\\\ndummy-only-value\n");
});
t("one-line and continued forms agree: ENV, ARG, quotes, multiple assignments, CRLF, comments, empty lines", () => {
  const groups = [
    ["FROM x\nENV API_TOKEN=dummy-only-value\n", "FROM x\nENV API_TOKEN=\\\ndummy-only-value\n", "FROM x\r\nENV API_TOKEN=\\\r\n# c\r\ndummy-only-value\r\n", "FROM x\nENV API_TOKEN=dummy-\\\n  # indented comment\n\nonly-value\n", "FROM x\nENV API_TOKEN=\\   \ndummy-only-value\n"],
    ['FROM x\nENV API_TOKEN="dummy-only-value"\n', 'FROM x\nENV API_TOKEN="dummy-\\\nonly-value"\n', "FROM x\nENV API_TOKEN='dummy-only-value'\n"],
    ["FROM x\nENV A=1 API_TOKEN=dummy-only-value B=2\n", "FROM x\nENV A=1 \\\n    API_TOKEN=dummy-only-value \\\n    B=2\n", "FROM x\nENV A=1 \\\n# c\n    API_TOKEN=dummy-only-value B=2\n"],
    ["FROM x\nARG API_TOKEN=dummy-only-value\n", "FROM x\nARG API_TOKEN=\\\ndummy-only-value\n", "FROM x\nARG A=1 API_TOKEN=dummy-only-value\n"],
    ["FROM x\nENV API_TOKEN dummy-only-value\n", "FROM x\nENV API_TOKEN \\\ndummy-only-value\n"],
  ];
  for (const g of groups) {
    const first = one(g[0]);
    for (const v of g.slice(1)) sameFacts(one(v), first);
  }
});
t("the escape directive: a backtick continues the line, and a backslash is then literal", () => {
  one("# escape=`\nFROM x\nENV API_TOKEN=`\ndummy-only-value\n");
  one("# escape=`\nFROM x\nENV API_TOKEN=C:\\\n$HOME\n", 1);   // backslash literal: C:\ is the value
  one("FROM x\nENV API_TOKEN=C:\\\n$HOME\n", 0);                // default escape: joined into C:$HOME, a reference
  one("# escape=\\\nFROM x\nENV API_TOKEN=\\\ndummy-only-value\n");
});
t("a directive after the first instruction is only a comment", () => {
  one("FROM x\n# escape=`\nENV API_TOKEN=`\ndummy-only-value\n", 1); // ` is not an escape here, two lines, the first a literal
});
t("variable references stay unresolved, in one line or continued; escaped $ and single quotes are literal", () => {
  one("FROM x\nENV API_TOKEN=$SECRET\n", 0);
  one("FROM x\nENV API_TOKEN=\\\n${SECRET}\n", 0);
  one('FROM x\nENV API_TOKEN="pre-$SECRET"\n', 0);
  one("FROM x\nENV API_TOKEN=\\$dummy-only-value\n", 1);
  one("FROM x\nENV API_TOKEN='$dummy-only-value'\n", 1);
  one("FROM x\nARG API_TOKEN\n", 0);
});
t("T18 kept: an earlier literal is counted when a later assignment, continued or not, is a reference", () => {
  one("FROM x\nENV API_TOKEN=dummy-only-value\nENV API_TOKEN=$OTHER\n", 1);
  one("FROM x\nENV API_TOKEN=\\\ndummy-only-value\nENV API_TOKEN=\\\n$OTHER\n", 1);
});
t("a RUN heredoc body is not read as instructions", () => {
  one("FROM x\nRUN <<EOF\nENV API_TOKEN=dummy-only-value\nEOF\nENV OTHER=1\n", 0);
});
t("unsupported ENV syntax is reported as invalid, the value never printed", () => {
  for (const body of ["FROM x\nENV A=1 API_TOKEN\n", 'FROM x\nENV API_TOKEN="dummy-only-value\n', "FROM x\nENV API_TOKEN\n", "FROM x\nENV\n", "# escape=x\nFROM x\n"]) {
    const r = dock(body);
    invalid(r); noLeak(r, SECRET);
  }
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exitCode = fail ? 1 : 0;
