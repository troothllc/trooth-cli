// O04 (audit of 2026-10-04): a successful --json document must reach the
// reader whole, however stdout is connected. Up to 0.6.0 the CLI called
// process.exit right after writing, and a piped reader got the first 64 KiB
// of the record with exit 0.
//
//   node tests/output-delivery.test.mjs
//
// The CLI runs as a child process against a loopback HTTP fixture serving a
// canonical record (TROOTH_WEB) at four sizes: small, exactly 64 KiB of
// stdout, about 300 KB, and just under the 2 MiB body limit check accepts.
// Each is captured through a socket pipe, a kernel pipe through a shell, an
// ordinary file, and a deliberately slow reader that pauses between chunks.
// Every success must parse, carry the final field and equal the served
// record. Then: a reader that closes early (exit 7, never 0), a large lint
// report with a nonzero exit, and the eight canonical record cases.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, openSync, closeSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BIN = "bin/trooth.mjs";
const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/projection/record-v2.json", import.meta.url), "utf8")).body;
const DOMAIN = FIXTURE.domain;
const scratch = mkdtempSync(join(tmpdir(), "trooth-o04-"));

let pass = 0, fail = 0;
const notRun = [];
async function t(name, fn) {
  try { await fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.stack ?? e)); }
}

const witnessed = () => ({
  ...structuredClone(FIXTURE),
  witnessed: { standing: "witnessed", lastWitnessed: "2026-09-29T05:00:00.000Z", firstWitnessedAt: "2026-08-01T05:00:00.000Z", coverage: { checksPassed: 63, checksRun: 65, source: "witness_statement", checksNotRead: 2, checksInReading: 67 } },
});
/** A witnessed record padded with extra facts; the last fact's value is the
 *  final bytes of the document, so a truncated read cannot hold it. */
function padded(extraChars) {
  const b = witnessed();
  const f0 = b.facts[0];
  let k = 0;
  while (extraChars > 0) {
    const len = Math.min(4000, extraChars);
    b.facts.push({ ...structuredClone(f0), key: `pad.${k++}`, value: "p".repeat(len) });
    extraChars -= len + 2000; // a pretty-printed fact carries about 1,700 bytes besides its value
  }
  b.facts.push({ ...structuredClone(f0), key: "pad.size", value: "s" });
  b.facts.push({ ...structuredClone(f0), key: "pad.final", value: "FINAL-FIELD-END" });
  return b;
}

let serve = () => ({ status: 200, body: witnessed() });
const server = createServer((req, res) => {
  const a = serve(req);
  if (a.destroy) { req.socket.destroy(); return; }
  res.statusCode = a.status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(typeof a.body === "string" ? a.body : JSON.stringify(a.body));
});
const dir = createServer((req, res) => { res.statusCode = 404; res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ listed: false })); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
await new Promise((r) => dir.listen(0, "127.0.0.1", r));
const ENV = { ...process.env, TROOTH_WEB: `http://127.0.0.1:${server.address().port}`, TROOTH_API: `http://127.0.0.1:${dir.address().port}`, NO_COLOR: "1", TROOTH_TIMEOUT_MS: "5000" };
const ARGS = (extra = []) => [BIN, "check", DOMAIN, "--json", ...extra];

const exited = (p) => new Promise((resolve) => p.on("close", (code) => resolve(code)));
function collectErr(p) { let e = ""; p.stderr.on("data", (b) => (e += b)); return () => e; }

/** stdout through a Node pipe (a socket pair), read as fast as it comes. */
async function viaPipe(args, env = ENV) {
  const p = spawn(process.execPath, args, { env });
  const err = collectErr(p);
  const chunks = []; p.stdout.on("data", (b) => chunks.push(b));
  const status = await exited(p);
  return { status, stdout: Buffer.concat(chunks).toString("utf8"), stderr: err() };
}
/** stdout through a kernel pipe set up by a shell, to a reader that waits first. */
async function viaShellPipe(args, env = ENV) {
  const out = join(scratch, `sh-${Math.random().toString(36).slice(2)}.out`);
  const cmd = `"${process.execPath}" ${args.map((a) => `'${a}'`).join(" ")} | (sleep 0.3; cat > '${out}'); exit \${PIPESTATUS[0]}`;
  const p = spawn("bash", ["-c", cmd], { env });
  const err = collectErr(p);
  const status = await exited(p);
  return { status, stdout: readFileSync(out, "utf8"), stderr: err() };
}
/** stdout redirected to an ordinary file. */
async function viaFile(args, env = ENV) {
  const out = join(scratch, `f-${Math.random().toString(36).slice(2)}.out`);
  const fd = openSync(out, "w");
  const p = spawn(process.execPath, args, { env, stdio: ["ignore", fd, "pipe"] });
  closeSync(fd);
  const err = collectErr(p);
  const status = await exited(p);
  return { status, stdout: readFileSync(out, "utf8"), stderr: err() };
}
/** A deliberately slow reader: paused at the start, then 25 ms of pause after
 *  every chunk, so the writer meets backpressure the whole way. */
async function viaSlowReader(args, env = ENV) {
  const p = spawn(process.execPath, args, { env });
  const err = collectErr(p);
  const chunks = [];
  p.stdout.pause();
  setTimeout(() => p.stdout.resume(), 200);
  p.stdout.on("data", (b) => { chunks.push(b); p.stdout.pause(); setTimeout(() => p.stdout.resume(), 25); });
  const status = await exited(p);
  return { status, stdout: Buffer.concat(chunks).toString("utf8"), stderr: err() };
}
const CAPTURES = { "socket pipe": viaPipe, "kernel pipe through a shell": viaShellPipe, "file redirection": viaFile, "slow reader": viaSlowReader };

function assertWhole(r, body, expectedBytes) {
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr.slice(0, 300)}`);
  if (expectedBytes !== undefined) assert.equal(Buffer.byteLength(r.stdout), expectedBytes, "byte length");
  assert.ok(r.stdout.endsWith("}\n"), "the document is not terminated");
  const d = JSON.parse(r.stdout);
  const keys = Object.keys(d);
  assert.equal(keys[keys.length - 1], "record", "the final field is missing");
  assert.deepEqual(d.record, body, "the record does not match the served record");
  assert.equal(d.record.facts[d.record.facts.length - 1].value, "FINAL-FIELD-END");
  assert.equal(d.signature_checked, false, "the signature_checked=false disclosure is gone");
  assert.equal(d.state, "listed_witnessed");
}

// Size the documents. The padding is tuned so the "64 KiB" case writes
// exactly 65,536 bytes of stdout.
async function outputBytes(body) { serve = () => ({ status: 200, body }); return Buffer.byteLength((await viaFile(ARGS())).stdout); }
const small = padded(0);
let exact = padded(20000);
{
  const sizer = exact.facts[exact.facts.length - 2];
  for (let i = 0; i < 3; i++) {
    const have = await outputBytes(exact);
    sizer.value = "s".repeat(Math.max(1, sizer.value.length + (65536 - have)));
  }
  assert.equal(await outputBytes(exact), 65536, "could not size the 64 KiB case");
}
const large = padded(300000);
let max = padded(2 * 1024 * 1024 - 60000);
while (Buffer.byteLength(JSON.stringify(max)) > 2 * 1024 * 1024 - 1024) max.facts.splice(max.facts.length - 2, 1);
const SIZES = { small, "exactly 64 KiB": exact, "about 300 KB": large, "just under the 2 MiB limit": max };

console.log("a successful --json document arrives whole");
for (const [sizeName, body] of Object.entries(SIZES)) {
  for (const [capName, cap] of Object.entries(CAPTURES)) {
    await t(`${sizeName}, ${capName}: exit 0, parses, final field present, equals the served record`, async () => {
      serve = () => ({ status: 200, body });
      const r = await cap(ARGS());
      assertWhole(r, body, sizeName === "exactly 64 KiB" ? 65536 : undefined);
    });
  }
}
await t("the 300 KB case, three repeats through a socket pipe, each whole", async () => {
  serve = () => ({ status: 200, body: large });
  for (let i = 0; i < 3; i++) assertWhole(await viaPipe(ARGS()), large);
});
await t("the human output of the 300 KB record also arrives whole through a slow reader", async () => {
  serve = () => ({ status: 200, body: large });
  const r = await viaSlowReader([BIN, "check", DOMAIN]);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.includes("FINAL-FIELD-END"));
  assert.ok(/Signing keys: /.test(r.stdout.trimEnd().split("\n").pop()), "the last line is missing");
});

console.log("a reader that stops early is never told the document was delivered");
await t("socket pipe closed after the first chunk: exit 7, stderr says the output was not delivered", async () => {
  serve = () => ({ status: 200, body: max });
  const p = spawn(process.execPath, ARGS(), { env: ENV });
  const err = collectErr(p);
  p.stdout.once("data", () => p.stdout.destroy());
  const status = await exited(p);
  assert.equal(status, 7, `exit ${status}: ${err()}`);
  assert.match(err(), /output not delivered: stdout failed \(EPIPE|output not delivered: stdout failed \(/);
});
await t("kernel pipe to head -c 100: exit 7 from trooth, never 0", async () => {
  serve = () => ({ status: 200, body: max });
  const p = spawn("bash", ["-c", `"${process.execPath}" ${ARGS().map((a) => `'${a}'`).join(" ")} | head -c 100 > /dev/null; exit \${PIPESTATUS[0]}`], { env: ENV });
  const err = collectErr(p);
  const status = await exited(p);
  assert.equal(status, 7, `exit ${status}: ${err()}`);
  assert.match(err(), /EPIPE/);
});
await t("human output to head -n 2: exit 7 and no stack trace", async () => {
  serve = () => ({ status: 200, body: max });
  const p = spawn("bash", ["-c", `"${process.execPath}" '${BIN}' check '${DOMAIN}' | head -n 2 > /dev/null; exit \${PIPESTATUS[0]}`], { env: ENV });
  const err = collectErr(p);
  const status = await exited(p);
  assert.equal(status, 7, err());
  assert.ok(!/at .*\.mjs:\d+/.test(err()), "a stack trace was printed");
});
// /dev/full exists on Linux and not on macOS. Where it is absent the case is
// counted as NOT RUN and printed as such; it is never counted as a pass. The
// file-size-limit case below produces a real write error on both platforms.
if (existsSync("/dev/full")) {
await t("a write error on a full device (/dev/full): exit 7, not 0", async () => {
  serve = () => ({ status: 200, body: small });
  const fd = openSync("/dev/full", "w");
  const p = spawn(process.execPath, ARGS(), { env: ENV, stdio: ["ignore", fd, "pipe"] });
  closeSync(fd);
  const err = collectErr(p);
  const status = await exited(p);
  assert.equal(status, 7, err());
  assert.match(err(), /ENOSPC/);
});
} else {
  notRun.push("a write error on a full device (/dev/full): this platform has no /dev/full");
  console.log("  NOT RUN  a write error on a full device (/dev/full): this platform has no /dev/full");
}
await t("a write error from a file size limit (EFBIG, Linux and macOS): exit 7, not 0", async () => {
  serve = () => ({ status: 200, body: small });
  const out = join(scratch, "efbig.out");
  // SIGXFSZ is ignored before exec, so the write fails with EFBIG instead of
  // killing the process; ulimit -f 0 allows no bytes in a regular file.
  const p = spawn("bash", ["-c", `trap '' XFSZ; ulimit -f 0; exec "${process.execPath}" ${ARGS().map((a) => `'${a}'`).join(" ")} > '${out}'`], { env: ENV, stdio: ["ignore", "ignore", "pipe"] });
  const err = collectErr(p);
  const status = await exited(p);
  assert.equal(status, 7, `exit ${status}: ${err()}`);
  assert.match(err(), /EFBIG/);
});

console.log("a large lint report with a nonzero exit arrives whole");
const lintTree = join(scratch, "lint");
{
  const deep = "d".repeat(120);
  for (let i = 0; i < 70; i++) {
    const d = join(lintTree, `${deep}${i}`, deep, deep);
    mkdirSync(d, { recursive: true });
    writeFileSync(join(d, "broken.tf.json"), "{");
  }
  for (let i = 0; i < 30; i++) writeFileSync(join(lintTree, `v${i}.tf`), `resource "aws_ebs_volume" "v${i}" {\n  encrypted = true\n}\n`);
}
for (const [capName, cap] of Object.entries(CAPTURES)) {
  await t(`lint, 70 invalid files, ${capName}: exit 4, parses, final field present`, async () => {
    const r = await cap([BIN, "lint", lintTree, "--json"]);
    assert.equal(r.status, 4, r.stderr);
    const d = JSON.parse(r.stdout);
    assert.equal(Object.keys(d).pop(), "note");
    assert.equal(d.coverage.files_invalid, 70);
    assert.equal(d.coverage_details.invalid.entries.length, 50);
    assert.equal(d.facts.storage_declaring_encryption, 30);
    assert.ok(Buffer.byteLength(r.stdout) > 16384, `only ${Buffer.byteLength(r.stdout)} bytes`);
  });
}
await t("lint human report through a slow reader: exit 4, ends with its last line", async () => {
  const r = await viaSlowReader([BIN, "lint", lintTree]);
  assert.equal(r.status, 4);
  assert.ok(r.stdout.trimEnd().endsWith("https://trooth.co/dashboard."), r.stdout.slice(-200));
});

console.log("the canonical record cases, through a slow reader");
const cases = [
  ["canonical", () => ({ status: 200, body: large }), [], 0, (d) => { assert.equal(d.signature_checked, false); assert.deepEqual(d.record, large); }],
  ["absence", () => ({ status: 200, body: { found: false } }), [], 1, (d) => assert.equal(d.state, "not_listed")],
  ["withheld", () => ({ status: 200, body: { found: true, withheld: true, slug: "acme", name: "Acme", reason: "R".repeat(400), since: "2026-09-01T00:00:00Z" } }), [], 6, (d) => assert.equal(d.state, "withheld")],
  ["wrong domain", () => ({ status: 200, body: { ...witnessed(), domain: "other.example" } }), [], 3, (d) => assert.equal(d.ok, false)],
  ["unsupported contract", () => ({ status: 400, body: { error: "unsupported contract" } }), [], 3, (d) => assert.equal(d.exit, 3)],
  ["rate limit no fallback", () => ({ status: 429, body: { error: "slow down" } }), [], 3, (d) => assert.equal(d.http_status, 429)],
  ["unreachable no fallback", () => ({ destroy: true }), ["--no-fallback"], 3, (d) => assert.equal(d.state, "service_error")],
  ["unreachable labelled fallback", () => ({ destroy: true }), [], 1, (d) => { assert.equal(d.source.surface, "directory_fallback"); assert.equal(d.source.fallback, true); }],
];
for (const [name, answer, extra, code, check] of cases) {
  await t(`${name}: exit ${code}, one whole JSON document`, async () => {
    serve = answer;
    const r = await viaSlowReader(ARGS(extra));
    assert.equal(r.status, code, r.stderr);
    check(JSON.parse(r.stdout));
  });
}
await t("usage error via fail(): exit 2, one JSON document, through a file", async () => {
  const r = await viaFile([BIN, "check", "not a domain", "--json"]);
  assert.equal(r.status, 2);
  assert.equal(JSON.parse(r.stdout).exit, 2);
});

server.close(); dir.close();
console.log(`\n${pass} passed, ${fail} failed, ${notRun.length} not run${notRun.length ? " (" + notRun.join("; ") + ")" : ""}`);
process.exitCode = fail ? 1 : 0;
