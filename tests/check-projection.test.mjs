// `trooth check` reads the one record projection, GET /api/network/profile,
// and carries the same fields, provenance and record version as the REST API,
// the MCP connector and the llms.txt twin. Held here without the network.
//
//   node tests/check-projection.test.mjs
//
// tests/fixtures/projection/record-v2.json is a byte copy of the web
// repository's tests/fixtures/cross-surface/record-v2.json: the REST body for
// one company at one record version, built by the route's own body function
// and validated against https://trooth.co/schemas/network-profile.v2.schema.json.
// A local server answers /api/network/profile with it (TROOTH_WEB), and a
// second one stands in for the directory route on api.trooth.co (TROOTH_API)
// so the fallback, and the absence of it, can be counted request by request.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";

const BIN = "bin/trooth.mjs";
const FIXTURE = JSON.parse(readFileSync(new URL("./fixtures/projection/record-v2.json", import.meta.url), "utf8")).body;
const DIGEST = "sha-256=" + "a".repeat(64);
const PREVIOUS = "sha-256=" + "b".repeat(64);
const RETIRED = /\b(score|scores|tier|tiers|certified|certification|verified|verification|scan|scanned|scanning|passed|passing|judgement)\b/i;
const DASH = /[–—]| - /;

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); pass++; console.log("  ok   " + name); }
  catch (e) { fail++; console.log("  FAIL " + name + "\n       " + (e?.stack ?? e)); }
}

const witnessedBody = () => ({
  ...structuredClone(FIXTURE),
  witnessed: {
    standing: "witnessed",
    lastWitnessed: "2026-09-29T05:00:00.000Z",
    firstWitnessedAt: "2026-08-01T05:00:00.000Z",
    coverage: { checksPassed: 63, checksRun: 65, source: "witness_statement", definition: "Checks read in the signed reading.", checksNotRead: 2, checksNotAsExpected: 2, checksInReading: 67 },
    continuity: { recordBegan: "2026-08-01T05:00:00.000Z", unbrokenSince: "2026-09-01T05:00:00.000Z", unbrokenReadings: 700, totalReadings: 1400 },
  },
});

// The projection stand-in. `web` decides each answer; every request is logged.
const log = [];
let web = (req, res) => sendJson(res, 200, witnessedBody(), { "trooth-record-version": "7", "trooth-record-digest": DIGEST, "trooth-record-previous-digest": PREVIOUS });
function sendJson(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}
const webServer = createServer((req, res) => { log.push("web " + req.url); web(req, res); });
const dirServer = createServer((req, res) => {
  log.push("dir " + req.url);
  sendJson(res, 200, { domain: "acme.example", company_name: "Acme Cloud", passed_at: "2026-09-26T05:00:25.618Z", probes: { passed: 63, total: 65 }, authority_key_id: "k-1" });
});
await new Promise((r) => webServer.listen(0, "127.0.0.1", r));
await new Promise((r) => dirServer.listen(0, "127.0.0.1", r));
const WEB = `http://127.0.0.1:${webServer.address().port}`;
const API = `http://127.0.0.1:${dirServer.address().port}`;

const check = (args, env = {}) => new Promise((resolve) => {
  log.length = 0;
  const p = spawn(process.execPath, [BIN, "check", ...args], { env: { ...process.env, TROOTH_WEB: WEB, TROOTH_API: API, NO_COLOR: "1", ...env } });
  let stdout = "", stderr = "";
  p.stdout.on("data", (b) => (stdout += b)); p.stderr.on("data", (b) => (stderr += b));
  p.on("close", (status) => resolve({ status, stdout, stderr, requests: [...log] }));
});
const doc = (r) => JSON.parse(r.stdout);

console.log("the record projection");
await t("one request, to /api/network/profile with the domain and the pinned contract; the directory is not read", async () => {
  const r = await check(["https://WWW.Acme.example/pricing", "--json"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.requests, ["web /api/network/profile?q=acme.example&contract=2"]);
});
await t("--json carries the projection body whole under `record`: every fact, its provenance, the conflicts and the signing descriptor", async () => {
  const body = witnessedBody();
  const d = doc(await check(["acme.example", "--json"]));
  assert.deepEqual(d.record, body);
  assert.deepEqual(d.record.facts.map((f) => [f.key, f.category, f.label, f.value, f.origin]), body.facts.map((f) => [f.key, f.category, f.label, f.value, f.origin]));
  for (const f of d.record.facts) {
    assert.equal(f.record.recordVersion, body.updatedAt, f.key);
    assert.ok(f.claim && f.claim.evidenceClass && f.claim.subject.scope, f.key);
  }
});
await t("the record version is the projection's own: header version and digests, and the body's updatedAt", async () => {
  const d = doc(await check(["acme.example", "--json"]));
  assert.deepEqual(d.source, {
    surface: "record_projection",
    fallback: false,
    url: `${WEB}/api/network/profile?q=acme.example&contract=2`,
    contract_version: 2,
    contract_schema: "https://trooth.co/schemas/network-profile.v2.schema.json",
    record_version: 7,
    record_digest: DIGEST,
    record_previous_digest: PREVIOUS,
    record_updated_at: FIXTURE.updatedAt,
  });
});
await t("the summary is derived from the projection's witnessed block and signing descriptor", async () => {
  const d = doc(await check(["acme.example", "--json"]));
  assert.equal(d.state, "listed_witnessed");
  assert.equal(d.company_name, "Acme Cloud");
  assert.equal(d.slug, "acme-cloud");
  assert.equal(d.witnessed_at, "2026-09-29T05:00:00.000Z");
  assert.equal(d.first_witnessed_at, "2026-08-01T05:00:00.000Z");
  assert.deepEqual(d.coverage, { source: "witness_statement", checks_run: 65, checks_as_expected: 63, checks_not_read: 2, checks_in_reading: 67 });
  assert.deepEqual(d.probes, { passed: 63, total: 65 });
  assert.equal(d.facts_published, FIXTURE.facts.length);
  assert.equal(d.signature_checked, false);
  assert.equal(d.record_url, FIXTURE.canonicalUrl);
  assert.equal(d.verify_keys, FIXTURE.signing.keys);
});
await t("the human output lists every fact under its category with its origin, and names the record version and where it was read", async () => {
  const r = await check(["acme.example"]);
  assert.equal(r.status, 0, r.stderr);
  for (const f of FIXTURE.facts) assert.ok(r.stdout.includes(`  ${f.label}: ${f.value}   [${f.origin}]`), f.key);
  assert.match(r.stdout, new RegExp(`Record version: 7 \\(${DIGEST}\\)   updated 2026-09-30   contract 2`));
  assert.match(r.stdout, /Read from the record projection: http:\/\/127\.0\.0\.1:\d+\/api\/network\/profile\?q=acme\.example&contract=2/);
  assert.match(r.stdout, /Last reading: 65 checks read; 63 as expected; 2 listed but not read \(67 in all\)/);
  assert.match(r.stdout, /What is signed: nothing in this record/);
  assert.match(r.stdout, /did not check any signature/);
  assert.ok(!/FALLBACK/.test(r.stdout));
  assert.ok(!RETIRED.test(r.stdout), r.stdout.match(RETIRED)?.[0]);
  assert.ok(!DASH.test(r.stdout), "no dash used as punctuation");
});
await t("a record with nothing witnessed: exit 5, listed_not_witnessed, the facts still carried", async () => {
  web = (req, res) => sendJson(res, 200, FIXTURE, { "trooth-record-version": "7", "trooth-record-digest": DIGEST });
  const r = await check(["acme.example", "--json"]);
  assert.equal(r.status, 5);
  const d = doc(r);
  assert.equal(d.state, "listed_not_witnessed");
  assert.equal(d.witnessed_at, null);
  assert.equal(d.coverage, null);
  assert.deepEqual(d.record.facts, FIXTURE.facts);
  const h = await check(["acme.example"]);
  assert.match(h.stdout, /Nothing witnessed by Trooth is published on this record yet/);
});
await t("a record version the server does not state is null, and printed as not stated, never guessed", async () => {
  web = (req, res) => sendJson(res, 200, FIXTURE);
  const d = doc(await check(["acme.example", "--json"]));
  assert.equal(d.source.record_version, null);
  assert.equal(d.source.record_digest, null);
  assert.equal(d.source.record_updated_at, FIXTURE.updatedAt);
  const h = await check(["acme.example"]);
  assert.match(h.stdout, /Record version: not stated on this read/);
});

console.log("answers that are not a record");
await t("found:false is no published record: exit 1, no fallback", async () => {
  web = (req, res) => sendJson(res, 200, { found: false });
  const r = await check(["nobody.example", "--json"]);
  assert.equal(r.status, 1);
  assert.equal(doc(r).state, "not_listed");
  assert.equal(doc(r).source.surface, "record_projection");
  assert.deepEqual(r.requests, ["web /api/network/profile?q=nobody.example&contract=2"]);
  const h = await check(["nobody.example"]);
  assert.match(h.stdout, /no published record on the Trooth Network/);
  assert.match(h.stdout, /says nothing/);
});
await t("withheld: exit 6, the website's own sentence, neither absent nor a finding", async () => {
  web = (req, res) => sendJson(res, 200, { found: true, withheld: true, slug: "acme-cloud", name: "Acme Cloud", reason: "Withheld while a report about this record is reviewed.", since: "2026-09-30T00:00:00Z", policyVersion: "1" });
  const r = await check(["acme.example", "--json"]);
  assert.equal(r.status, 6);
  assert.equal(doc(r).state, "withheld");
  assert.equal(doc(r).reason, "Withheld while a report about this record is reviewed.");
});
await t("an ambiguous-name answer to a domain is a contract error: exit 3", async () => {
  web = (req, res) => sendJson(res, 200, { found: false, ambiguous: true, candidates: [{ slug: "a" }, { slug: "b" }] });
  assert.equal((await check(["acme.example"])).status, 3);
});
await t("another contract, another company's record, or no facts list: exit 3, and the directory is not read", async () => {
  for (const body of [{ ...FIXTURE, contractVersion: 3 }, { ...FIXTURE, domain: "other.example" }, { ...FIXTURE, facts: undefined }]) {
    web = (req, res) => sendJson(res, 200, body);
    const r = await check(["acme.example"]);
    assert.equal(r.status, 3);
    assert.ok(r.requests.every((x) => x.startsWith("web ")), r.requests.join(","));
  }
});
await t("a 4xx (a refused contract pin, a rate limit) is an error, not a reason to fall back: exit 3", async () => {
  for (const status of [400, 404, 429]) {
    web = (req, res) => sendJson(res, status, { found: false, error: "x" });
    const r = await check(["acme.example", "--json"]);
    assert.equal(r.status, 3, String(status));
    assert.equal(doc(r).state, "service_error");
    assert.ok(r.requests.every((x) => x.startsWith("web ")), r.requests.join(","));
  }
});

console.log("the fallback, only when the projection is unreachable, and labelled");
await t("a 5xx from the projection (after one retry) falls back to the directory route, labelled in every mode", async () => {
  web = (req, res) => sendJson(res, 503, { error: "witnessed_record_unavailable" }, { "retry-after": "30" });
  const r = await check(["acme.example", "--json"]);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.requests, ["web /api/network/profile?q=acme.example&contract=2", "web /api/network/profile?q=acme.example&contract=2", "dir /directory/api/vendors/acme.example"]);
  const d = doc(r);
  assert.equal(d.source.surface, "directory_fallback");
  assert.equal(d.source.fallback, true);
  assert.equal(d.source.record_version, null);
  assert.match(d.source.projection_error, /HTTP 503/);
  assert.equal(d.record, undefined, "the fallback carries no record");
  assert.match(r.stderr, /fallback/);
  const h = await check(["acme.example"]);
  assert.match(h.stdout, /^FALLBACK READ\. The record projection at .* could not be reached/m);
  assert.match(h.stdout, /no facts, no per-fact provenance and no record version/);
});
await t("a projection that cannot be reached at all falls back the same way", async () => {
  const r = await check(["acme.example", "--json"], { TROOTH_WEB: "http://127.0.0.1:9" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(doc(r).source.surface, "directory_fallback");
  assert.match(doc(r).source.projection_error, /could not reach/);
});
await t("--no-fallback makes an unreachable projection exit 3, and the directory is never read", async () => {
  web = (req, res) => sendJson(res, 503, { error: "x" });
  const r = await check(["acme.example", "--no-fallback", "--json"]);
  assert.equal(r.status, 3);
  assert.ok(r.requests.every((x) => x.startsWith("web ")), r.requests.join(","));
  const u = await check(["acme.example", "--no-fallback"], { TROOTH_WEB: "http://127.0.0.1:9" });
  assert.equal(u.status, 3);
  assert.deepEqual(u.requests, []);
});
await t("a projection body over its 2 MiB bound is an error, not a fallback", async () => {
  web = (req, res) => { res.setHeader("content-type", "application/json"); res.end('{"found":true,"pad":"' + "x".repeat(2 * 1024 * 1024 + 10) + '"}'); };
  const r = await check(["acme.example"]);
  assert.equal(r.status, 3);
  assert.ok(r.requests.every((x) => x.startsWith("web ")));
});

webServer.close();
dirServer.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
