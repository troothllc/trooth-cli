// One license, one version, one description: asserted, not assumed.
//
// This package says what it is in five places: package.json, the LICENSE file,
// the copyright header in bin/trooth.mjs, the README, and whatever npm ends up
// displaying. Before this file existed they disagreed: package.json said MIT,
// LICENSE said Apache-2.0, and the source header said "All rights reserved".
// Three answers to one question, in a repository belonging to a company whose
// product is one answer per company. This test is here so that cannot recur.
//
// It also holds the line that npm silently enforces and does not tell you about:
// a description longer than 255 characters is stored truncated, mid-word.

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const pkg  = JSON.parse(read('package.json'));

let failed = 0;
const ok   = (m) => console.log('  ok    ' + m);
const bad  = (m) => { failed++; console.error('  FAIL  ' + m); };
const is   = (cond, m) => (cond ? ok(m) : bad(m));

console.log('\npackage identity');
is(pkg.name === 'trooth', `name is "trooth" (got "${pkg.name}")`);
is(/^\d+\.\d+\.\d+$/.test(pkg.version), `version is a release version (got "${pkg.version}")`);

const reported = execFileSync(process.execPath, [join(ROOT, 'bin/trooth.mjs'), '--version'], { encoding: 'utf8' }).trim();
is(reported === pkg.version, `trooth --version prints ${pkg.version} (got "${reported}")`);

console.log('\ndescription, against what npm actually stores');
const d = pkg.description;
is(d.length <= 250, `description is ${d.length} characters, npm keeps 255`);
is(!/[—–]/.test(d), 'description has no em or en dash');
is(/[.!?]$/.test(d), 'description ends on a complete sentence');

console.log('\none license, stated the same way everywhere');
is(pkg.license === 'Apache-2.0', `package.json license is Apache-2.0 (got "${pkg.license}")`);
is(existsSync(join(ROOT, 'LICENSE')), 'a LICENSE file exists');
if (existsSync(join(ROOT, 'LICENSE'))) {
  const lic = read('LICENSE');
  is(/Apache License/.test(lic) && /Version 2\.0/.test(lic), 'LICENSE is the Apache License, Version 2.0');
}
const head = read('bin/trooth.mjs').slice(0, 800);
is(!/All rights reserved/i.test(head), 'the source header does not say "All rights reserved"');
is(/Apache License, Version 2\.0/.test(head), 'the source header names Apache-2.0');
const readme = read('README.md');
is(/^## License$/m.test(readme), 'the README has a License section');
is(/Apache License 2\.0/.test(readme), 'the README names Apache-2.0');
is((pkg.files || []).includes('LICENSE'), 'the published tarball carries the LICENSE');

console.log('\nthe repository this package claims to come from');
const url = (pkg.repository || {}).url || '';
is(url === 'git+https://github.com/troothllc/trooth-cli.git', `repository is this repo (got "${url}")`);

console.log('\nlint is deterministic, which is the only reason its digest is worth recording');
const runDigest = () => JSON.parse(execFileSync(
  process.execPath,
  [join(ROOT, 'bin/trooth.mjs'), 'lint', join(ROOT, 'tests/fixtures/infra'), '--json'],
  { encoding: 'utf8' },
)).digest;
const a = runDigest(), b = runDigest();
is(a === b, `the same tree digests the same twice (${a.slice(0, 22)}...)`);

console.log('');
if (failed) { console.error(`${failed} check(s) failed\n`); process.exit(1); }
console.log('all metadata checks passed\n');
