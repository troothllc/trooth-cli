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
is(reported === `trooth ${pkg.version}`, `trooth --version prints the name and ${pkg.version} (got "${reported}")`);

console.log('\ndescription, against what npm actually stores');
const d = pkg.description;
is(d.length <= 250, `description is ${d.length} characters, npm keeps 255`);
is(!/[—–]/.test(d), 'description has no em or en dash');
is(/[.!?]$/.test(d), 'description ends on a complete sentence');

console.log('\none license, Apache-2.0, stated the same way everywhere (MCP27, 2026-11-14; FSL from 0.24.0 to 0.25.0 only)');
is(pkg.license === 'Apache-2.0', `package.json license is "Apache-2.0" (got "${pkg.license}")`);
is(existsSync(join(ROOT, 'LICENSE')), 'a LICENSE file exists');
if (existsSync(join(ROOT, 'LICENSE'))) {
  const lic = read('LICENSE');
  is(/Apache License/.test(lic) && /Version 2\.0/.test(lic), 'LICENSE is the Apache License, Version 2.0');
}
const head = read('bin/trooth.mjs').slice(0, 800);
is(!/All rights reserved/i.test(head), 'the source header does not say "All rights reserved"');
is(/Apache License, Version 2\.0/.test(head), 'the source header names Apache-2.0');
// The guard decision engine was FSL-1.1-ALv2 in 0.24.0 and 0.25.0; from 0.26.0 every file is Apache-2.0.
const ENGINE = ['bin/lib/guard.mjs', 'bin/lib/guard-decide.mjs', 'bin/lib/guard-policy.mjs', 'bin/lib/guard-evidence.mjs', 'bin/lib/guard-ci.mjs'];
for (const f of ENGINE) {
  const h = read(f).slice(0, 600);
  is(h.startsWith('// SPDX-License-Identifier: Apache-2.0\n') && /Apache License, Version 2\.0\./.test(h), `${f} is marked Apache-2.0`);
}
const { readdirSync } = await import('node:fs');
const all = readdirSync(join(ROOT, 'bin/lib')).filter((n) => n.endsWith('.mjs')).map((n) => `bin/lib/${n}`)
  .concat(readdirSync(join(ROOT, 'bin/lib/guard')).map((n) => `bin/lib/guard/${n}`));
for (const f of all) is(!/SPDX-License-Identifier: FSL/.test(read(f).slice(0, 600)), `${f} is not marked FSL`);
is(!existsSync(join(ROOT, 'LICENSE-FSL.md')), 'LICENSE-FSL.md is gone from the package');
is(!(pkg.files || []).includes('LICENSE-FSL.md'), 'the published tarball carries no LICENSE-FSL.md');
const readme = read('README.md');
is(/^## License$/m.test(readme), 'the README has a License section');
is(/Apache License 2\.0/.test(readme), 'the README names Apache-2.0');
is(/from 0\.26\.0 it is Apache-2\.0 again/.test(readme), 'the README says the engine is Apache-2.0 from 0.26.0');
is(!/Apache-2\.0 AND FSL/.test(readme + read('package.json') + read('npm-shrinkwrap.json')), 'no file still says Apache-2.0 AND FSL');
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
