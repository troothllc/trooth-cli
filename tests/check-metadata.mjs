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

console.log('\ntwo licenses, each stated the same way everywhere (MCP27, 2026-11-14)');
is(pkg.license === 'Apache-2.0 AND FSL-1.1-ALv2', `package.json license is "Apache-2.0 AND FSL-1.1-ALv2" (got "${pkg.license}")`);
is(existsSync(join(ROOT, 'LICENSE')), 'a LICENSE file exists');
if (existsSync(join(ROOT, 'LICENSE'))) {
  const lic = read('LICENSE');
  is(/Apache License/.test(lic) && /Version 2\.0/.test(lic), 'LICENSE is the Apache License, Version 2.0');
}
const head = read('bin/trooth.mjs').slice(0, 800);
is(!/All rights reserved/i.test(head), 'the source header does not say "All rights reserved"');
is(/Apache License, Version 2\.0/.test(head), 'the source header names Apache-2.0');
// The guard decision engine is FSL-1.1-ALv2 from 0.24.0; every other source file stays Apache-2.0.
const ENGINE = ['bin/lib/guard.mjs', 'bin/lib/guard-decide.mjs', 'bin/lib/guard-policy.mjs', 'bin/lib/guard-evidence.mjs', 'bin/lib/guard-ci.mjs'];
is(existsSync(join(ROOT, 'LICENSE-FSL.md')), 'a LICENSE-FSL.md file exists');
if (existsSync(join(ROOT, 'LICENSE-FSL.md'))) {
  const fsl = read('LICENSE-FSL.md');
  is(/^# Functional Source License, Version 1\.1, ALv2 Future License\n/.test(fsl) && /\nFSL-1\.1-ALv2\n/.test(fsl), 'LICENSE-FSL.md is FSL-1.1-ALv2');
  is(/Copyright 2026 Trooth, LLC/.test(fsl) && !/\$\{/.test(fsl), 'LICENSE-FSL.md names Trooth, LLC and leaves no template field');
}
for (const f of ENGINE) {
  const h = read(f).slice(0, 600);
  is(h.startsWith('// SPDX-License-Identifier: FSL-1.1-ALv2\n') && /Functional Source License/.test(h) && !/Apache License, Version 2\.0\./.test(h), `${f} is marked FSL-1.1-ALv2`);
}
const { readdirSync } = await import('node:fs');
const others = readdirSync(join(ROOT, 'bin/lib')).filter((n) => n.endsWith('.mjs') && !ENGINE.includes(`bin/lib/${n}`)).map((n) => `bin/lib/${n}`)
  .concat(readdirSync(join(ROOT, 'bin/lib/guard')).map((n) => `bin/lib/guard/${n}`));
for (const f of others) is(!/FSL-1\.1/.test(read(f).slice(0, 600)), `${f} is not marked FSL (it stays Apache-2.0)`);
is(!/FSL/.test(read('SPECIFICATION-LICENSE.md').split('## The code')[0]), 'the specification (rules, schemas, formal model, vectors) stays open');
is((pkg.files || []).includes('LICENSE-FSL.md'), 'the published tarball carries LICENSE-FSL.md');
const readme = read('README.md');
is(/^## License$/m.test(readme), 'the README has a License section');
is(/Apache License 2\.0/.test(readme), 'the README names Apache-2.0');
is(/FSL-1\.1-ALv2/.test(readme) && /LICENSE-FSL\.md/.test(readme), 'the README names FSL-1.1-ALv2 for the guard engine');
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
