#!/usr/bin/env node
// bin/semanto.mjs - `semanto <tool>` is `trooth semanto <tool>` (tracker K1, 0.23.0): one binary, one login, one key.
process.argv.splice(2, 0, 'semanto');
await import('./trooth.mjs');
