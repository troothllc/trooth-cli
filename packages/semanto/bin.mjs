#!/usr/bin/env node
// semanto <tool> is trooth semanto <tool>: this package only installs trooth and hands over to it.
import { existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
const here = fileURLToPath(new URL(".", import.meta.url));
const found = [`${here}node_modules/trooth/bin/semanto.mjs`, `${here}../trooth/bin/semanto.mjs`].find((p) => existsSync(p));
if (!found) { console.error("semanto: the trooth package is not installed beside this one. Run: npm install -g trooth"); process.exit(1); }
await import(pathToFileURL(found).href);
