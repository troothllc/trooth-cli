// bin/lib/log-trust.mjs - the verifier key of Trooth's witness statement log,
// pinned in this release so a checkpoint is checked against a key this
// package carries rather than one the log serves about itself.
// Copyright 2026 Trooth, LLC. Licensed under the Apache License, Version 2.0.
//
// The key is written here when a release is made (the publisher reads it
// from https://api.trooth.co/scan/log/v1/vkey and from the founder's own copy,
// and refuses to release when the two differ). A key change ships in a new
// release and in docs/KEY-CEREMONY.md, never silently. With no pinned key,
// the CLI uses the key the log serves and says so.
export const PINNED_LOG_VKEYS = [
  "trooth.co/witness-log/v1+06471ca9+AY9UdmLMbCX5Ib3ksDeoE8x3CburcWGJE9eJiPiYP5sZ",
];
