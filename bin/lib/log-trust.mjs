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

// The witnesses whose cosignatures `trooth log checkpoint` and `trooth log
// monitor` count (docs/LOG.md section 7): the staging witnesses of the
// witness network (witness-network.org) that cosign with Ed25519. A key here
// changes only in a release, like the log key.
export const PINNED_WITNESSES = [
  { operator: 'Geomys', vkey: 'witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G' },
  { operator: 'Mullvad VPN AB', vkey: 'witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv' },
  { operator: 'TrustFabric (transparency.dev)', vkey: 'staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL' },
];
