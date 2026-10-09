# Mirrors of the witness statement log

Version 1.0, October 8, 2026. Normative for `trooth mirror` and `trooth mirror --check` (bin/lib/mirror.mjs). Added in trooth 0.16.0.

Anyone can keep a full copy of Trooth's witness statement log ([LOG.md](LOG.md)) and serve it. A copy is useful because it does not depend on Trooth: if api.trooth.co is down, changed or gone, every statement the log ever held, and the signed checkpoints over them, can still be read and checked. Nothing in a mirror needs to be trusted. A reader checks it with the log key it already holds.

## 1. The layout

A mirror is a directory, or a static web host serving one, in the C2SP tlog-tiles layout ([c2sp.org/tlog-tiles](https://c2sp.org/tlog-tiles)), the layout Go's checksum database and Sigstore's Rekor v2 use:

| Path | Holds |
|---|---|
| `checkpoint` | The log's signed checkpoint, byte for byte as the log served it, with any witness cosignatures |
| `tile/entries/<N>[.p/<W>]` | Entry bundles: each entry is a big-endian uint16 length followed by the entry's bytes (LOG.md section 2), 256 entries to a full bundle |
| `tile/<L>/<N>[.p/<W>]` | Hash tiles of height 8: level 0 holds the leaf hashes, level L+1 the roots of each complete group of 256 hashes at level L |
| `mirror.json` | Who made the copy, when and from where. Informational only; nothing is checked against it |

`<N>` is the tile index in three-digit groups, every group but the last prefixed with `x` (`000`, `x001/234`). A tile that is not full has the suffix `.p/<W>`, its width. These are the same paths the log serves under `https://api.trooth.co/scan/log/v1`, so a client that reads the log's tiles reads a mirror by changing only the base URL.

## 2. Making and keeping one

```
trooth mirror ./trooth-log
```

The command reads the log's signed checkpoint and checks its signature with the log key pinned in the release (or `--log-vkey`). It then reads every entry bundle, rebuilds every leaf hash, recomputes the root (RFC 9162), and writes nothing unless that root is the signed root. It derives the hash tiles from the entries rather than copying them, and writes the checkpoint last, so a reader never sees a checkpoint ahead of its tiles.

Run it again and the mirror grows. It accepts the new tree only if the first entries, up to the size it already holds, hash to the root it already holds, so a mirror only ever grows by extension. A source that is smaller, or that rewrote history, is refused (exit 9) and the mirror is left as it was.

`--from <url or directory>` copies from another mirror instead of the log, with exactly the same checks, so a mirror of a mirror is as trustworthy as one made from the log.

Serve the directory as static files over HTTPS, from any host. Nothing else is needed.

## 3. Checking a mirror

```
trooth mirror --check https://mirror.example.org/trooth-log
trooth mirror --check ./trooth-log
```

A mirror is compatible when all of these hold:

1. Its checkpoint is signed by the log key.
2. Its entry bundles hold exactly the checkpoint's number of entries, and they hash to its root.
3. Every hash tile it serves is the tile its entries make.
4. The live log extends it: the live log is the same size with the same root, or larger, with a consistency proof (RFC 9162) from the mirror's tree to the live tree.

Any check that fails exits 9 and names it. A mirror or a live log that cannot be read at all (an unreachable URL, a checkpoint or entry bundle missing from a directory) exits 3, and a usage error (no mirror named, a path that is neither a directory nor an https URL) exits 2. Rule 4 also catches the opposite case: a live log that is smaller than a faithful mirror, or that shows a different root at the same size, is evidence of a split view or a lost tail. A mirror is evidence against the log, not only a copy of it.

## 4. Running one on a schedule

The trooth-cli repository mirrors the log once a day from GitHub's runners (`.github/workflows/log-mirror.yml`), checks the copy, and keeps it as a workflow artifact. That copy runs on infrastructure Trooth does not operate, but in Trooth's own GitHub organization, so it is not an independent mirror. The same workflow works unchanged in anyone else's repository:

```yaml
on:
  schedule: [{ cron: "41 5 * * *" }]
  workflow_dispatch:
permissions: { contents: read }
jobs:
  mirror:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/setup-node@v7
        with: { node-version: 22 }
      - uses: actions/cache/restore@v6
        with: { path: trooth-log, key: trooth-log-${{ github.run_id }}, restore-keys: trooth-log- }
      - run: npx --yes trooth@0.16.0 mirror trooth-log
      - run: npx --yes trooth@0.16.0 mirror --check trooth-log
      - uses: actions/cache/save@v6
        with: { path: trooth-log, key: trooth-log-${{ github.run_id }} }
```

Publish the directory with GitHub Pages, or any static host, and it is a public mirror.

## 5. Witnesses from other operators

A mirror keeps the history. A witness refuses to cosign a checkpoint that does not extend the last one it saw ([LOG.md](LOG.md) section 7). The log speaks the witness network's protocol (C2SP tlog-witness), so any operator who runs a witness that follows `trooth.co/witness-log/v1` with the verifier key at `/vkey` can cosign its checkpoints. No change at Trooth is needed beyond adding the operator's cosigner key to the list the log asks and the list `trooth` pins. An operator who wants to witness the log writes to security@trooth.co with its cosigner key.

## 6. Limits of this version

- A mirror holds the log's entries and checkpoints, not the companies' records or Trooth's readings. Each logged statement names its reading by SHA-256, so a reading kept anywhere can be checked against the mirror.
- `trooth mirror` reads the whole log on each run. At the log's present size that is under a megabyte. Partial updates come with a later release.
- Mirrors run by organizations other than Trooth: none is known as of this version.
