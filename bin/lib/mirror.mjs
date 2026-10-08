// Mirrors of the witness statement log (docs/MIRRORS.md).
//
// A mirror is a directory, or any static web host serving one, in the C2SP
// tlog-tiles layout (https://c2sp.org/tlog-tiles):
//
//   checkpoint                     the signed checkpoint, byte for byte as the log served it
//   tile/<L>/<N>[.p/<W>]           hash tiles, height 8, 32-byte SHA-256 hashes
//   tile/entries/<N>[.p/<W>]       entry bundles: big-endian uint16 length, then the entry
//   mirror.json                    who mirrored it, when, and from where (informational)
//
// Nothing in a mirror is trusted because of where it came from. A reader checks
// the checkpoint's signature with the log key it already holds, rebuilds every
// leaf hash from the entry bundles, and recomputes the root (RFC 9162). The hash
// tiles are derived from the entries, so a mirror that serves wrong tiles is
// caught the same way. Pure functions only: the CLI does the reading and writing.
import { leafHash, nodeHash, rootOf } from './tlog.mjs';

export const TILE_WIDTH = 256;

/** C2SP tile index path: 3-digit groups, every group but the last prefixed with x. */
export function tileIndexPath(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`bad tile index ${n}`);
  const s = String(n);
  const groups = [];
  let rest = s;
  while (rest.length > 3) { groups.unshift(rest.slice(-3)); rest = rest.slice(0, -3); }
  groups.unshift(rest.padStart(3, '0'));
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join('/');
}

/** The path of tile (level, index) of a tree of `width` hashes at that tile: full, or partial. */
export function tilePath(level, index, width) {
  const base = level === 'entries' ? `tile/entries/${tileIndexPath(index)}` : `tile/${level}/${tileIndexPath(index)}`;
  return width === TILE_WIDTH ? base : `${base}.p/${width}`;
}

/** The entry bundles a tree of `size` entries needs, with their widths. */
export function entryBundles(size) {
  const out = [];
  for (let i = 0; i * TILE_WIDTH < size; i++) out.push({ index: i, width: Math.min(TILE_WIDTH, size - i * TILE_WIDTH) });
  return out;
}

export function parseBundle(buf, expected) {
  const entries = [];
  let o = 0;
  while (o < buf.length) {
    if (o + 2 > buf.length) throw new Error('entry bundle ends inside a length prefix');
    const n = buf.readUInt16BE(o);
    if (o + 2 + n > buf.length) throw new Error('entry bundle ends inside an entry');
    entries.push(Buffer.from(buf.subarray(o + 2, o + 2 + n)));
    o += 2 + n;
  }
  if (expected !== undefined && entries.length !== expected) throw new Error(`entry bundle holds ${entries.length} entries, expected ${expected}`);
  return entries;
}

export function encodeBundle(entries) {
  return Buffer.concat(entries.flatMap((e) => {
    if (e.length > 0xffff) throw new Error('entry too long for a bundle');
    const len = Buffer.alloc(2); len.writeUInt16BE(e.length);
    return [len, e];
  }));
}

/**
 * Every hash tile of a tree, from its leaf hashes: level 0 holds the leaves,
 * level L+1 the roots of each complete 256-wide group at level L.
 * Returns [{ level, index, width, bytes }].
 */
export function hashTiles(leaves) {
  const tiles = [];
  let level = 0;
  let hashes = leaves.map((h) => Buffer.from(h));
  while (hashes.length > 0) {
    for (let i = 0; i * TILE_WIDTH < hashes.length; i++) {
      const slice = hashes.slice(i * TILE_WIDTH, (i + 1) * TILE_WIDTH);
      tiles.push({ level, index: i, width: slice.length, bytes: Buffer.concat(slice) });
    }
    const up = [];
    for (let i = 0; (i + 1) * TILE_WIDTH <= hashes.length; i++) up.push(rootOf(hashes.slice(i * TILE_WIDTH, (i + 1) * TILE_WIDTH)));
    hashes = up;
    level++;
  }
  return tiles;
}

/** Leaf hashes and root of a list of entries. */
export function treeOf(entries) {
  const leaves = entries.map((e) => leafHash(e));
  return { leaves, root: rootOf(leaves) };
}

export { nodeHash };
