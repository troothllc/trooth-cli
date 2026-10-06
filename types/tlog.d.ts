// Declarations for bin/lib/tlog.mjs: checking Trooth's witness statement log (docs/LOG.md).
import type { WitnessStatement, LogReceipt } from './trooth.js';

export declare const LOG_ORIGIN: 'trooth.co/witness-log/v1';
export declare const ENTRY_KINDS: readonly ['witness_statement', 'correction'];
export declare const EMPTY_ROOT: Uint8Array;
export declare function leafHash(entry: Uint8Array): Uint8Array;
export declare function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array;
export declare function entryBytes(kind: 'witness_statement' | 'correction', statement: WitnessStatement): Uint8Array;
export declare function verifyInclusion(index: number | bigint, size: number | bigint, leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): boolean;
export declare function verifyConsistency(first: number | bigint, second: number | bigint, firstRoot: Uint8Array, secondRoot: Uint8Array, proof: Uint8Array[]): boolean;
export declare function noteKeyHash(name: string, publicKey: Uint8Array): Uint8Array;
export declare function parseVkey(vkey: string): { name: string; hash: Uint8Array; key: Uint8Array };
export declare function formatVkey(name: string, publicKey: Uint8Array): string;
export declare function verifyNote(note: string, vkey: string | { name: string; hash: Uint8Array; key: Uint8Array }): { text: string } | null;
export declare function parseCheckpoint(text: string): { origin: string; size: bigint; root: Uint8Array; extensions: string[] };
export declare function openCheckpoint(note: string, vkey: string, origin?: string): { origin: string; size: bigint; root: Uint8Array; extensions: string[] };
export declare function checkReceipt(input: { kind?: 'witness_statement' | 'correction'; statement: WitnessStatement; receipt: LogReceipt; vkeys: string[] }): { status: 'included' | 'checkpoint_invalid' | 'proof_invalid'; index: number | null; tree_size: number | null; reason: string };
export declare function rootOf(leaves: Uint8Array[]): Uint8Array;
export declare function inclusionPath(m: number, leaves: Uint8Array[]): Uint8Array[];
export declare function consistencyPath(m: number, leaves: Uint8Array[]): Uint8Array[];
export declare function toB64(hash: Uint8Array): string;
export declare function fromB64(s: string): Uint8Array | null;
