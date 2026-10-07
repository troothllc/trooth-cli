// Declarations for bin/lib/jcs.mjs: RFC 8785 under the v3 profile (integers only).
export declare class CanonicalizationError extends Error {}
export declare function canonicalize(value: unknown): string;
export declare function isCanonical(text: string): boolean;
/** RFC 8785 for a public record reading: finite numbers in ECMAScript's shortest form (docs/EVIDENCE.md section 5). */
export declare function canonicalizeRecord(value: unknown): string;
