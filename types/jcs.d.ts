// Declarations for bin/lib/jcs.mjs: RFC 8785 under the v3 profile (integers only).
export declare class CanonicalizationError extends Error {}
export declare function canonicalize(value: unknown): string;
export declare function isCanonical(text: string): boolean;
