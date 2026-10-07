// Types for trooth/declaration (bin/lib/declaration.mjs). docs/DECLARATION.md describes the format and the rules.
import type { DomainDeclaration, DeclaredProduct, DeclaredApi } from './trooth.js';

export type { DomainDeclaration, DeclaredProduct, DeclaredApi };

export declare const DECLARATION_FORMAT: 'trooth.declaration.v1';
export declare const DECLARATION_PATH: '/.well-known/trooth.json';
export declare const MAX_DECLARATION_BYTES: number;
export declare const MAX_VALIDITY_DAYS: number;
export declare const DEFAULT_VALIDITY_DAYS: number;
export declare const REPOSITORY_HOSTS: readonly string[];
export declare const DOH_URL: string;
export declare const RECORD_PREFIX: string;

export interface Ed25519PublicJwk { kty: 'OKP'; crv: 'Ed25519'; x: string }
/** Keep it secret: `d` is the private key. */
export interface Ed25519PrivateJwk extends Ed25519PublicJwk { d: string }

export declare class DeclarationError extends Error {}

/** The RFC 7638 JWK thumbprint, base64url: SHA-256 over {"crv","kty","x"}. */
export declare function jwkThumbprint(jwk: Ed25519PublicJwk): string;
/** <domain>#<thumbprint>. */
export declare function keyIdFor(domain: string, jwk: Ed25519PublicJwk): string;
export declare function publicJwkOf(jwk: Ed25519PublicJwk | Ed25519PrivateJwk): Ed25519PublicJwk;
export declare function generateDeclarationKey(): { privateJwk: Ed25519PrivateJwk; publicJwk: Ed25519PublicJwk; thumbprint: string };
/** Parse a private JWK and check that x is the public half of d; throws DeclarationError. */
export declare function readPrivateJwk(input: string | object): Ed25519PrivateJwk;
/** `_trooth-key.<domain> TXT "trooth-key=<thumbprint>"`. */
export declare function pinLine(domain: string, thumbprint: string): string;
/** The RFC 8785 bytes the signature covers: the document without `signature`. */
export declare function signingBytes(doc: object): Uint8Array;
export declare function signDeclaration(doc: Omit<DomainDeclaration, 'signature'> | DomainDeclaration, privateJwk: Ed25519PrivateJwk | string): DomainDeclaration;
export declare function isoSeconds(ms: number): string;
/** Build and sign a declaration; throws DeclarationError when it would not check. */
export declare function buildDeclaration(opts: {
  domain: string;
  privateJwk: Ed25519PrivateJwk | string;
  now?: number;
  days?: number;
  record?: string | null;
  products?: DeclaredProduct[];
  apis?: DeclaredApi[];
  repositories?: string[];
  extraKeys?: Ed25519PublicJwk[];
}): DomainDeclaration;
export declare function hostInDomain(host: string, domain: string): boolean;

export interface DeclarationCheck {
  status: 'checked' | 'invalid' | 'expired';
  reason: string | null;
  problems: string[];
  signature: 'valid' | 'invalid' | 'not_checked';
  /** SHA-256 (hex) of the bytes checked. */
  sha256: string | null;
  domain: string | null;
  issued_at: string | null;
  expires_at: string | null;
  kid: string | null;
  keys: string[];
  thumbprints: string[];
  /** Only a 'checked' result carries the record and the subjects. */
  record: string | null;
  products: DeclaredProduct[];
  apis: DeclaredApi[];
  repositories: string[];
  /** False when read from a file with no domain to require. */
  host_checked: boolean;
}
/** Check a declaration (the bytes served, or a parsed object) against every rule. `domain` is the host it was served from. */
export declare function checkDeclaration(input: string | Uint8Array | object, opts?: { domain?: string | null; now?: number }): DeclarationCheck;
/** Whether a failed check is about the signature or its key (the CLI's exit 8) rather than the content (exit 9). */
export declare function isSignatureProblem(r: DeclarationCheck): boolean;

export interface DeclarationFetch {
  status: 'read' | 'absent' | 'invalid' | 'not_read';
  url: string;
  bytes?: Uint8Array;
  reason: string | null;
  http_status?: number;
}
/** GET https://<domain>/.well-known/trooth.json: no redirects, 64 KB at most, a deadline. */
export declare function fetchDeclaration(domain: string, opts?: { fetch?: typeof fetch; timeoutMs?: number; userAgent?: string }): Promise<DeclarationFetch>;

export interface KeyPin { status: 'present' | 'absent' | 'not_read'; name: string; thumbprints: string[]; reason: string | null }
/** The TXT records at _trooth-key.<domain>, read through DNS over HTTPS (application/dns-json). */
export declare function readKeyPin(domain: string, opts?: { fetch?: typeof fetch; timeoutMs?: number; dohUrl?: string }): Promise<KeyPin>;
export declare function txtValue(data: string): string;
export declare function pinStatus(pin: KeyPin, thumbprints: string[]): { pinned: boolean; state: 'matches' | 'other_key' | 'absent' | 'not_read' | 'present'; thumbprint: string | null };
