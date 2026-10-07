// Declarations for bin/lib/ids.mjs: Trooth stable identifiers (docs/IDS.md).
export type TroothIdType = 'domain' | 'reading' | 'key' | 'mapping' | 'statement' | 'entity' | 'cik' | 'lei' | 'jurisdiction' | 'registry' | 'uei' | 'repo' | 'api' | 'mcp' | 'contact' | 'company' | 'product' | 'person';
export declare const ID_TYPES: Readonly<Record<TroothIdType, RegExp>>;
export declare function formatId(type: TroothIdType, value: string): string;
export declare function parseId(id: string): { type: TroothIdType; value: string } | null;
export declare function statementId(payload: string): string;
