# What a company publishes, and what Trooth reads

Version 1.4, October 7, 2026. Version 1.4 adds the proofs that bind a domain to its company record, its own key and its repositories, the domain-signed declaration, the company, product and person subjects, three continuity events and two evidence classes (section 11). Version 1.3 added the proof method of each binding, evidence classes with their stale-after days, continuity between readings, and the representative and signing authority subjects (section 10). Version 1.2 added SAM.gov registrations and exclusions, patent applications, four state business registries, FTC merger review, the domain's registration (RDAP), the changes those sources record, the subjects a reading names (section 7), and MCP tool description hashes (section 9). Version 1.1 added certificates in Certificate Transparency logs, security.txt, the pages a home page links to, the OFAC list, the entity id, the record of every source read, and the signed statement that names each reading (section 5). Normative for the public-record reading (`https://api.trooth.co/scan/public-record/<domain>`, [schema](../schemas/public-record.v1.schema.json), [statement schema](../schemas/public-record-statement.v1.schema.json), `trooth public-record`) and the reference list of evidence classes for the Trooth Network.

A company publishes about itself in three places: its own website and DNS, the regulators and registries it must file with, and outside parties that describe it. This document lists what is published in each, says for every item whether Trooth reads it today, and sets the rules for reading it. Nothing here grades, rates or ranks a company.

## 1. Who said it

Every fact Trooth carries is labelled with one of these, and they are never merged:

| Class | Meaning | Examples |
|---|---|---|
| `company_declaration` | The company's own statement on its Trooth record, published as written | Its stated certifications, its products |
| `trooth_observation` | Trooth read it from the company's public surface at a stated time; signed in the witness statement | The 100 checks of the Trooth Standard |
| `regulator_filing` | The company's statement to a regulator, as the regulator publishes it | A 10-K on SEC EDGAR, an 8-K item, an XBRL value |
| `registry_record` | A registry's record about the entity | The GLEIF LEI record, a state business registry number |
| `dns_record` | What the domain publishes in DNS | MTA-STS, BIMI, DNSSEC |
| `public_source` | A named third party | A news report, a certification body's list |

A `regulator_filing` is the company's own statement, made under the rules that govern filings. It is not Trooth's finding, and Trooth never restates it as one.

## 2. The inventory

"Read" names the check (Trooth Standard check id, in the witness statement) or the public-record field that carries it. "Declared" means it is held only as the company's declaration. "Not read" means Trooth holds nothing about it today.

### 2.1 On the company's own site and DNS

| What | Status |
|---|---|
| Privacy policy, terms, acceptable-use policy | Read: L1, L2, L3 |
| Cookie disclosure and consent | Read: L9, L11 |
| Data-subject contact, retention, transfers, children's data, governing law, breach notification | Read: L5, L10, L12, L15, L16, L17, L18 |
| Sub-processor list, DPA availability | Read: L13, L14 |
| Export-control statement, employee AI-use policy, COPPA disclosure | Read: L6, L7, L8 |
| security.txt (RFC 9116), its Contact and Expires | Read: S1, I14, I15; and public record `security_txt` (contacts, expiry, policy, canonical, whether clear-signed) |
| TLS and HSTS, security headers, exposed `.env` or `.git`, server banner | Read: S2, S11 to S19 |
| Vulnerability disclosure, bug bounty, incident contact | Read: S7, S9, S5 |
| CAA, MX, SPF, DMARC | Read: S20, B16, B17, B18 |
| DMARC policy value, MTA-STS and its mode, SMTP TLS reporting, BIMI, DNSSEC | Read: public record `dns.*` |
| Status page, SLA, support, complaint channel, pricing, refunds | Read: B3 to B6, B8, B9, B11 to B15 |
| Legal entity named on site | Read: B14; the name itself, in public record `site.legal_names` |
| Copyright and trademark notices, DMCA contact, open-source notices, SBOM | Read: I5, I11, I12, I13, I16, I3 |
| Model card, training-data statements, AI disclosures, llms.txt, AI crawler rules | Read: A1, A2, A4, A5, A9, A11 to A16 |
| Accessibility statement, modern slavery statement | Not read |
| Investor-relations site: earnings releases, call transcripts, guidance, presentations | Linked: public record `site.links` names the page when the home page links to it on the company's domain; its content is not read (often behind bot protection; never guessed at) |
| Sustainability, ESG and climate reports | Linked, not read (`site.links`) |
| Trust center: SOC 2, ISO 27001, PCI attestations it lists | Declared; the trust-center page is linked, not read (`site.links`) |
| Security advisories it publishes as a vendor | Not read |
| Careers pages, press releases, blog | Not read |
| Developer surfaces: OpenAPI documents, `.well-known` files | Read where the Standard asks (A14, I14); otherwise not read |

### 2.2 With regulators and registries

| What | Where | Status |
|---|---|---|
| SEC filer registration: name, CIK, tickers, exchanges, filer category, SIC, state of incorporation, fiscal year end, business address, phone, website on file, former names, LEI on file | data.sec.gov submissions | Read: public record `sec.facts` |
| Latest annual and quarterly reports (10-K, 10-Q; 20-F, 40-F for foreign issuers), proxy (DEF 14A), registration statements (S-1, S-3), conflict-minerals report (SD), 11-K, annual report to holders (ARS) | EDGAR | Read: public record `sec.latest`, with links |
| Current reports (8-K) and their item numbers, two years | EDGAR | Read: public record `sec.events` |
| Material cybersecurity incidents (8-K Item 1.05) | EDGAR | Read: public record `sec.cybersecurity_incidents` |
| Auditor changes (Item 4.01), non-reliance on earlier financial statements (Item 4.02) | EDGAR | Read: `sec.auditor_changes`, `sec.non_reliance` |
| Insider ownership forms (3, 4, 5) | EDGAR | Read as a count: `sec.insider_forms_last_90_days` |
| Annual revenue, net income, total assets, as filed in XBRL | data.sec.gov XBRL | Read: `sec.financials`, US-GAAP filers only |
| The authority of the company's XBRL extension taxonomy (normally its own domain) | The latest annual filing | Read: `sec.facts` key `sec.xbrl_namespace_authorities`; evidence for the domain binding |
| Cybersecurity risk management and governance (10-K Item 1C), risk factors (1A), legal proceedings (3) | The 10-K text | Not read in this version: linked through the 10-K |
| Officers, directors, auditor name, executive pay | Proxy and 10-K | Not read in this version: linked through the filings |
| Subsidiaries (Exhibit 21) | 10-K exhibits | Not read |
| Legal Entity Identifier record: legal name, other names, jurisdiction, legal form, business registry and number, status, addresses, registration dates, corroboration level | GLEIF | Read: public record `lei.facts` |
| Direct and ultimate parent | GLEIF | Read: `lei.direct_parent`, `lei.ultimate_parent` |
| State or country business registry entry | New York, Colorado, Connecticut and Oregon open-data registries; the registry number the LEI record carries | Read: public record `registries`, exact legal name; a name match is not an identification. Other states publish no open-data registry with a common query interface; B1 is declared |
| Federal contractor registration and exclusions | SAM.gov Entity and Exclusions APIs | Read when Trooth holds a SAM.gov key: public record `sam`, exact legal name, cached 30 days per name, at most 8 requests a day; a name match is not an identification |
| Merger review | FTC early termination notices under the Hart-Scott-Rodino Act | Read: public record `merger_review`, notices with a party of exactly the legal name, cached 7 days per name |
| Renames, acquisitions and dispositions (8-K Item 2.01), changes in control (Item 5.01), previous legal names, parents | EDGAR, GLEIF | Read: public record `changes`, with merger review and domain events, newest first |
| The domain's registration: registrar, registration, expiry, transfer | RDAP (RFC 9083) through rdap.org | Read: public record `domain_registration` |
| Sanctions lists | OFAC Specially Designated Nationals list | Read: public record `sanctions`, entities' primary names, exact name after folding; a name match is not an identification. Other lists are not read |
| Patents | USPTO Open Data Portal | Read when Trooth holds a USPTO key: public record `patents`, applications whose first applicant is the legal name, cached 7 days per name |
| Trademarks | USPTO, EUIPO | Declared (I4, I7); not read in this version |
| Certificates issued for the domain | Certificate Transparency logs, through the Cert Spotter monitor | Read: public record `certificates` (unexpired certificates for the exact name, issuers, newest and soonest-expiring) |
| Code repositories, APIs and MCP servers | The company's home page | Linked, not read: public record `subjects` (`repo`, `api`, `mcp` ids). An MCP server's tool list is read separately (section 9) |
| Packages | npm, PyPI | Not read |

### 2.3 Said by others

Ratings by third parties are not carried, because Trooth carries no grade of a company. News, analyst reports and app-store listings are not read.

## 3. Tying a domain to a legal entity

A public-record reading reports each identifier it finds as a **binding** between the domain and the identifier, with the evidence for and against it.

How an identifier is found:

1. `asked`: the requester named it (`?cik=`, `?lei=`).
2. `ticker`: the requester named a ticker, resolved through the SEC's ticker list.
3. `site_legal_name`: the legal name the site states in a copyright notice matches exactly one listed SEC filer, after case, punctuation and suffix spellings are folded (Inc and Incorporated, Corp and Corporation, and so on). Two or more matches: none is chosen.
4. `edgar_lei_field`: the SEC record carries the LEI.
5. `registry_name_match`: exactly one active LEI record carries the same legal name and, when the SEC gives a US state of incorporation, the same jurisdiction.

Evidence, and what it can establish:

| Kind | Ties the identifier to the domain? |
|---|---|
| `filing_namespace_names_domain`: the company's own latest annual filing declares its XBRL extension taxonomy under a host in the domain | Yes |
| `registry_lists_domain`: the SEC record's website or investor website is in the domain | Yes |
| `through_corroborated_filer`: the LEI record and a corroborated SEC filer name the same entity in the same jurisdiction | Yes, through the filer |
| `site_names_registry_name`: the site states the registry's legal name | No. Any site can state any company's name |
| `registries_agree`, `edgar_names_lei`: the SEC and the LEI registry agree with each other | No, they tie the identifiers to each other |
| `registry_lists_other_domain`, `registries_disagree`, `edgar_names_other_lei` | Against |

Status: `corroborated` when evidence that ties it is present; otherwise `contradicted` when there is evidence against; otherwise `claimed_by_site` when only the site names the entity; otherwise `registries_only`, `uncorroborated`, or `not_found` when the registry holds no such identifier. A look-alike site that copies a company's copyright line reaches `claimed_by_site`, never `corroborated` (the vector in the scan worker's tests).

## 4. How it is read

- **Sources.** data.sec.gov and www.sec.gov with a named agent and contact address, as the SEC's fair-access rules ask; api.gleif.org; DNS over HTTPS; api.certspotter.com; the OFAC SDN list (read at most once a day); api.sam.gov, api.uspto.gov and api.ftc.gov with Trooth's keys; data.ny.gov, data.colorado.gov, data.ct.gov and data.oregon.gov; rdap.org; the company's home page and its terms, legal and privacy pages, until a legal name is found, and its `/.well-known/security.txt`.
- **Safety.** Every request goes through the same guarded fetch as the witness reading: public addresses only, at most five redirects, bodies capped at 2 MB, of a filing only its first 256 KB. Pages are read as text with patterns; nothing in them runs. A site whose robots.txt names Trooth-Witness with `Disallow: /` is not read; the registries still are, because they are not the company's servers.
- **Limits.** An answer is cached for a day; `?cached=only` answers from the cache or 404 and never starts a reading. Uncached readings: 3 a minute from one address, 6 an hour of one domain. Once an hour Trooth also reads up to three Network companies whose cached reading is missing, so their Trust Profiles can show one.
- **Replay.** Every response read is listed in `sources` with its URL, status, the SHA-256 of the bytes read and whether the whole document was read. Trooth keeps those bytes under that hash, so a disputed fact can be replayed from what Trooth actually received.
- **Absence.** Every source that was not read, or did not answer, is listed in `not_read` with the reason. A source not read is never filled in.
- **Names.** SAM.gov, the USPTO, the state registries and the FTC are searched by the legal names the SEC and the LEI record hold (the site's own copyright name only when no registry names the company). A match is reported as a name match beside its source; it is not an identification.
- **Keys.** A key goes only in the request. Every URL in `sources` has any `api_key` value replaced with `REDACTED`, and no key appears in the reading, the statement or the log. A keyed source's answer is cached per name, so its `read_at` can be earlier than the reading's.
## 5. The signed statement

Each reading carries `signed`, which is not part of what it names:

1. `record_sha256` is SHA-256, hex, of the RFC 8785 bytes of the reading without `signed`. Numbers are written in ECMAScript's shortest form, as RFC 8785 specifies (a reading can carry a value that is not an integer); everything else follows the profile in [VERIFY.md](VERIFY.md) section 2.1.
2. `statement` is an envelope like a v3 witness statement: Ed25519 over RFC 8785 payload bytes, signed with Trooth's statement key, whose payload is a `trooth.public-record.v1` statement ([schema](../schemas/public-record-statement.v1.schema.json)) naming the domain, `read_at`, `record_sha256`, the entity id, each binding's id and status, how many sources were read, when it was issued, and the signer inside the signed bytes.
3. `log` is the receipt of that statement as a `public_record` entry of the witness statement log ([LOG.md](LOG.md) section 4), or null with the reason in `problem`.

A checker recomputes the hash from the reading, checks the payload names it (and the same domain, `read_at` and subject), checks the signature with a key on the published key list that was trusted at `issued_at`, and checks the receipt. `trooth public-record` does all four: it exits 8 when the signature or key does not hold and 9 when the reading is not the one named or the receipt does not check.

What the signature establishes: Trooth read these sources and got these answers at this time, and published that reading in this order. It does not establish that what the sources say is true, that a filing is accurate, or that a name match on a sanctions list is the same entity.

## 6. Limits of this version

- Foreign issuers reporting in IFRS: filings are listed, financial values are not read.
- Filing text (Items 1A, 1C, 3; exhibits) is linked, not read.
- The Trust Profile shows a reading when one was taken in the last day; otherwise the reader can ask for one there.
- SAM.gov is read for at most four names a day (its allowance for a key without a federal role is 10 requests); the others are listed under `not_read` and read on a later day. Trademarks are not read. State registries other than New York, Colorado, Connecticut and Oregon are not read. Code registries are not read; investor-relations, sustainability and trust-center pages are linked, not read.
- RDAP answers only for top-level domains whose registry publishes an RDAP service; some country-code registries do not.
- The FTC publishes early termination notices only for filings granted early termination; a merger reviewed to the end of its waiting period has no notice.
- Certificates are counted for the exact domain name only, from one CT monitor's first page.
- Only the OFAC SDN list's primary entity names are checked; aliases and other lists are not.

## 7. Changes and subjects

`changes` lists what the sources in a reading record as having changed, newest first, each with its date as the source gives it and where to read it: a former name on file with the SEC (`renamed`), a previous legal name in the LEI record, an 8-K reporting Item 2.01 (completion of an acquisition or disposition) or Item 5.01 (a change in control), a parent the LEI record names, an FTC early termination notice naming the company, and the domain's registration and last transfer. A change is the source's statement, not Trooth's finding.

`subjects` lists every subject the reading names, each with why ([IDS.md](IDS.md) 1.3): the domain; the entity, filer and LEI ids with their binding status; the jurisdictions the LEI record and the SEC record give; each state registry entry and SAM.gov UEI found by name (marked as name matches); and the code repositories, APIs and MCP servers the home page links to.

## 8. Reading the public record in the terminal

`trooth public-record <domain>` prints every section above and checks the signed statement (section 5). `--json` prints the reading with `cli_check`.

## 9. MCP tool description hashes

An agent decides what an MCP tool does from the description and schema the server lists. A server that changes a description after it was reviewed changes what agents do without anyone being told. Trooth reads the tool list of MCP servers with no credentials, over the streamable HTTP transport (`initialize`, `notifications/initialized`, `tools/list`, paged), and publishes ([schema](../schemas/mcp-tools.v1.schema.json)):

- for each tool, `description_sha256`, SHA-256 of the description's UTF-8 bytes, and `definition_sha256`, SHA-256 of the RFC 8785 bytes of the whole tool object as listed (name, title, description, input and output schemas, annotations, and anything else the server put there);
- `manifest_sha256`, SHA-256 of the RFC 8785 bytes of the list of `{name, definition_sha256}` sorted by name;
- the previous manifest and the tools added, removed or changed since.

A statement naming the reading ([statement schema](../schemas/mcp-tools-statement.v1.schema.json)) carries every tool's two hashes, the manifest and the reading's own RFC 8785 SHA-256; it is signed with Trooth's statement key and logged as an `mcp_tools` entry ([LOG.md](LOG.md) section 1) when the manifest is one Trooth has not logged before. A reading that finds the same manifest only moves `last_checked`. So the log is each server's history of tool changes, each with a receipt.

Trooth reads each server at most once a day. The servers read are listed at `https://api.trooth.co/scan/mcp-tools`; one server's newest reading is at `https://api.trooth.co/scan/mcp-tools/reading?endpoint=<url>`. `trooth mcp-tools <endpoint>` recomputes every description hash and the manifest, checks the statement and its log receipt, and with `--live` reads the server's tool list from the user's own machine and says whether it is the same, tool by tool (exit 9 when it is not).

What a hash establishes: the server listed exactly these bytes to a client with no credentials when Trooth read it. It does not establish what a tool does, that its description is accurate, or that the server lists the same tools to every client.

## 10. Proof methods, evidence classes, continuity and new subjects

These fields are additive: the format stays `trooth.public-record.v1`, and a reading taken before them simply does not carry them.

**Proof method.** Each binding carries `proof_method`, what ties the identifier to the domain, strongest first:

| `proof_method` | Meaning |
|---|---|
| `regulator_filing` | The company's own 10-K XBRL extension namespace names a host in the domain |
| `registry_record` | The registry record (the SEC record's website, or the LEI record) lists the domain |
| `site_statement` | The site states the legal name. This is the site's claim, and any site can state any name |
| `registry_name_match` | A name match between registries, or a registry search by name. Nothing ties the domain |
| `asked` | The caller supplied the identifier, and nothing above ties it |
| `none` | No evidence ties it |

An LEI tied through a corroborated SEC filer takes the filer's proof method.

**Evidence classes.** `evidence_classes` lists each class of evidence the reading can hold, kept apart, each with the record sections that hold it, `stale_after_days`, whether this reading read it (`read`), when the evidence was observed (`observed_at`: the reading's `read_at`, or a cached source's own earlier read time), `stale_after` (`observed_at` plus the days; null when not read) and a `does_not_establish` line saying in one sentence what that class of evidence does not show.

| Class | Sections | Stale after (days) |
|---|---|---|
| `regulator_filing` | `sec` | 90 |
| `registry_record` | `lei`, `registries` | 365 |
| `sanctions_list` | `sanctions` | 7 |
| `procurement_exclusion` | `sam` | 7 |
| `domain_registration` | `domain_registration` | 30 |
| `dns_configuration` | `dns` | 2 |
| `certificate_transparency` | `certificates` | 7 |
| `site_publication` | `site`, `security_txt` | 30 |
| `patent_record` | `patents` | 90 |
| `merger_review` | `merger_review` | 30 |

A reader that has no rule of its own takes evidence past `stale_after` as stale and reads again. The guard (`trooth guard`) uses these days when a policy rule gives no `max_age_days`.

**Continuity.** `continuity` compares this reading with the previous cached reading of the same domain. `previous` is that reading's `read_at` and `record_sha256`, or null when there is none. Each event in `events` has a `kind` and a `detail` naming both readings' values: `entity_changed`, `entity_appeared`, `entity_disappeared`, `renamed`, `parent_changed`, `registrar_changed`, `domain_transferred`, or a single `unchanged` when none of these differ. A changed entity is never merged: the new reading carries only what it read now, nothing from the earlier entity is carried over, and a parent named in the LEI record stays a separate legal entity.

**New subjects.** `subjects` gains two kinds:

- `representative`: a contact the site publishes in security.txt, named by a `contact` id ([IDS.md](IDS.md) 1.4), such as `trooth:contact:mailto:psirt@example.com` or `trooth:contact:security.example.com/report`. It is a contact the site publishes; it is not a person authorized to act for the entity. Contacts of other kinds (telephone, plain HTTP) are not kept, and a site that opted out of reading is not read for contacts.
- `signing_authority`: the key that signs this reading's statement, `trooth:key:<kid>`, filled in at signing. A reading with no signature names no signing authority.

## 11. Proofs and the domain-signed declaration

Added in version 1.4 (trooth 0.14.0). Additive: the format stays `trooth.public-record.v1`, and a reading taken before these fields does not carry them.

**Proof methods.** `bindings[].proof_method` and `proofs[].proof_method` gain five values:

| `proof_method` | Meaning |
|---|---|
| `dns_txt` | A TXT record in the domain's zone: Trooth's claim challenge at `_trooth-challenge.<domain>` with a value starting `trooth-domain-challenge=`, or the key pin `trooth-key=<thumbprint>` at `_trooth-key.<domain>` ([DECLARATION.md](DECLARATION.md) section 4) |
| `domain_signed_declaration` | A `/.well-known/trooth.json` that checks ([DECLARATION.md](DECLARATION.md)) |
| `identity_provider_sign_in` | The publisher signed in through the company's identity provider at the domain (a Google Workspace hosted domain or a Microsoft Entra tenant), as Trooth recorded at claim time |
| `domain_email_code` | A code sent to a mailbox at the domain, as Trooth recorded at claim time |
| `repository_control` | The code host marks a domain of the organization as confirmed by the code host: GitHub's `GET https://api.github.com/orgs/<org>` answers `is_verified: true` and its blog or website host is the domain or a subdomain. Read without authentication; a 403 or 404 is not read, never absent |

**Proofs.** `proofs` lists each proof that binds two subjects: `{ id, binds: [<subject id>, <subject id>], proof_method, status, detail, source, observed_at }`. `id` is `<proof kind>:<n>`. `status` is `confirmed` (the proof holds as read), `claimed` (asserted, and nothing read confirms it), `not_found` (looked for and not there) or `not_read` (the source could not be read). `source` is the URL read, or `trooth record` for Trooth's own record of a claim. The proofs a reading can carry:

- the domain and the company record (`trooth:company:<slug>`), by `dns_txt` (the challenge TXT is present), or by `identity_provider_sign_in`, `domain_email_code` or `dns_txt` from Trooth's record of the claim: the record projection's `authority.claim` (`{ method, confirmed_at, representative }`, absent on older deployments), confirmed when `confirmed_at` is set, observed at `confirmed_at`;
- the domain and the company's own key (`trooth:key:<domain>#<thumbprint>`), by `domain_signed_declaration`, and by `dns_txt` as a second proof when the key pin names the same key;
- the domain and a code repository (`trooth:repo:github.com/<org>`), by `repository_control`.

**The declaration.** `declaration` is null when the reading did not look for one, or `{ url, status, reason, sha256, issued_at, expires_at, keys, key_pinned_by_dns, products, apis, repositories }`. `status` is `checked`, `invalid`, `expired`, `absent` or `not_read`; `sha256` is of the bytes served. Only a declaration that checks carries `products`, `apis` and `repositories`, and only those reach `subjects`. The declaration is fetched only through the scan worker's fetch guard (DNS resolved, https only, no redirect to another host, 64 KB), and no URL inside it is followed.

**New subjects.** `subjects` gains three kinds and widens two:

- `company`: the company's Trooth record, `trooth:company:<slug>` ([IDS.md](IDS.md) 1.5). It names the record, not a legal entity.
- `product`: `trooth:product:<domain>/<id>`, with the basis "claimed by the domain's owner in its signed declaration". A product is never inferred from a name match.
- `person`: `trooth:person:<16 hex>`, the representative Trooth recorded at claim time. The id carries no personal data. It does not establish that the person may act for the legal entity.
- `signing_authority` also names the company's own key, `trooth:key:<domain>#<thumbprint>`, with the basis "the company's key, published at its domain in a declaration that checks, and logged in this reading".
- `api` also comes from the declaration ("named in the company's signed declaration", with the MCP manifest hash in the basis); `code_repository` is marked `repository_control` when that proof is confirmed.

**Continuity.** `continuity.events[].kind` gains `declaration_appeared` (a declaration that checks, where the previous reading had none), `declaration_key_changed` (its keys differ from the previous reading's) and `declaration_disappeared` (the previous reading had one that checked, and this one does not). Trooth's part is this record of the first key seen and every change, signed and logged.

**Evidence classes.**

| Class | Sections | Stale after (days) | Does not establish |
|---|---|---|---|
| `domain_declaration` | `declaration`, `proofs` | 30 | A key the site publishes shows who controlled the site's content when Trooth read it; it does not establish the legal entity or a person's authority to act for it. |
| `trooth_claim_record` | `proofs` | 365 | Domain control at claim time; it does not establish that the person may act for the legal entity. |

**In the terminal and the guard.** `trooth public-record` prints the declaration line and each proof with its method and status. The guard derives `domain_control_confirmed` from these proofs ([GUARD.md](GUARD.md) section 4): a proof binding the domain to the company record or to the declaration key, confirmed by `dns_txt`, `domain_email_code`, `identity_provider_sign_in` or `domain_signed_declaration`, fresh for its evidence class.
