# What a company publishes, and what Trooth reads

Version 1.0, October 7, 2026. Normative for the public-record reading (`https://api.trooth.co/scan/public-record/<domain>`, [schema](../schemas/public-record.v1.schema.json), `trooth public-record`) and the reference list of evidence classes for the Trooth Network.

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
| security.txt (RFC 9116), its Contact and Expires | Read: S1, I14, I15 |
| TLS and HSTS, security headers, exposed `.env` or `.git`, server banner | Read: S2, S11 to S19 |
| Vulnerability disclosure, bug bounty, incident contact | Read: S7, S9, S5 |
| CAA, MX, SPF, DMARC | Read: S20, B16, B17, B18 |
| DMARC policy value, MTA-STS and its mode, SMTP TLS reporting, BIMI, DNSSEC | Read: public record `dns.*` |
| Status page, SLA, support, complaint channel, pricing, refunds | Read: B3 to B6, B8, B9, B11 to B15 |
| Legal entity named on site | Read: B14; the name itself, in public record `site.legal_names` |
| Copyright and trademark notices, DMCA contact, open-source notices, SBOM | Read: I5, I11, I12, I13, I16, I3 |
| Model card, training-data statements, AI disclosures, llms.txt, AI crawler rules | Read: A1, A2, A4, A5, A9, A11 to A16 |
| Accessibility statement, modern slavery statement | Not read |
| Investor-relations site: earnings releases, call transcripts, guidance, presentations | Not read (often behind bot protection; never guessed at) |
| Sustainability, ESG and climate reports | Not read |
| Trust center: SOC 2, ISO 27001, PCI attestations it lists | Declared |
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
| State or country business registry entry | The registry | Read only as the registry number the LEI record carries; B1 is declared |
| Federal contractor registration and exclusions | SAM.gov | Not read |
| Sanctions lists | OFAC and others | Not read |
| Patents and trademarks | USPTO, EUIPO | Declared (I4, I7) |
| Certificates issued for the domain | Certificate Transparency logs | Not read |
| Code and packages | GitHub, npm, PyPI | Not read |

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

- **Sources.** data.sec.gov and www.sec.gov with a named agent and contact address, as the SEC's fair-access rules ask; api.gleif.org; DNS over HTTPS; the company's home page and its terms, legal and privacy pages, until a legal name is found.
- **Safety.** Every request goes through the same guarded fetch as the witness reading: public addresses only, at most five redirects, bodies capped at 2 MB, of a filing only its first 256 KB. Pages are read as text with patterns; nothing in them runs. A site whose robots.txt names Trooth-Witness with `Disallow: /` is not read; the registries still are, because they are not the company's servers.
- **Limits.** An answer is cached for a day. Uncached readings: 3 a minute from one address, 6 an hour of one domain.
- **Absence.** Every source that was not read, or did not answer, is listed in `not_read` with the reason. A source not read is never filled in.
- **Not signed.** The reading is not signed and not logged in this version; each fact carries the URL to read it again from its source.

## 5. Limits of this version

- Foreign issuers reporting in IFRS: filings are listed, financial values are not read.
- Filing text (Items 1A, 1C, 3; exhibits) is linked, not read.
- The public record is served by the API and the command-line tool; it is not yet shown on the company's Trust Profile.
- Certificate Transparency, SAM.gov, sanctions lists, patent offices, code registries, investor-relations, sustainability and trust-center pages are not read.
