// bin/lib/profile.mjs - a company's Trust Profile, section by section, from
// the record projection (GET https://trooth.co/api/network/profile?q=<domain>
// &contract=2). Used by `trooth profile`. Pure functions: no network, no
// process state.
//
// WHERE EACH SECTION COMES FROM. The contract 2 body carries the complete
// profile as `profile` (format trooth.company-profile.v1): every section of
// the public Trust Profile page, in page order, each with a state, a
// provenance and its fields, groups and items. Its section ids are the names
// the MCP tool trooth_public_trust_profile takes, and they are the names
// --section takes here. The body also carries `facts`, the typed facts, each
// keyed <category>.<field> with its origin and, when Trooth recorded one, a
// date (claim.declaredAt for a company declaration, claim.observedAt for an
// observation). Typed fact categories map onto sections as SECTION_OF_CATEGORY
// says; a profile row is joined to the typed fact with the same label and the
// same value in the same section, and only then carries that fact's date.
// A row with no such fact has no recorded date and is printed "date unknown":
// no date is ever borrowed from the record's update time, a reading's time or
// another fact. A typed fact no row shows is added to its section, so nothing
// the record carries is dropped.
//
// Nothing here is signed. Trooth signs one object, the witness statement for
// a reading it took of the company's public surface; `trooth verify` checks it.

/** The section names, in the page's order: the MCP tool's names. */
export const SECTION_NAMES = Object.freeze([
  'overview', 'identity', 'history', 'funding', 'product', 'pricing', 'stack', 'security', 'privacy', 'ai',
  'hosting', 'infrastructure', 'procurement', 'relationships', 'proof', 'people', 'documents', 'evidence', 'cards', 'faq',
]);

/** Section titles as the page shows them, used only when a body carries no profile. */
export const SECTION_TITLES = Object.freeze({
  overview: 'Overview', identity: 'Company identity', history: 'Company history', funding: 'Company & funding',
  product: 'Product offering & demos', pricing: 'Commercial & pricing', stack: 'Integrations & stack', security: 'Security',
  privacy: 'Privacy', ai: 'AI practices', hosting: 'Data & hosting', infrastructure: 'Infrastructure & latency',
  procurement: 'Procurement', relationships: 'Relationships', proof: 'Customer proof', people: 'People',
  documents: 'Request documents', evidence: 'Evidence & history', cards: 'Trust cards', faq: 'Questions & answers',
});

/**
 * The typed fact categories (the part of a fact key before the dot, and the
 * values the API's ?sections= takes) and the section each one is shown in.
 * Each is also accepted by --section as another name for that section.
 */
export const SECTION_OF_CATEGORY = Object.freeze({
  identity: 'identity',
  registration: 'identity',
  hosting: 'hosting',
  recovery: 'hosting',
  pricing: 'pricing',
  'pricing-add-ons': 'pricing',
  security: 'security',
  privacy: 'privacy',
  'privacy-roles': 'privacy',
  'ai-practices': 'ai',
});

/** A section holding typed facts whose category no section above names. */
export const UNSORTED = 'unsorted';

export const STATES = Object.freeze(['published', 'not_published', 'hidden_by_company', 'unavailable', 'request_only']);
const PROVENANCES = new Set(['company_declared', 'trooth_observation', 'public_sources', 'named_customers', 'mixed']);
const ORIGINS = new Set(['company-declared', 'witnessed', 'public-source']);

/** Who said it, in words, for a section or group provenance. */
export const PROVENANCE_WORDS = Object.freeze({
  company_declared: 'the company (declared)',
  trooth_observation: 'Trooth (observed)',
  public_sources: 'public sources',
  named_customers: 'named customers',
  mixed: 'more than one source (see each group)',
});
/** What an empty or withheld section prints, by state. */
export const STATE_WORDS = Object.freeze({
  published: 'published',
  not_published: 'not published',
  hidden_by_company: 'hidden by the company',
  unavailable: 'unavailable on this read (not empty)',
  request_only: 'on request only',
});

/**
 * --section values (each may hold several names separated by commas) as
 * section names in page order. Returns { names } or { unknown } listing the
 * values that name no section.
 */
export function parseSectionArgs(values) {
  const asked = new Set();
  const unknown = [];
  for (const v of values) {
    for (const raw of String(v).split(',')) {
      const n = raw.trim().toLowerCase();
      if (!n) continue;
      if (SECTION_NAMES.includes(n)) asked.add(n);
      else if (Object.prototype.hasOwnProperty.call(SECTION_OF_CATEGORY, n)) asked.add(SECTION_OF_CATEGORY[n]);
      else unknown.push(raw.trim());
    }
  }
  if (unknown.length) return { unknown };
  return { names: SECTION_NAMES.filter((n) => asked.has(n)) };
}

const str = (v) => (typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v));
const isoOrNull = (v) => (typeof v === 'string' && v && !Number.isNaN(Date.parse(v)) ? v : null);

/** Who said a typed fact, in words. */
function originWords(f) {
  if (f.origin === 'company-declared') return 'the company (declared)';
  if (f.origin === 'witnessed') return 'Trooth (observed)';
  const issuer = f.record && f.record.issuer && typeof f.record.issuer.name === 'string' ? f.record.issuer.name : null;
  return issuer ? `public source: ${issuer}` : 'a public source';
}
const PROVENANCE_OF_ORIGIN = { 'company-declared': 'company_declared', witnessed: 'trooth_observation', 'public-source': 'public_sources' };

/** The date a typed fact carries, and what kind of date it is; never another field's. */
function factDate(f) {
  const claim = f && f.claim && typeof f.claim === 'object' ? f.claim : {};
  const declared = isoOrNull(claim.declaredAt);
  if (declared) return { date: declared, date_kind: 'declared' };
  const observed = isoOrNull(claim.observedAt);
  if (observed) return { date: observed, date_kind: 'observed' };
  return { date: null, date_kind: null };
}

function sectionOfKey(key) {
  const cat = str(key).split('.')[0];
  return Object.prototype.hasOwnProperty.call(SECTION_OF_CATEGORY, cat) ? SECTION_OF_CATEGORY[cat] : UNSORTED;
}

/** One printed fact. */
function makeFact({ label, value, group = null, item = null, provenance, said_by, source, typed = null, conflicts }) {
  const fact = {
    label: str(label),
    value: str(value),
    group,
    item,
    provenance,
    said_by,
    key: null,
    origin: null,
    source: source || null,
    date: null,
    date_kind: null,
    contested: false,
    accounts: [],
    signed: false,
  };
  if (typed) {
    fact.key = str(typed.key);
    fact.origin = ORIGINS.has(typed.origin) ? typed.origin : null;
    if (fact.origin) { fact.provenance = PROVENANCE_OF_ORIGIN[fact.origin]; fact.said_by = originWords(typed); }
    const ref = typed.record && typeof typed.record.sourceReference === 'string' && typed.record.sourceReference ? typed.record.sourceReference : null;
    if (ref) fact.source = ref;
    Object.assign(fact, factDate(typed));
    const c = conflicts.get(fact.key);
    if (typed.contested === true || c) {
      fact.contested = true;
      fact.accounts = (c && Array.isArray(c.accounts) ? c.accounts : [])
        .filter((a) => a && typeof a === 'object')
        .map((a) => ({ origin: ORIGINS.has(a.origin) ? a.origin : 'public-source', value: str(a.value) }));
    }
  }
  return fact;
}

/**
 * The sections of a contract 2 body, each { name, title, state, provenance,
 * said_by, meaning, url, facts, notes }, in page order, plus `unsorted` when
 * a typed fact names a category no section shows. `profilePresent` says
 * whether the body carried the complete profile; without it only the typed
 * facts are known and every other section is `unavailable`.
 */
export function buildSections(body) {
  const facts = Array.isArray(body.facts) ? body.facts.filter((f) => f && typeof f === 'object') : [];
  const conflicts = new Map((Array.isArray(body.conflicts) ? body.conflicts : []).filter((c) => c && typeof c.key === 'string').map((c) => [c.key, c]));
  const recordUrl = typeof body.canonicalUrl === 'string' ? body.canonicalUrl : null;

  // Typed facts by section, then by label and value, each used once.
  const pool = new Map();
  for (const f of facts) {
    const sec = sectionOfKey(f.key);
    if (!pool.has(sec)) pool.set(sec, []);
    pool.get(sec).push({ f, used: false });
  }
  const take = (sec, label, value) => {
    const list = pool.get(sec) || [];
    const hit = list.find((x) => !x.used && str(x.f.label) === str(label) && str(x.f.value) === str(value));
    if (!hit) return null;
    hit.used = true;
    return hit.f;
  };

  const profile = body.profile && typeof body.profile === 'object' && Array.isArray(body.profile.sections) ? body.profile : null;
  const byId = new Map();
  if (profile) for (const s of profile.sections) if (s && typeof s.id === 'string') byId.set(s.id, s);
  const ids = profile ? [...SECTION_NAMES.filter((n) => byId.has(n)), ...[...byId.keys()].filter((n) => !SECTION_NAMES.includes(n))] : [...SECTION_NAMES];

  const sections = [];
  for (const id of ids) {
    const s = byId.get(id);
    const out = {
      name: id,
      title: s && typeof s.title === 'string' ? s.title : (SECTION_TITLES[id] || id),
      state: s && STATES.includes(s.state) ? s.state : 'unavailable',
      provenance: s && PROVENANCES.has(s.provenance) ? s.provenance : null,
      said_by: null,
      meaning: s && typeof s.meaning === 'string' ? s.meaning : null,
      url: s && typeof s.url === 'string' ? s.url : recordUrl,
      facts: [],
      notes: [],
    };
    out.said_by = out.provenance ? PROVENANCE_WORDS[out.provenance] : null;
    if (s) {
      const secProv = out.provenance || 'company_declared';
      const row = (label, value, group, item, prov) => {
        const typed = take(id, label, value);
        out.facts.push(makeFact({ label, value, group, item, provenance: prov, said_by: PROVENANCE_WORDS[prov], source: out.url, typed, conflicts }));
      };
      for (const f of Array.isArray(s.fields) ? s.fields : []) row(f.label, f.value, null, null, secProv);
      for (const n of Array.isArray(s.notes) ? s.notes : []) out.notes.push({ group: null, item: null, text: str(n) });
      for (const g of Array.isArray(s.groups) ? s.groups : []) {
        if (!g || typeof g !== 'object') continue;
        const gt = str(g.title);
        const gp = PROVENANCES.has(g.provenance) ? g.provenance : secProv;
        for (const f of Array.isArray(g.fields) ? g.fields : []) row(f.label, f.value, gt, null, gp);
        for (const it of Array.isArray(g.items) ? g.items : []) {
          if (!it || typeof it !== 'object') continue;
          const itTitle = str(it.title);
          const fields = Array.isArray(it.fields) ? it.fields : [];
          const links = Array.isArray(it.links) ? it.links : [];
          // An item published by name only is one fact: the group, and the name.
          if (!fields.length && !links.length) row(gt, itTitle, gt, null, gp);
          for (const f of fields) row(f.label, f.value, gt, itTitle, gp);
          for (const l of links) row(l.label, l.value, gt, itTitle, gp);
          for (const n of Array.isArray(it.notes) ? it.notes : []) out.notes.push({ group: gt, item: itTitle, text: str(n) });
        }
        for (const n of Array.isArray(g.notes) ? g.notes : []) out.notes.push({ group: gt, item: null, text: str(n) });
      }
    }
    sections.push(out);
  }

  // Typed facts no row showed: added to their section, so none is dropped.
  // A section the company hid, or one shared on request only, takes none.
  const unsorted = [];
  for (const [sec, list] of pool) {
    for (const x of list) {
      if (x.used) continue;
      const target = sections.find((s) => s.name === sec);
      const fact = makeFact({ label: x.f.label, value: x.f.value, group: profile ? 'Other recorded facts' : null, item: null, provenance: 'company_declared', said_by: PROVENANCE_WORDS.company_declared, source: recordUrl, typed: x.f, conflicts });
      if (!target) { unsorted.push(fact); continue; }
      if (target.state === 'hidden_by_company' || target.state === 'request_only') continue;
      if (!profile && target.state === 'unavailable') {
        target.state = 'published';
      }
      target.facts.push(fact);
    }
  }
  if (!profile) {
    for (const s of sections) {
      if (s.state !== 'published') continue;
      const provs = [...new Set(s.facts.map((f) => f.provenance))];
      s.provenance = provs.length === 1 ? provs[0] : 'mixed';
      s.said_by = PROVENANCE_WORDS[s.provenance];
    }
  }
  if (unsorted.length) {
    const provs = [...new Set(unsorted.map((f) => f.provenance))];
    const prov = provs.length === 1 ? provs[0] : 'mixed';
    sections.push({ name: UNSORTED, title: 'Facts in no named section', state: 'published', provenance: prov, said_by: PROVENANCE_WORDS[prov], meaning: 'Typed facts whose category this CLI does not map to a section. Each carries who said it.', url: recordUrl, facts: unsorted, notes: [] });
  }
  return { sections, profilePresent: !!profile };
}

export const NOT_SIGNED = 'This profile is the company\'s own declared record, as Trooth publishes it; facts Trooth observed are labeled as such. It is not signed: Trooth signs one object, the witness statement for a reading it took of the company\'s public surface, and that statement covers the reading, not these facts.';

/** The date part of a fact, in words: "declared 2026-10-06" or "date unknown". */
export function dateWords(f) {
  if (!f.date) return 'date unknown';
  const d = new Date(f.date);
  const day = Number.isNaN(d.getTime()) ? f.date : d.toISOString().slice(0, 10);
  return `${f.date_kind === 'observed' ? 'observed' : 'declared'} ${day}`;
}

/** Continuation lines under their first, with no trailing spaces on a blank line. */
const indent = (s, pad) => str(s).split(/\r?\n/).map((l, i) => (i === 0 ? l : l.trim() ? pad + l : '')).join('\n');

/**
 * The profile as terminal text. `st` carries the color codes ({B, D, A, C, J, X});
 * every one is '' when color is off.
 */
export function renderText(doc, st) {
  const { B, D, A, C, J, X } = st;
  const lines = [];
  lines.push('', `${B}${doc.name}${X}   ${C}${doc.subject}${X}${doc.slug ? `   ${D}slug ${doc.slug}${X}` : ''}`);
  lines.push(`${D}Trust Profile:${X} ${doc.record.url || '(no page named)'}`);
  const meta = [];
  meta.push(doc.record.updated_at ? `record updated ${doc.record.updated_at}` : 'record update time not stated');
  if (doc.record.version !== null) meta.push(`record version ${doc.record.version}`);
  meta.push(`read ${doc.read_at}`);
  lines.push(`${D}${meta.join(' · ')}${X}`);
  lines.push('', `${A}${NOT_SIGNED}${X}`, `${A}Check that statement yourself: ${B}${doc.verify_with}${X}`);
  if (!doc.profile_present) lines.push('', `${A}This response carries no complete profile, only the typed facts; sections they do not cover read as unavailable on this read.${X}`);
  if (doc.requested_sections) lines.push('', `${D}Sections asked for: ${doc.requested_sections.join(', ')}${X}`);
  for (const s of doc.sections) {
    lines.push('', `${J}${B}== ${s.title}${X} ${D}(${s.name})${X} · ${s.state === 'published' ? STATE_WORDS.published : `${A}${STATE_WORDS[s.state]}${X}`}${s.said_by ? ` ${D}· ${s.said_by}${X}` : ''}`);
    if (s.meaning) lines.push(`   ${D}${indent(s.meaning, '   ')}${X}`);
    if (s.state !== 'published') {
      lines.push(`  ${STATE_WORDS[s.state]}`);
    } else if (!s.facts.length) {
      lines.push(`  ${D}no facts in this section${s.notes.length ? '; its notes follow' : ''}${X}`);
    }
    let lastHead = null;
    for (const f of s.facts) {
      const head = [f.group, f.item].filter(Boolean).join(' · ') || null;
      if (head !== lastHead) { if (head) lines.push(`  ${B}${head}${X}`); lastHead = head; }
      const pad = head ? '    ' : '  ';
      lines.push(`${pad}${f.label}: ${indent(f.value, pad + '  ')}`);
      const who = [`said by ${f.said_by}`, dateWords(f)];
      if (f.key) who.push(f.key);
      lines.push(`${pad}  ${D}${who.join(' · ')}${X}`);
      if (f.contested) {
        lines.push(`${pad}  ${A}contested: sources disagree, and Trooth does not choose between them${X}`);
        for (const a of f.accounts) lines.push(`${pad}    ${D}${a.origin}:${X} ${indent(a.value, pad + '      ')}`);
      }
    }
    if (s.notes.length) {
      lines.push(`  ${D}Notes${X}`);
      for (const n of s.notes) {
        const where = [n.group, n.item].filter(Boolean).join(' · ');
        lines.push(`  ${D}- ${where ? `${where}: ` : ''}${indent(n.text, '    ')}${X}`);
      }
    }
  }
  lines.push('', `${D}${doc.sections.length} section${doc.sections.length === 1 ? '' : 's'}; ${doc.sections.reduce((n, s) => n + s.facts.length, 0)} facts. Trooth does not grade, rate, rank or certify a company.${X}`, '');
  return lines.join('\n');
}

const mdEsc = (s) => str(s).replace(/([\\`*_[\]<>|])/g, '\\$1').replace(/\r?\n/g, ' ');

/** The profile as Markdown: the same content as the text form. */
export function renderMarkdown(doc) {
  const L = [];
  L.push(`# ${mdEsc(doc.name)} (${mdEsc(doc.subject)}): Trust Profile`, '');
  L.push(`> ${NOT_SIGNED} Check that statement yourself: \`${doc.verify_with}\`.`, '');
  L.push(`- Trust Profile: ${doc.record.url ? `<${doc.record.url}>` : 'no page named'}`);
  if (doc.slug) L.push(`- Slug: \`${doc.slug}\``);
  L.push(`- Record updated: ${doc.record.updated_at || 'not stated'}`);
  if (doc.record.version !== null) L.push(`- Record version: ${doc.record.version}`);
  L.push(`- Read: ${doc.read_at} (contract ${doc.contract})`);
  if (doc.requested_sections) L.push(`- Sections asked for: ${doc.requested_sections.join(', ')}`);
  if (!doc.profile_present) L.push('', '*This response carries no complete profile, only the typed facts; sections they do not cover read as unavailable on this read.*');
  for (const s of doc.sections) {
    L.push('', `## ${mdEsc(s.title)} (\`${s.name}\`)`, '');
    L.push(`*${STATE_WORDS[s.state]}${s.said_by ? ` · ${mdEsc(s.said_by)}` : ''}*${s.meaning ? `. ${mdEsc(s.meaning)}` : ''}`);
    if (s.state !== 'published') { L.push('', `${STATE_WORDS[s.state][0].toUpperCase()}${STATE_WORDS[s.state].slice(1)}.`); }
    else if (!s.facts.length) L.push('', 'No facts in this section.');
    let lastHead;
    for (const f of s.facts) {
      const head = [f.group, f.item].filter(Boolean).join(' · ') || null;
      if (head !== lastHead) { L.push(''); if (head) L.push(`### ${mdEsc(head)}`, ''); lastHead = head; }
      const meta = [`said by ${mdEsc(f.said_by)}`, dateWords(f)];
      if (f.key) meta.push(`\`${f.key}\``);
      L.push(`- **${mdEsc(f.label)}:** ${mdEsc(f.value)} (${meta.join('; ')})`);
      if (f.contested) {
        L.push('  - Contested: sources disagree, and Trooth does not choose between them.');
        for (const a of f.accounts) L.push(`  - ${a.origin}: ${mdEsc(a.value)}`);
      }
    }
    if (s.notes.length) {
      L.push('', '**Notes**', '');
      for (const n of s.notes) {
        const where = [n.group, n.item].filter(Boolean).map(mdEsc).join(' · ');
        L.push(`- ${where ? `${where}: ` : ''}${mdEsc(n.text)}`);
      }
    }
  }
  L.push('', '---', '', `${doc.sections.length} sections; ${doc.sections.reduce((n, s) => n + s.facts.length, 0)} facts. Trooth does not grade, rate, rank or certify a company.`, '');
  return L.join('\n');
}
