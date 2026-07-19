import {
  ADVISORY_SOURCE_TYPES,
  normalizeAdvisorySignal,
} from './advisory-source-normalization.mjs';

const CSAF_STATUS_PRIORITY = [
  ['known_not_affected', 'not_affected'],
  ['known_affected', 'affected'],
  ['fixed', 'fixed'],
  ['under_investigation', 'under_investigation'],
];

const OPENVEX_STATUS_MAP = Object.freeze({
  affected: 'affected',
  fixed: 'fixed',
  not_affected: 'not_affected',
  under_investigation: 'under_investigation',
});

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} fixture must be a JSON object`);
  }
  return value;
}

function firstText(value) {
  if (Array.isArray(value)) return value.map(firstText).find(Boolean) ?? '';
  if (value && typeof value === 'object') return firstText(value.text ?? value.value ?? value.title ?? value.summary);
  return String(value ?? '').trim();
}

function cveIdsFrom(values = []) {
  return [...new Set(values.map((value) => String(value ?? '').trim()).filter((value) => /^CVE-\d{4}-\d+$/i.test(value)))] ;
}

function csafStatusFromProductStatus(productStatus = {}) {
  for (const [csafField, normalized] of CSAF_STATUS_PRIORITY) {
    if (Array.isArray(productStatus[csafField]) && productStatus[csafField].length > 0) return normalized;
  }
  return 'unknown';
}

function csafProductsFromStatus(productStatus = {}) {
  return Object.values(productStatus).flatMap((value) => (Array.isArray(value) ? value : [])).map(String);
}

function csafRevisions(document = {}) {
  return (document.tracking?.revision_history ?? []).map((revision) => ({
    version: revision.number,
    date: revision.date,
    summary: revision.summary,
  }));
}

export function normalizeCsafDocumentFixture(document, context = {}) {
  const fixture = requireObject(document, 'CSAF document');
  const tracking = fixture.document?.tracking;
  const vulnerability = fixture.vulnerabilities?.[0];
  if (!tracking?.id || !vulnerability?.cve) {
    throw new Error('CSAF document fixture requires document.tracking.id and vulnerabilities[0].cve');
  }
  const notes = vulnerability.notes ?? fixture.document?.notes ?? [];
  return normalizeAdvisorySignal({
    sourceType: context.sourceType ?? ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
    sourceName: context.sourceName ?? fixture.document?.publisher?.name ?? 'CSAF document fixture',
    sourceUrl: context.sourceUrl,
    observedAt: context.observedAt ?? tracking.current_release_date,
    upstreamIds: {
      cve: cveIdsFrom([vulnerability.cve]),
      csafDocumentTrackingId: tracking.id,
      vendorAdvisoryId: fixture.document?.references?.[0]?.summary ?? null,
    },
    vendorCandidate: context.vendorCandidate ?? fixture.document?.publisher?.name ?? 'Unknown vendor',
    affectedProducts: csafProductsFromStatus(vulnerability.product_status),
    category: 'vulnerability',
    status: csafStatusFromProductStatus(vulnerability.product_status),
    severity: vulnerability.scores?.[0]?.cvss_v3?.baseSeverity ?? vulnerability.scores?.[0]?.cvss_v4?.baseSeverity ?? null,
    confidence: 0.9,
    title: vulnerability.title ?? fixture.document?.title,
    summary: firstText(notes),
    remediation: firstText(vulnerability.remediations?.[0]?.details ?? vulnerability.remediations?.[0]),
    references: (fixture.document?.references ?? []).map((reference) => reference.url).filter(Boolean),
    revisions: csafRevisions(fixture.document),
    raw: fixture,
  });
}

export function normalizeOpenVexFixture(document, context = {}) {
  const fixture = requireObject(document, 'OpenVEX');
  const statement = fixture.statements?.[0];
  if (!statement?.vulnerability?.name || !statement.status) {
    throw new Error('OpenVEX fixture requires statements[0].vulnerability.name and statements[0].status');
  }
  return normalizeAdvisorySignal({
    sourceType: ADVISORY_SOURCE_TYPES.OPENVEX,
    sourceName: context.sourceName ?? fixture.author ?? 'OpenVEX fixture',
    sourceUrl: context.sourceUrl,
    observedAt: context.observedAt ?? statement.timestamp ?? fixture.timestamp,
    upstreamIds: {
      cve: cveIdsFrom([statement.vulnerability.name]),
      vendorAdvisoryId: fixture['@id'] ?? null,
    },
    vendorCandidate: context.vendorCandidate ?? fixture.author ?? 'Unknown vendor',
    affectedProducts: [statement.products ?? []].flat().map((product) => product['@id'] ?? product).filter(Boolean),
    category: 'vulnerability',
    status: OPENVEX_STATUS_MAP[statement.status] ?? 'unknown',
    confidence: 0.85,
    title: `${statement.vulnerability.name} ${statement.status}`,
    summary: statement.justification ?? statement.action_statement ?? '',
    remediation: statement.action_statement ?? '',
    references: statement.vulnerability.aliases?.filter((alias) => /^https?:\/\//.test(alias)) ?? [],
    revisions: [{ version: fixture.version, date: statement.timestamp ?? fixture.timestamp, summary: 'OpenVEX statement' }],
    raw: fixture,
  });
}

export function normalizeOsvFixture(document, context = {}) {
  const fixture = requireObject(document, 'OSV');
  if (!fixture.id || !fixture.summary) throw new Error('OSV fixture requires id and summary');
  const affected = fixture.affected?.[0] ?? {};
  return normalizeAdvisorySignal({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    sourceName: context.sourceName ?? 'OSV fixture',
    sourceUrl: context.sourceUrl,
    observedAt: context.observedAt ?? fixture.modified ?? fixture.published,
    upstreamIds: {
      cve: cveIdsFrom(fixture.aliases ?? []),
      osvId: fixture.id,
    },
    vendorCandidate: context.vendorCandidate ?? affected.package?.ecosystem ?? 'Open source package',
    affectedProducts: [affected.package?.name, ...(affected.ranges ?? []).map((range) => range.type)].filter(Boolean),
    category: 'vulnerability',
    status: fixture.withdrawn ? 'withdrawn' : 'affected',
    severity: fixture.database_specific?.severity ?? fixture.severity?.[0]?.score ?? null,
    confidence: 0.85,
    title: fixture.summary,
    summary: fixture.details ?? fixture.summary,
    remediation: firstText(affected.versions?.length ? `Review affected versions: ${affected.versions.join(', ')}` : ''),
    references: (fixture.references ?? []).map((reference) => reference.url).filter(Boolean),
    revisions: [
      { version: 'published', date: fixture.published, summary: 'OSV published timestamp' },
      { version: 'modified', date: fixture.modified, summary: 'OSV modified timestamp' },
    ].filter((revision) => revision.date),
    raw: fixture,
  });
}

export function normalizeNvdFixture(document, context = {}) {
  const fixture = requireObject(document, 'NVD');
  const cve = fixture.vulnerabilities?.[0]?.cve ?? fixture.cve;
  if (!cve?.id || !Array.isArray(cve.descriptions)) {
    throw new Error('NVD fixture requires cve.id and cve.descriptions');
  }
  const description = cve.descriptions.find((entry) => entry.lang === 'en')?.value ?? cve.descriptions[0]?.value;
  const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData ?? cve.metrics?.cvssMetricV2?.[0]?.cvssData;
  return normalizeAdvisorySignal({
    sourceType: ADVISORY_SOURCE_TYPES.NVD,
    sourceName: context.sourceName ?? 'NVD fixture',
    sourceUrl: context.sourceUrl,
    observedAt: context.observedAt ?? cve.lastModified ?? cve.published,
    upstreamIds: {
      cve: cveIdsFrom([cve.id]),
      nvdCveId: cve.id,
    },
    vendorCandidate: context.vendorCandidate ?? 'NVD vendor candidate',
    affectedProducts: (cve.configurations ?? []).flatMap((configuration) => configuration.nodes ?? []).flatMap((node) => node.cpeMatch ?? []).map((match) => match.criteria).filter(Boolean),
    category: 'vulnerability',
    status: cve.vulnStatus === 'Rejected' ? 'withdrawn' : 'affected',
    severity: cvss?.baseSeverity ?? null,
    confidence: 0.8,
    title: cve.id,
    summary: description,
    references: (cve.references?.referenceData ?? cve.references ?? []).map((reference) => reference.url).filter(Boolean),
    revisions: [{ version: cve.sourceIdentifier, date: cve.lastModified ?? cve.published, summary: cve.vulnStatus }],
    raw: fixture,
  });
}

function xmlTag(xml, tag) {
  const match = String(xml).match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return match ? match[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, '').trim() : '';
}

function xmlAttribute(xml, tag, attribute) {
  const match = String(xml).match(new RegExp(`<${tag}[^>]*\\s${attribute}=["']([^"']+)["'][^>]*>`, 'i'));
  return match?.[1] ?? '';
}

export function normalizeFeedFixture(payload, context = {}) {
  const sourceType = context.sourceType;
  if (![ADVISORY_SOURCE_TYPES.RSS, ADVISORY_SOURCE_TYPES.ATOM, ADVISORY_SOURCE_TYPES.JSON_FEED].includes(sourceType)) {
    throw new Error('Feed fixture sourceType must be rss, atom, or json_feed');
  }

  if (sourceType === ADVISORY_SOURCE_TYPES.JSON_FEED) {
    const fixture = requireObject(payload, 'JSON Feed');
    const item = fixture.items?.[0];
    if (!item?.id || !item?.title) throw new Error('JSON Feed fixture requires items[0].id and items[0].title');
    return normalizeAdvisorySignal({
      sourceType,
      sourceName: context.sourceName ?? fixture.title ?? 'JSON Feed fixture',
      sourceUrl: context.sourceUrl ?? fixture.feed_url,
      observedAt: context.observedAt ?? item.date_modified ?? item.date_published,
      upstreamIds: { feedGuid: item.id, vendorAdvisoryId: item.id },
      vendorCandidate: context.vendorCandidate ?? fixture.title ?? 'Unknown vendor',
      category: 'security_advisory',
      status: 'informational',
      confidence: 0.6,
      title: item.title,
      summary: item.summary ?? item.content_text ?? '',
      references: [item.url].filter(Boolean),
      revisions: [{ version: item.id, date: item.date_modified ?? item.date_published, summary: 'Feed item timestamp' }],
      raw: fixture,
    });
  }

  const xml = String(payload ?? '');
  const isAtom = sourceType === ADVISORY_SOURCE_TYPES.ATOM;
  const itemBlock = isAtom ? xml.match(/<entry[\s\S]*?<\/entry>/i)?.[0] : xml.match(/<item[\s\S]*?<\/item>/i)?.[0];
  if (!itemBlock) throw new Error(`${sourceType} fixture requires at least one feed item`);
  const guid = isAtom ? xmlTag(itemBlock, 'id') : (xmlTag(itemBlock, 'guid') || xmlTag(itemBlock, 'link'));
  const link = isAtom ? (xmlAttribute(itemBlock, 'link', 'href') || xmlTag(itemBlock, 'link')) : xmlTag(itemBlock, 'link');
  return normalizeAdvisorySignal({
    sourceType,
    sourceName: context.sourceName ?? xmlTag(xml, 'title') ?? `${sourceType} fixture`,
    sourceUrl: context.sourceUrl,
    observedAt: context.observedAt ?? (isAtom ? xmlTag(itemBlock, 'updated') : xmlTag(itemBlock, 'pubDate')),
    upstreamIds: { feedGuid: guid, vendorAdvisoryId: guid },
    vendorCandidate: context.vendorCandidate ?? xmlTag(xml, 'title') ?? 'Unknown vendor',
    category: 'security_advisory',
    status: 'informational',
    confidence: 0.6,
    title: xmlTag(itemBlock, 'title'),
    summary: xmlTag(itemBlock, isAtom ? 'summary' : 'description'),
    references: [link].filter(Boolean),
    revisions: [{ version: guid, date: isAtom ? xmlTag(itemBlock, 'updated') : xmlTag(itemBlock, 'pubDate'), summary: 'Feed item timestamp' }],
    raw: { payload: xml },
  });
}
