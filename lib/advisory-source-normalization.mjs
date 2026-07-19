export const ADVISORY_SOURCE_TYPES = Object.freeze({
  CSAF_PROVIDER_METADATA: 'csaf_provider_metadata',
  CSAF_DOCUMENT: 'csaf_document',
  CSAF_VEX: 'csaf_vex',
  OPENVEX: 'openvex',
  OSV: 'osv',
  NVD: 'nvd',
  RSS: 'rss',
  ATOM: 'atom',
  JSON_FEED: 'json_feed',
  VENDOR_HTML: 'vendor_html',
  TRUST_CENTER: 'trust_center',
  CUSTOMER_AUTHENTICATED_PORTAL: 'customer_authenticated_portal',
  MANUAL_CUSTOMER_EVIDENCE: 'manual_customer_evidence',
  PARTNER_FEED: 'partner_feed',
});

export const ADVISORY_SIGNAL_CATEGORIES = Object.freeze([
  'vulnerability',
  'breach',
  'outage',
  'trust_posture',
  'compliance',
  'security_advisory',
  'other',
]);

export const ADVISORY_SIGNAL_STATUSES = Object.freeze([
  'new',
  'under_investigation',
  'affected',
  'not_affected',
  'fixed',
  'mitigated',
  'withdrawn',
  'informational',
  'unknown',
]);

export const PROPRIETARY_ADVISORY_EXCHANGE_STATUS = Object.freeze({
  allowedForMvp: false,
  reason: 'Use CSAF/VEX/OpenVEX/OSV/NVD/feed ingestion first; defer proprietary OpenWatch federation or customer-scoped feeds until beta evidence proves a gap.',
});

const STRUCTURED_SOURCE_TYPES = new Set([
  ADVISORY_SOURCE_TYPES.CSAF_PROVIDER_METADATA,
  ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
  ADVISORY_SOURCE_TYPES.CSAF_VEX,
  ADVISORY_SOURCE_TYPES.OPENVEX,
  ADVISORY_SOURCE_TYPES.OSV,
  ADVISORY_SOURCE_TYPES.NVD,
]);

const DISCOVERY_ONLY_SOURCE_TYPES = new Set([
  ADVISORY_SOURCE_TYPES.RSS,
  ADVISORY_SOURCE_TYPES.ATOM,
  ADVISORY_SOURCE_TYPES.JSON_FEED,
  ADVISORY_SOURCE_TYPES.VENDOR_HTML,
  ADVISORY_SOURCE_TYPES.TRUST_CENTER,
]);

const AUTHENTICATED_SOURCE_TYPES = new Set([
  ADVISORY_SOURCE_TYPES.CUSTOMER_AUTHENTICATED_PORTAL,
  ADVISORY_SOURCE_TYPES.MANUAL_CUSTOMER_EVIDENCE,
  ADVISORY_SOURCE_TYPES.PARTNER_FEED,
]);

const VALID_SOURCE_TYPES = new Set(Object.values(ADVISORY_SOURCE_TYPES));
const VALID_CATEGORIES = new Set(ADVISORY_SIGNAL_CATEGORIES);
const VALID_STATUSES = new Set(ADVISORY_SIGNAL_STATUSES);

function normalizeSourceType(sourceType) {
  const normalized = String(sourceType ?? '').trim().toLowerCase();
  if (!VALID_SOURCE_TYPES.has(normalized)) {
    throw new Error(`Unknown advisory source type: ${sourceType}`);
  }
  return normalized;
}

function normalizeUrl(url, fieldName = 'url') {
  if (!url) return null;
  const parsed = new URL(String(url));
  if (!['https:', 'http:'].includes(parsed.protocol)) {
    throw new Error(`${fieldName} must be an HTTP(S) URL`);
  }
  return parsed.toString();
}

function normalizeStringArray(values = []) {
  return [...new Set(values.map((value) => String(value).trim()).filter(Boolean))];
}

function clampConfidence(confidence) {
  if (confidence === null || confidence === undefined || confidence === '') return 0.5;
  const numeric = Number(confidence);
  if (Number.isNaN(numeric)) return 0.5;
  return Math.max(0, Math.min(1, numeric));
}

function normalizeDate(value, fieldName) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    throw new Error(`${fieldName} must be a valid date`);
  }
  return date.toISOString();
}

export function classifyAdvisorySource(sourceType) {
  const normalized = normalizeSourceType(sourceType);
  return {
    sourceType: normalized,
    structured: STRUCTURED_SOURCE_TYPES.has(normalized),
    discoveryOnly: DISCOVERY_ONLY_SOURCE_TYPES.has(normalized),
    requiresAuthentication: AUTHENTICATED_SOURCE_TYPES.has(normalized),
    canAuthorizeCustomerViewing: false,
  };
}

export function normalizeAdvisorySourceRegistration({
  sourceType,
  name,
  url,
  vendorId = null,
  vendorName = null,
  authentication = 'none',
  owner = null,
  notes = '',
}) {
  const classification = classifyAdvisorySource(sourceType);
  if (!name) throw new Error('Advisory source registration requires a name');
  const normalizedUrl = normalizeUrl(url);
  if (!normalizedUrl) throw new Error('Advisory source registration requires a URL');
  return {
    ...classification,
    name: String(name).trim(),
    url: normalizedUrl,
    vendorId,
    vendorName: vendorName ? String(vendorName).trim() : null,
    authentication: String(authentication || 'none').trim().toLowerCase(),
    owner: owner ? String(owner).trim() : null,
    notes: String(notes ?? '').trim(),
  };
}

export function normalizeAdvisorySignal({
  sourceType,
  sourceName,
  sourceUrl,
  observedAt,
  upstreamIds = {},
  vendorCandidate,
  affectedProducts = [],
  category = 'other',
  status = 'unknown',
  severity = null,
  confidence = 0.5,
  title,
  summary = '',
  remediation = '',
  references = [],
  revisions = [],
  raw = {},
}) {
  const classification = classifyAdvisorySource(sourceType);
  if (!sourceName || !sourceUrl || !vendorCandidate || !title) {
    throw new Error('Normalized advisory signals require sourceName, sourceUrl, vendorCandidate, and title');
  }
  const normalizedCategory = String(category ?? 'other').trim().toLowerCase();
  if (!VALID_CATEGORIES.has(normalizedCategory)) {
    throw new Error(`Unknown advisory signal category: ${category}`);
  }
  const normalizedStatus = String(status ?? 'unknown').trim().toLowerCase();
  if (!VALID_STATUSES.has(normalizedStatus)) {
    throw new Error(`Unknown advisory signal status: ${status}`);
  }
  return {
    ...classification,
    sourceName: String(sourceName).trim(),
    sourceUrl: normalizeUrl(sourceUrl, 'sourceUrl'),
    observedAt: normalizeDate(observedAt, 'observedAt') ?? new Date(0).toISOString(),
    upstreamIds: {
      cve: normalizeStringArray(upstreamIds.cve ?? []),
      csafDocumentTrackingId: upstreamIds.csafDocumentTrackingId ? String(upstreamIds.csafDocumentTrackingId).trim() : null,
      osvId: upstreamIds.osvId ? String(upstreamIds.osvId).trim() : null,
      nvdCveId: upstreamIds.nvdCveId ? String(upstreamIds.nvdCveId).trim() : null,
      feedGuid: upstreamIds.feedGuid ? String(upstreamIds.feedGuid).trim() : null,
      vendorAdvisoryId: upstreamIds.vendorAdvisoryId ? String(upstreamIds.vendorAdvisoryId).trim() : null,
      signatureId: upstreamIds.signatureId ? String(upstreamIds.signatureId).trim() : null,
    },
    vendorCandidate: String(vendorCandidate).trim(),
    affectedProducts: normalizeStringArray(affectedProducts),
    category: normalizedCategory,
    status: normalizedStatus,
    severity: severity ? String(severity).trim().toLowerCase() : null,
    confidence: clampConfidence(confidence),
    title: String(title).trim(),
    summary: String(summary ?? '').trim(),
    remediation: String(remediation ?? '').trim(),
    references: normalizeStringArray(references).map((reference) => normalizeUrl(reference, 'reference')),
    revisions: revisions.map((revision) => ({
      version: revision.version ? String(revision.version).trim() : null,
      date: normalizeDate(revision.date, 'revision.date'),
      summary: revision.summary ? String(revision.summary).trim() : '',
    })),
    raw,
  };
}
