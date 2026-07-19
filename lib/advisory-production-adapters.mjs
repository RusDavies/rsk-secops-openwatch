import { Buffer } from 'node:buffer';
import { ADVISORY_SOURCE_TYPES } from './advisory-source-normalization.mjs';
import {
  normalizeCsafDocumentFixture,
  normalizeFeedFixture,
  normalizeNvdFixture,
  normalizeOpenVexFixture,
  normalizeOsvFixture,
} from './advisory-fixture-parsers.mjs';

export const DEFAULT_ADVISORY_ADAPTER_LIMITS = Object.freeze({
  maxPayloadBytes: 512 * 1024,
  maxJsonDepth: 32,
  maxFeedItems: 50,
  timeoutMs: 2_000,
});

const SOURCE_KIND = Object.freeze({
  json: 'json',
  xml: 'xml',
});

const SOURCE_PROFILES = Object.freeze({
  [ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT]: { kind: SOURCE_KIND.json, parser: normalizeCsafDocumentFixture },
  [ADVISORY_SOURCE_TYPES.CSAF_VEX]: { kind: SOURCE_KIND.json, parser: normalizeCsafDocumentFixture },
  [ADVISORY_SOURCE_TYPES.OPENVEX]: { kind: SOURCE_KIND.json, parser: normalizeOpenVexFixture },
  [ADVISORY_SOURCE_TYPES.OSV]: { kind: SOURCE_KIND.json, parser: normalizeOsvFixture },
  [ADVISORY_SOURCE_TYPES.NVD]: { kind: SOURCE_KIND.json, parser: normalizeNvdFixture },
  [ADVISORY_SOURCE_TYPES.JSON_FEED]: { kind: SOURCE_KIND.json, parser: normalizeFeedFixture },
  [ADVISORY_SOURCE_TYPES.RSS]: { kind: SOURCE_KIND.xml, parser: normalizeFeedFixture },
  [ADVISORY_SOURCE_TYPES.ATOM]: { kind: SOURCE_KIND.xml, parser: normalizeFeedFixture },
});

const CSAF_ALLOWED_DOCUMENT_STATUSES = new Set(['draft', 'interim', 'final']);
const CSAF_ALLOWED_PRODUCT_STATUS_FIELDS = new Set([
  'first_affected',
  'first_fixed',
  'fixed',
  'known_affected',
  'known_not_affected',
  'last_affected',
  'recommended',
  'under_investigation',
]);
const OPENVEX_ALLOWED_STATUSES = new Set(['affected', 'fixed', 'not_affected', 'under_investigation']);
const OSV_ALLOWED_REFERENCE_TYPES = new Set(['ADVISORY', 'ARTICLE', 'DETECTION', 'DISCUSSION', 'REPORT', 'FIX', 'GIT', 'INTRODUCED', 'PACKAGE', 'WEB']);
const NVD_ALLOWED_STATUSES = new Set(['Awaiting Analysis', 'Undergoing Analysis', 'Analyzed', 'Modified', 'Deferred', 'Rejected']);

function byteLength(payload) {
  if (Buffer.isBuffer(payload)) return payload.byteLength;
  return Buffer.byteLength(typeof payload === 'string' ? payload : JSON.stringify(payload ?? null), 'utf8');
}

function elapsedMs(startedAt) {
  return Number(process.hrtime.bigint() - startedAt) / 1_000_000;
}

function fail(sourceType, code, message, detail = {}) {
  return {
    ok: false,
    sourceType,
    telemetry: {
      event: 'advisory_adapter_rejected_payload',
      sourceType,
      code,
      message,
      detail,
    },
    signal: null,
  };
}

function pass(sourceType, signal, detail = {}) {
  return {
    ok: true,
    sourceType,
    telemetry: {
      event: 'advisory_adapter_accepted_payload',
      sourceType,
      detail,
    },
    signal,
  };
}

function parseJsonPayload(payload) {
  if (Buffer.isBuffer(payload)) return JSON.parse(payload.toString('utf8'));
  if (typeof payload === 'string') return JSON.parse(payload);
  return payload;
}

function jsonDepth(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object') return 0;
  if (seen.has(value)) throw new Error('JSON payload must not contain circular references');
  seen.add(value);
  const children = Array.isArray(value) ? value : Object.values(value);
  return 1 + Math.max(0, ...children.map((child) => jsonDepth(child, seen)));
}

function asObject(value, label, errors) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) errors.push(`${label} must be an object`);
  return value ?? {};
}

function requireString(value, path, errors) {
  if (typeof value !== 'string' || value.trim() === '') errors.push(`${path} must be a non-empty string`);
}

function requireArray(value, path, errors) {
  if (!Array.isArray(value) || value.length === 0) errors.push(`${path} must be a non-empty array`);
}

function requireHttpsUrl(value, path, errors) {
  try {
    const parsed = new URL(String(value ?? ''));
    if (parsed.protocol !== 'https:') errors.push(`${path} must be an HTTPS URL`);
  } catch {
    errors.push(`${path} must be an HTTPS URL`);
  }
}

function validateCsaf(document, sourceType) {
  const errors = [];
  asObject(document, 'CSAF payload', errors);
  const tracking = document.document?.tracking;
  requireString(tracking?.id, 'document.tracking.id', errors);
  requireString(tracking?.current_release_date, 'document.tracking.current_release_date', errors);
  requireString(document.document?.publisher?.name, 'document.publisher.name', errors);
  if (tracking?.status && !CSAF_ALLOWED_DOCUMENT_STATUSES.has(tracking.status)) errors.push('document.tracking.status must be draft, interim, or final');
  requireArray(document.vulnerabilities, 'vulnerabilities', errors);
  const vulnerability = document.vulnerabilities?.[0] ?? {};
  requireString(vulnerability.cve, 'vulnerabilities[0].cve', errors);
  if (vulnerability.cve && !/^CVE-\d{4}-\d+$/i.test(vulnerability.cve)) errors.push('vulnerabilities[0].cve must be a CVE identifier');
  const productStatus = vulnerability.product_status ?? {};
  asObject(productStatus, 'vulnerabilities[0].product_status', errors);
  const statusFields = Object.keys(productStatus);
  if (statusFields.length === 0) errors.push('vulnerabilities[0].product_status must contain at least one source-native status field');
  for (const field of statusFields) {
    if (!CSAF_ALLOWED_PRODUCT_STATUS_FIELDS.has(field)) errors.push(`unsupported CSAF product_status field: ${field}`);
    if (!Array.isArray(productStatus[field]) || productStatus[field].length === 0) errors.push(`product_status.${field} must be a non-empty array`);
  }
  if (sourceType === ADVISORY_SOURCE_TYPES.CSAF_VEX && !('known_not_affected' in productStatus || 'known_affected' in productStatus || 'under_investigation' in productStatus || 'fixed' in productStatus)) {
    errors.push('CSAF VEX payload must carry an exploitability-oriented product status');
  }
  return errors;
}

function validateOpenVex(document) {
  const errors = [];
  asObject(document, 'OpenVEX payload', errors);
  requireString(document['@id'], '@id', errors);
  requireString(document.author, 'author', errors);
  requireArray(document.statements, 'statements', errors);
  const statement = document.statements?.[0] ?? {};
  requireString(statement.vulnerability?.name, 'statements[0].vulnerability.name', errors);
  if (statement.vulnerability?.name && !/^CVE-\d{4}-\d+$/i.test(statement.vulnerability.name)) errors.push('statements[0].vulnerability.name must be a CVE identifier');
  requireString(statement.status, 'statements[0].status', errors);
  if (statement.status && !OPENVEX_ALLOWED_STATUSES.has(statement.status)) errors.push('statements[0].status must be an OpenVEX status');
  requireArray(statement.products, 'statements[0].products', errors);
  return errors;
}

function validateOsv(document) {
  const errors = [];
  asObject(document, 'OSV payload', errors);
  requireString(document.id, 'id', errors);
  requireString(document.summary, 'summary', errors);
  requireString(document.modified, 'modified', errors);
  requireArray(document.affected, 'affected', errors);
  const affected = document.affected?.[0] ?? {};
  requireString(affected.package?.ecosystem, 'affected[0].package.ecosystem', errors);
  requireString(affected.package?.name, 'affected[0].package.name', errors);
  for (const alias of document.aliases ?? []) {
    if (!/^CVE-\d{4}-\d+$/i.test(alias) && !/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(alias)) errors.push(`unsupported OSV alias: ${alias}`);
  }
  for (const reference of document.references ?? []) {
    if (reference.type && !OSV_ALLOWED_REFERENCE_TYPES.has(reference.type)) errors.push(`unsupported OSV reference type: ${reference.type}`);
    if (reference.url) requireHttpsUrl(reference.url, 'references[].url', errors);
  }
  return errors;
}

function validateNvd(document) {
  const errors = [];
  asObject(document, 'NVD payload', errors);
  const cve = document.vulnerabilities?.[0]?.cve ?? document.cve;
  requireString(cve?.id, 'cve.id', errors);
  if (cve?.id && !/^CVE-\d{4}-\d+$/i.test(cve.id)) errors.push('cve.id must be a CVE identifier');
  requireArray(cve?.descriptions, 'cve.descriptions', errors);
  if (cve?.vulnStatus && !NVD_ALLOWED_STATUSES.has(cve.vulnStatus)) errors.push('cve.vulnStatus must be an NVD status');
  const references = cve?.references?.referenceData ?? cve?.references ?? [];
  for (const reference of references) {
    if (reference.url) requireHttpsUrl(reference.url, 'cve.references[].url', errors);
  }
  return errors;
}

function validateJsonFeed(document, limits) {
  const errors = [];
  asObject(document, 'JSON Feed payload', errors);
  requireString(document.version, 'version', errors);
  requireString(document.title, 'title', errors);
  requireArray(document.items, 'items', errors);
  if ((document.items?.length ?? 0) > limits.maxFeedItems) errors.push(`items exceeds maxFeedItems ${limits.maxFeedItems}`);
  const item = document.items?.[0] ?? {};
  requireString(item.id, 'items[0].id', errors);
  requireString(item.title, 'items[0].title', errors);
  if (item.url) requireHttpsUrl(item.url, 'items[0].url', errors);
  return errors;
}

function validateXmlFeed(xml, sourceType, limits) {
  const text = String(xml ?? '');
  const errors = [];
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) errors.push('XML feeds must not contain DOCTYPE or ENTITY declarations');
  if (sourceType === ADVISORY_SOURCE_TYPES.RSS && !/<rss\b/i.test(text)) errors.push('RSS payload must include an <rss> root');
  if (sourceType === ADVISORY_SOURCE_TYPES.ATOM && !/<feed\b/i.test(text)) errors.push('Atom payload must include a <feed> root');
  const itemCount = sourceType === ADVISORY_SOURCE_TYPES.ATOM ? (text.match(/<entry\b/gi) ?? []).length : (text.match(/<item\b/gi) ?? []).length;
  if (itemCount === 0) errors.push('feed payload must contain at least one item/entry');
  if (itemCount > limits.maxFeedItems) errors.push(`feed item count exceeds maxFeedItems ${limits.maxFeedItems}`);
  if (!/<title[\s>]/i.test(text)) errors.push('feed payload must contain a title');
  return errors;
}

function validateSourceDocument(sourceType, document, limits) {
  switch (sourceType) {
    case ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT:
    case ADVISORY_SOURCE_TYPES.CSAF_VEX:
      return validateCsaf(document, sourceType);
    case ADVISORY_SOURCE_TYPES.OPENVEX:
      return validateOpenVex(document);
    case ADVISORY_SOURCE_TYPES.OSV:
      return validateOsv(document);
    case ADVISORY_SOURCE_TYPES.NVD:
      return validateNvd(document);
    case ADVISORY_SOURCE_TYPES.JSON_FEED:
      return validateJsonFeed(document, limits);
    case ADVISORY_SOURCE_TYPES.RSS:
    case ADVISORY_SOURCE_TYPES.ATOM:
      return validateXmlFeed(document, sourceType, limits);
    default:
      return [`unsupported production advisory source type: ${sourceType}`];
  }
}

export function parseProductionAdvisoryPayload({
  sourceType,
  payload,
  sourceUrl,
  sourceName,
  vendorCandidate,
  observedAt,
  limits = {},
} = {}) {
  const startedAt = process.hrtime.bigint();
  const effectiveLimits = { ...DEFAULT_ADVISORY_ADAPTER_LIMITS, ...limits };
  const profile = SOURCE_PROFILES[sourceType];
  if (!profile) return fail(sourceType, 'unsupported_source_type', `Unsupported production advisory source type: ${sourceType}`);
  if (!sourceUrl) return fail(sourceType, 'missing_source_url', 'Production advisory payloads require a sourceUrl');
  const size = byteLength(payload);
  if (size > effectiveLimits.maxPayloadBytes) {
    return fail(sourceType, 'payload_too_large', `Payload exceeds maxPayloadBytes ${effectiveLimits.maxPayloadBytes}`, { bytes: size, maxPayloadBytes: effectiveLimits.maxPayloadBytes });
  }

  let parsed = payload;
  try {
    if (profile.kind === SOURCE_KIND.json) {
      parsed = parseJsonPayload(payload);
      const depth = jsonDepth(parsed);
      if (depth > effectiveLimits.maxJsonDepth) {
        return fail(sourceType, 'json_too_deep', `JSON payload exceeds maxJsonDepth ${effectiveLimits.maxJsonDepth}`, { depth, maxJsonDepth: effectiveLimits.maxJsonDepth });
      }
    } else {
      parsed = Buffer.isBuffer(payload) ? payload.toString('utf8') : String(payload ?? '');
    }
  } catch (error) {
    return fail(sourceType, 'parse_error', error.message, { bytes: size });
  }

  const validationErrors = validateSourceDocument(sourceType, parsed, effectiveLimits);
  if (validationErrors.length > 0) {
    return fail(sourceType, 'schema_validation_failed', 'Payload failed source-specific validation', { errors: validationErrors, bytes: size });
  }

  if (elapsedMs(startedAt) > effectiveLimits.timeoutMs) {
    return fail(sourceType, 'adapter_timeout', `Adapter validation exceeded timeoutMs ${effectiveLimits.timeoutMs}`, { elapsedMs: elapsedMs(startedAt), timeoutMs: effectiveLimits.timeoutMs });
  }

  try {
    const signal = profile.parser(parsed, { sourceType, sourceUrl, sourceName, vendorCandidate, observedAt });
    return pass(sourceType, signal, { bytes: size, elapsedMs: elapsedMs(startedAt) });
  } catch (error) {
    return fail(sourceType, 'normalization_error', error.message, { bytes: size });
  }
}

export function assertProductionAdvisoryPayload(input) {
  const result = parseProductionAdvisoryPayload(input);
  if (!result.ok) {
    const error = new Error(result.telemetry.message);
    error.code = result.telemetry.code;
    error.telemetry = result.telemetry;
    throw error;
  }
  return result.signal;
}
