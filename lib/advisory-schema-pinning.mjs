import { ADVISORY_SOURCE_TYPES } from './advisory-source-normalization.mjs';

export const ADVISORY_SCHEMA_PIN_REQUIREMENTS = Object.freeze({
  [ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT]: Object.freeze({
    standard: 'CSAF 2.0',
    requiredArtifacts: Object.freeze(['json_schema', 'schema_version', 'schema_digest', 'schema_source_url', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://docs.oasis-open.org/csaf/csaf/v2.0/']),
    parserRequirement: 'Use an official CSAF 2.0 JSON Schema bundle or a maintained CSAF validator pinned by version/digest.',
  }),
  [ADVISORY_SOURCE_TYPES.CSAF_VEX]: Object.freeze({
    standard: 'CSAF 2.0 VEX profile',
    requiredArtifacts: Object.freeze(['json_schema', 'schema_version', 'schema_digest', 'schema_source_url', 'profile_validation', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://docs.oasis-open.org/csaf/csaf/v2.0/']),
    parserRequirement: 'Use CSAF 2.0 schema validation plus VEX/profile validation for product_status semantics.',
  }),
  [ADVISORY_SOURCE_TYPES.OPENVEX]: Object.freeze({
    standard: 'OpenVEX',
    requiredArtifacts: Object.freeze(['json_schema', 'schema_version', 'schema_digest', 'schema_source_url', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://github.com/openvex/spec']),
    parserRequirement: 'Use the OpenVEX schema/spec pinned by release or commit digest before live ingestion.',
  }),
  [ADVISORY_SOURCE_TYPES.OSV]: Object.freeze({
    standard: 'OSV schema',
    requiredArtifacts: Object.freeze(['json_schema', 'schema_version', 'schema_digest', 'schema_source_url', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://ossf.github.io/osv-schema/']),
    parserRequirement: 'Use the OSV schema pinned by version/digest before live ingestion.',
  }),
  [ADVISORY_SOURCE_TYPES.NVD]: Object.freeze({
    standard: 'NVD CVE API 2.0 JSON schema/profile',
    requiredArtifacts: Object.freeze(['json_schema', 'schema_version', 'schema_digest', 'schema_source_url', 'api_version', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://nvd.nist.gov/developers/vulnerabilities']),
    parserRequirement: 'Use NVD API 2.0 schema/profile validation pinned to an API version and schema digest.',
  }),
  [ADVISORY_SOURCE_TYPES.RSS]: Object.freeze({
    standard: 'RSS 2.0',
    requiredArtifacts: Object.freeze(['xml_parser', 'parser_package_version', 'parser_lock_digest', 'doctype_entity_disabled', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://www.rssboard.org/rss-specification']),
    parserRequirement: 'Use a maintained XML/feed parser with external entity/DOCTYPE handling disabled and dependency lock evidence.',
  }),
  [ADVISORY_SOURCE_TYPES.ATOM]: Object.freeze({
    standard: 'Atom Syndication Format',
    requiredArtifacts: Object.freeze(['xml_parser', 'parser_package_version', 'parser_lock_digest', 'doctype_entity_disabled', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://www.rfc-editor.org/rfc/rfc4287']),
    parserRequirement: 'Use a maintained XML/feed parser with external entity/DOCTYPE handling disabled and dependency lock evidence.',
  }),
  [ADVISORY_SOURCE_TYPES.JSON_FEED]: Object.freeze({
    standard: 'JSON Feed 1.1',
    requiredArtifacts: Object.freeze(['json_schema_or_profile', 'schema_version', 'schema_digest', 'schema_source_url', 'drift_test_fixture']),
    recommendedSources: Object.freeze(['https://www.jsonfeed.org/version/1.1/']),
    parserRequirement: 'Use JSON Feed 1.1 profile/schema validation pinned by version/digest before live ingestion.',
  }),
});

const LIVE_FETCHER_SOURCE_TYPES = new Set(Object.keys(ADVISORY_SCHEMA_PIN_REQUIREMENTS));
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;

function normalizeArtifactName(value) {
  return String(value ?? '').trim().toLowerCase();
}

function normalizeArtifactMap(artifacts = []) {
  const map = new Map();
  for (const artifact of artifacts) {
    const name = normalizeArtifactName(artifact?.name ?? artifact?.type);
    if (!name) continue;
    map.set(name, artifact);
  }
  return map;
}

function isHttpsUrl(value) {
  try {
    return new URL(String(value ?? '')).protocol === 'https:';
  } catch {
    return false;
  }
}

function artifactHasPinEvidence(artifact) {
  if (!artifact || typeof artifact !== 'object') return false;
  return Boolean(
    (typeof artifact.digest === 'string' && DIGEST_PATTERN.test(artifact.digest))
      || (typeof artifact.packageVersion === 'string' && artifact.packageVersion.trim())
      || (typeof artifact.schemaVersion === 'string' && artifact.schemaVersion.trim())
      || (typeof artifact.apiVersion === 'string' && artifact.apiVersion.trim())
      || artifact.disabled === true,
  );
}

export function getAdvisorySchemaPinRequirement(sourceType) {
  return ADVISORY_SCHEMA_PIN_REQUIREMENTS[sourceType] ?? null;
}

export function advisorySourceRequiresSchemaPin(sourceType) {
  return LIVE_FETCHER_SOURCE_TYPES.has(sourceType);
}

export function validateAdvisorySchemaPinning({ sourceType, artifacts = [], driftTests = [], enabledForLiveFetch = false } = {}) {
  const requirement = getAdvisorySchemaPinRequirement(sourceType);
  if (!requirement) {
    return {
      ok: false,
      sourceType,
      errors: [`unsupported live advisory schema pinning source type: ${sourceType}`],
      requirement: null,
    };
  }

  const artifactMap = normalizeArtifactMap(artifacts);
  const errors = [];
  for (const required of requirement.requiredArtifacts) {
    const artifact = artifactMap.get(required);
    if (!artifact) {
      errors.push(`missing required schema/parser artifact: ${required}`);
      continue;
    }
    if (!artifactHasPinEvidence(artifact)) {
      errors.push(`schema/parser artifact lacks pin evidence: ${required}`);
    }
    if (artifact.sourceUrl && !isHttpsUrl(artifact.sourceUrl)) {
      errors.push(`schema/parser artifact sourceUrl must be HTTPS: ${required}`);
    }
    if (artifact.digest && !DIGEST_PATTERN.test(artifact.digest)) {
      errors.push(`schema/parser artifact digest must be sha256:<64 hex chars>: ${required}`);
    }
  }

  const hasDriftTest = driftTests.some((driftTest) => driftTest?.sourceType === sourceType && driftTest?.fixture && driftTest?.expectedOutcome === 'accepted');
  if (!hasDriftTest) {
    errors.push('missing accepted schema drift fixture test for live source type');
  }

  if (enabledForLiveFetch && errors.length > 0) {
    errors.unshift('live advisory fetcher cannot be enabled until schema/parser pins and drift tests are complete');
  }

  return {
    ok: errors.length === 0,
    sourceType,
    errors,
    requirement,
  };
}

export function assertAdvisorySchemaPinning(input) {
  const result = validateAdvisorySchemaPinning(input);
  if (!result.ok) {
    const error = new Error(result.errors.join('; '));
    error.code = 'advisory_schema_pinning_incomplete';
    error.result = result;
    throw error;
  }
  return result;
}

export function buildLiveFetcherReadinessRecord({ sourceType, artifacts = [], driftTests = [], enabledForLiveFetch = false, owner = null, notes = '' } = {}) {
  const validation = validateAdvisorySchemaPinning({ sourceType, artifacts, driftTests, enabledForLiveFetch });
  return {
    sourceType,
    standard: validation.requirement?.standard ?? null,
    enabledForLiveFetch: enabledForLiveFetch && validation.ok,
    requestedLiveFetch: Boolean(enabledForLiveFetch),
    ready: validation.ok,
    owner: owner ? String(owner).trim() : null,
    notes: String(notes ?? '').trim(),
    artifacts: artifacts.map((artifact) => ({
      name: normalizeArtifactName(artifact?.name ?? artifact?.type),
      sourceUrl: artifact?.sourceUrl ?? null,
      digest: artifact?.digest ?? null,
      schemaVersion: artifact?.schemaVersion ?? null,
      packageVersion: artifact?.packageVersion ?? null,
      apiVersion: artifact?.apiVersion ?? null,
      disabled: artifact?.disabled === true,
    })),
    driftTests: driftTests.map((driftTest) => ({
      sourceType: driftTest?.sourceType,
      fixture: driftTest?.fixture,
      expectedOutcome: driftTest?.expectedOutcome,
    })),
    errors: validation.errors,
  };
}
