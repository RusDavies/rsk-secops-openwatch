import test from 'node:test';
import assert from 'node:assert/strict';
import { ADVISORY_SOURCE_TYPES } from '../lib/advisory-source-normalization.mjs';
import {
  ADVISORY_SCHEMA_PIN_REQUIREMENTS,
  advisorySourceRequiresSchemaPin,
  assertAdvisorySchemaPinning,
  buildLiveFetcherReadinessRecord,
  getAdvisorySchemaPinRequirement,
  validateAdvisorySchemaPinning,
} from '../lib/advisory-schema-pinning.mjs';

const DIGEST = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function jsonArtifacts(extra = []) {
  return [
    { name: 'json_schema', sourceUrl: 'https://standards.example/schema.json', digest: DIGEST },
    { name: 'schema_version', schemaVersion: '1.0.0' },
    { name: 'schema_digest', digest: DIGEST },
    { name: 'schema_source_url', sourceUrl: 'https://standards.example/schema.json', digest: DIGEST },
    { name: 'drift_test_fixture', digest: DIGEST },
    ...extra,
  ];
}

function xmlArtifacts() {
  return [
    { name: 'xml_parser', packageVersion: 'feed-parser@1.2.3' },
    { name: 'parser_package_version', packageVersion: 'feed-parser@1.2.3' },
    { name: 'parser_lock_digest', digest: DIGEST },
    { name: 'doctype_entity_disabled', disabled: true },
    { name: 'drift_test_fixture', digest: DIGEST },
  ];
}

function driftTest(sourceType) {
  return [{ sourceType, fixture: `tests/fixtures/advisory-sources/${sourceType}.fixture`, expectedOutcome: 'accepted' }];
}

test('schema pinning registry covers every source type eligible for future live fetching', () => {
  const expected = [
    ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
    ADVISORY_SOURCE_TYPES.CSAF_VEX,
    ADVISORY_SOURCE_TYPES.OPENVEX,
    ADVISORY_SOURCE_TYPES.OSV,
    ADVISORY_SOURCE_TYPES.NVD,
    ADVISORY_SOURCE_TYPES.RSS,
    ADVISORY_SOURCE_TYPES.ATOM,
    ADVISORY_SOURCE_TYPES.JSON_FEED,
  ];

  assert.deepEqual(Object.keys(ADVISORY_SCHEMA_PIN_REQUIREMENTS).sort(), expected.sort());
  for (const sourceType of expected) {
    const requirement = getAdvisorySchemaPinRequirement(sourceType);
    assert.ok(requirement.standard);
    assert.ok(requirement.requiredArtifacts.length >= 5);
    assert.ok(requirement.recommendedSources.every((source) => source.startsWith('https://')));
    assert.equal(advisorySourceRequiresSchemaPin(sourceType), true);
  }
  assert.equal(advisorySourceRequiresSchemaPin(ADVISORY_SOURCE_TYPES.VENDOR_HTML), false);
});

test('CSAF VEX live fetchers require both CSAF schema pins and profile validation evidence', () => {
  const result = validateAdvisorySchemaPinning({
    sourceType: ADVISORY_SOURCE_TYPES.CSAF_VEX,
    artifacts: jsonArtifacts([{ name: 'profile_validation', digest: DIGEST }]),
    driftTests: driftTest(ADVISORY_SOURCE_TYPES.CSAF_VEX),
    enabledForLiveFetch: true,
  });

  assert.equal(result.ok, true);
  assert.equal(result.requirement.standard, 'CSAF 2.0 VEX profile');
});

test('OpenVEX, OSV, NVD, and JSON Feed schema pins validate with source-specific required artifacts', () => {
  const cases = [
    [ADVISORY_SOURCE_TYPES.OPENVEX, jsonArtifacts()],
    [ADVISORY_SOURCE_TYPES.OSV, jsonArtifacts()],
    [ADVISORY_SOURCE_TYPES.NVD, jsonArtifacts([{ name: 'api_version', apiVersion: '2.0' }])],
    [ADVISORY_SOURCE_TYPES.JSON_FEED, [
      { name: 'json_schema_or_profile', sourceUrl: 'https://www.jsonfeed.org/version/1.1/', digest: DIGEST },
      { name: 'schema_version', schemaVersion: '1.1' },
      { name: 'schema_digest', digest: DIGEST },
      { name: 'schema_source_url', sourceUrl: 'https://www.jsonfeed.org/version/1.1/', digest: DIGEST },
      { name: 'drift_test_fixture', digest: DIGEST },
    ]],
  ];

  for (const [sourceType, artifacts] of cases) {
    const result = validateAdvisorySchemaPinning({ sourceType, artifacts, driftTests: driftTest(sourceType), enabledForLiveFetch: true });
    assert.equal(result.ok, true, `${sourceType}: ${result.errors.join('; ')}`);
  }
});

test('RSS and Atom live fetchers require pinned parser dependencies and entity-disabled evidence', () => {
  for (const sourceType of [ADVISORY_SOURCE_TYPES.RSS, ADVISORY_SOURCE_TYPES.ATOM]) {
    const result = validateAdvisorySchemaPinning({
      sourceType,
      artifacts: xmlArtifacts(),
      driftTests: driftTest(sourceType),
      enabledForLiveFetch: true,
    });
    assert.equal(result.ok, true, `${sourceType}: ${result.errors.join('; ')}`);
  }
});

test('live fetcher readiness fails closed when required schema pins or drift tests are missing', () => {
  const result = validateAdvisorySchemaPinning({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    artifacts: [{ name: 'json_schema', sourceUrl: 'http://schema.example/osv.json' }],
    driftTests: [],
    enabledForLiveFetch: true,
  });

  assert.equal(result.ok, false);
  assert.match(result.errors[0], /cannot be enabled/);
  assert.match(result.errors.join('\n'), /missing required schema\/parser artifact: schema_version/);
  assert.match(result.errors.join('\n'), /sourceUrl must be HTTPS/);
  assert.match(result.errors.join('\n'), /missing accepted schema drift fixture test/);
});

test('schema pinning rejects weak or unstructured digest evidence', () => {
  const result = validateAdvisorySchemaPinning({
    sourceType: ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
    artifacts: [
      { name: 'json_schema', sourceUrl: 'https://standards.example/csaf.json', digest: 'latest' },
      { name: 'schema_version', schemaVersion: '2.0' },
      { name: 'schema_digest', digest: 'sha1:bad' },
      { name: 'schema_source_url', sourceUrl: 'https://standards.example/csaf.json', digest: DIGEST },
      { name: 'drift_test_fixture', digest: DIGEST },
    ],
    driftTests: driftTest(ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT),
  });

  assert.equal(result.ok, false);
  assert.match(result.errors.join('\n'), /digest must be sha256/);
});

test('readiness records do not enable live fetch unless schema pins validate', () => {
  const blocked = buildLiveFetcherReadinessRecord({
    sourceType: ADVISORY_SOURCE_TYPES.NVD,
    artifacts: jsonArtifacts(),
    driftTests: [],
    enabledForLiveFetch: true,
    owner: 'Security Engineering',
  });

  assert.equal(blocked.ready, false);
  assert.equal(blocked.enabledForLiveFetch, false);
  assert.equal(blocked.requestedLiveFetch, true);
  assert.equal(blocked.owner, 'Security Engineering');
  assert.ok(blocked.errors.length > 0);

  const ready = buildLiveFetcherReadinessRecord({
    sourceType: ADVISORY_SOURCE_TYPES.NVD,
    artifacts: jsonArtifacts([{ name: 'api_version', apiVersion: '2.0' }]),
    driftTests: driftTest(ADVISORY_SOURCE_TYPES.NVD),
    enabledForLiveFetch: true,
  });
  assert.equal(ready.ready, true);
  assert.equal(ready.enabledForLiveFetch, true);
});

test('assertAdvisorySchemaPinning throws with machine-readable code for incomplete live fetcher evidence', () => {
  assert.throws(
    () => assertAdvisorySchemaPinning({ sourceType: ADVISORY_SOURCE_TYPES.RSS, artifacts: [], driftTests: [], enabledForLiveFetch: true }),
    (error) => error.code === 'advisory_schema_pinning_incomplete' && error.result.errors.length > 0,
  );
});
