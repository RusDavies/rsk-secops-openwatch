import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { ADVISORY_SOURCE_TYPES } from '../lib/advisory-source-normalization.mjs';
import {
  DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH,
  loadAdvisorySchemaPinManifest,
  parseAdvisorySchemaPinManifest,
  validateAdvisorySchemaPinManifest,
} from '../lib/advisory-schema-pin-manifest.mjs';
import { ADVISORY_SCHEMA_PIN_REQUIREMENTS } from '../lib/advisory-schema-pinning.mjs';

const EXPECTED_SOURCE_TYPES = [
  ADVISORY_SOURCE_TYPES.ATOM,
  ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
  ADVISORY_SOURCE_TYPES.CSAF_VEX,
  ADVISORY_SOURCE_TYPES.JSON_FEED,
  ADVISORY_SOURCE_TYPES.NVD,
  ADVISORY_SOURCE_TYPES.OPENVEX,
  ADVISORY_SOURCE_TYPES.OSV,
  ADVISORY_SOURCE_TYPES.RSS,
].sort();

test('source-controlled advisory schema pin manifest validates every future live-fetch source', () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const result = validateAdvisorySchemaPinManifest(manifest, { repoRoot: '.' });

  assert.equal(result.ok, true, result.errors.join('\n'));
  assert.deepEqual(result.sourceTypes, EXPECTED_SOURCE_TYPES);
  assert.deepEqual(result.sourceTypes, Object.keys(ADVISORY_SCHEMA_PIN_REQUIREMENTS).sort());
  assert.equal(manifest.liveFetchEnabled, false);
  assert.equal(result.readiness.every((record) => record.ready), true);
  assert.equal(result.readiness.every((record) => record.enabledForLiveFetch === false), true);
});

test('manifest records concrete official source URLs, sha256 pins, and drift fixtures', () => {
  const manifest = loadAdvisorySchemaPinManifest();
  for (const source of manifest.sources) {
    assert.equal(source.enabledForLiveFetch, false);
    assert.ok(source.owner);
    assert.ok(source.notes);
    assert.ok(source.driftTests.some((driftTest) => driftTest.sourceType === source.sourceType && driftTest.expectedOutcome === 'accepted'));
    assert.ok(source.artifacts.some((artifact) => artifact.name === 'drift_test_fixture' && /^sha256:[a-f0-9]{64}$/i.test(artifact.digest)));

    const urlArtifacts = source.artifacts.filter((artifact) => artifact.sourceUrl);
    if (![ADVISORY_SOURCE_TYPES.RSS, ADVISORY_SOURCE_TYPES.ATOM].includes(source.sourceType)) {
      assert.ok(urlArtifacts.length > 0, `${source.sourceType} must include schema/profile source URL evidence`);
      assert.ok(urlArtifacts.every((artifact) => artifact.sourceUrl.startsWith('https://')));
      assert.ok(urlArtifacts.every((artifact) => /^sha256:[a-f0-9]{64}$/i.test(artifact.digest)));
    }
  }
});

test('RSS and Atom manifest entries record parser package lock and entity-disabled evidence', () => {
  const manifest = loadAdvisorySchemaPinManifest();
  for (const sourceType of [ADVISORY_SOURCE_TYPES.RSS, ADVISORY_SOURCE_TYPES.ATOM]) {
    const source = manifest.sources.find((entry) => entry.sourceType === sourceType);
    assert.ok(source, `${sourceType} manifest entry exists`);
    assert.ok(source.artifacts.some((artifact) => artifact.name === 'xml_parser' && artifact.packageVersion === 'fast-xml-parser@5.8.0'));
    assert.ok(source.artifacts.some((artifact) => artifact.name === 'parser_lock_digest' && /^sha256:[a-f0-9]{64}$/i.test(artifact.digest)));
    assert.ok(source.artifacts.some((artifact) => artifact.name === 'doctype_entity_disabled' && artifact.disabled === true));
  }
});

test('manifest parser rejects malformed or unsupported manifest versions', async () => {
  await assert.rejects(
    async () => parseAdvisorySchemaPinManifest(await readFile('package.json', 'utf8')),
    /manifestVersion 1/,
  );

  assert.throws(
    () => parseAdvisorySchemaPinManifest(JSON.stringify({ manifestVersion: 99, sources: [] })),
    /manifestVersion 1/,
  );
});

test('manifest validation catches missing drift fixture digest and accidental live-fetch enablement', () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const mutated = structuredClone(manifest);
  mutated.liveFetchEnabled = true;
  mutated.sources[0].artifacts = mutated.sources[0].artifacts.filter((artifact) => artifact.name !== 'drift_test_fixture');

  const result = validateAdvisorySchemaPinManifest(mutated, { repoRoot: '.' });
  assert.equal(result.ok, false);
  assert.match(result.errors.join('\n'), /liveFetchEnabled must remain false/);
  assert.match(result.errors.join('\n'), /missing required schema\/parser artifact: drift_test_fixture/);
});

console.log(`checked advisory schema pin manifest at ${DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH}`);
