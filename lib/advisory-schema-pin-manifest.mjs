import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { buildLiveFetcherReadinessRecord } from './advisory-schema-pinning.mjs';

export const DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH = 'config/advisory-schema-pin-manifest.json';
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;

function digestFile(path) {
  const bytes = readFileSync(path);
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function artifactDigestErrors(source, repoRoot = '.') {
  const errors = [];
  for (const artifact of source.artifacts ?? []) {
    if (artifact.digest && !DIGEST_PATTERN.test(artifact.digest)) {
      errors.push(`${source.sourceType}:${artifact.name} has invalid sha256 digest format`);
    }
  }
  const lockArtifact = (source.artifacts ?? []).find((artifact) => artifact.name === 'parser_lock_digest');
  if (lockArtifact?.digest) {
    const actualLockDigest = digestFile(`${repoRoot}/package-lock.json`);
    if (actualLockDigest !== lockArtifact.digest) {
      errors.push(`${source.sourceType}: parser lock digest mismatch for package-lock.json`);
    }
  }
  for (const driftTest of source.driftTests ?? []) {
    const fixtureArtifact = (source.artifacts ?? []).find((artifact) => artifact.name === 'drift_test_fixture');
    if (!fixtureArtifact?.digest || !driftTest.fixture) continue;
    const actual = digestFile(`${repoRoot}/${driftTest.fixture}`);
    if (actual !== fixtureArtifact.digest) {
      errors.push(`${source.sourceType}: drift fixture digest mismatch for ${driftTest.fixture}`);
    }
  }
  return errors;
}

export function parseAdvisorySchemaPinManifest(jsonText) {
  const manifest = JSON.parse(jsonText);
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Advisory schema pin manifest must be a JSON object');
  }
  if (manifest.manifestVersion !== 1) {
    throw new Error('Advisory schema pin manifest must use manifestVersion 1');
  }
  if (!Array.isArray(manifest.sources) || manifest.sources.length === 0) {
    throw new Error('Advisory schema pin manifest must contain sources');
  }
  return manifest;
}

export function loadAdvisorySchemaPinManifest(path = DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH) {
  return parseAdvisorySchemaPinManifest(readFileSync(path, 'utf8'));
}

export function validateAdvisorySchemaPinManifest(manifest, { repoRoot = '.', requireLiveFetchDisabled = true } = {}) {
  const sourceTypes = new Set();
  const errors = [];
  const readiness = [];

  if (requireLiveFetchDisabled && manifest.liveFetchEnabled !== false) {
    errors.push('manifest liveFetchEnabled must remain false until live fetch orchestration exists');
  }

  for (const source of manifest.sources ?? []) {
    if (!source?.sourceType) {
      errors.push('manifest source missing sourceType');
      continue;
    }
    if (sourceTypes.has(source.sourceType)) errors.push(`duplicate manifest sourceType: ${source.sourceType}`);
    sourceTypes.add(source.sourceType);
    errors.push(...artifactDigestErrors(source, repoRoot));
    const record = buildLiveFetcherReadinessRecord(source);
    readiness.push(record);
    if (!record.ready) {
      errors.push(...record.errors.map((error) => `${source.sourceType}: ${error}`));
    }
    if (source.enabledForLiveFetch && !record.ready) {
      errors.push(`${source.sourceType}: enabledForLiveFetch cannot be true without readiness`);
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    readiness,
    sourceTypes: [...sourceTypes].sort(),
  };
}

export function loadAndValidateAdvisorySchemaPinManifest(path = DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH, options = {}) {
  const manifest = loadAdvisorySchemaPinManifest(path);
  return validateAdvisorySchemaPinManifest(manifest, options);
}
