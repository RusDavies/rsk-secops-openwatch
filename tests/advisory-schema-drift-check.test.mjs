import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { loadAdvisorySchemaPinManifest } from '../lib/advisory-schema-pin-manifest.mjs';
import {
  checkAdvisorySchemaPinDrift,
  formatAdvisorySchemaPinDriftReport,
} from '../lib/advisory-schema-drift-check.mjs';

function digestBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function sourceUrlArtifacts(manifest) {
  return manifest.sources.flatMap((source) => (source.artifacts ?? [])
    .filter((artifact) => artifact.sourceUrl && artifact.digest)
    .map((artifact) => ({ sourceType: source.sourceType, artifact })));
}

async function fetcherForManifest(manifest) {
  const payloadByUrl = new Map();
  for (const { artifact } of sourceUrlArtifacts(manifest)) {
    payloadByUrl.set(artifact.sourceUrl, Buffer.from(`payload for ${artifact.sourceUrl}`));
  }
  for (const { artifact } of sourceUrlArtifacts(manifest)) {
    artifact.digest = digestBytes(payloadByUrl.get(artifact.sourceUrl));
  }
  return async (url) => {
    if (!payloadByUrl.has(url)) throw new Error(`unexpected URL ${url}`);
    return payloadByUrl.get(url);
  };
}

test('schema drift check validates local manifest and compares every pinned upstream URL without enabling live fetchers', async () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const fetcher = await fetcherForManifest(manifest);

  const result = await checkAdvisorySchemaPinDrift({ manifest, fetcher, repoRoot: '.', now: '2026-06-05T16:00:00.000Z' });

  assert.equal(result.ok, true, JSON.stringify(result, null, 2));
  assert.equal(result.liveFetchStillDisabled, true);
  assert.equal(result.summary.localErrors, 0);
  assert.equal(result.summary.drifted, 0);
  assert.equal(result.summary.fetchFailed, 0);
  assert.equal(result.summary.upstreamArtifactsChecked, sourceUrlArtifacts(manifest).length);
  assert.ok(result.summary.upstreamArtifactsChecked >= 10);
  assert.equal(result.upstreamChecks.every((check) => check.status === 'unchanged'), true);
});

test('schema drift check reports upstream digest drift as review-required evidence', async () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const fetcher = await fetcherForManifest(manifest);
  manifest.sources[0].artifacts.find((artifact) => artifact.sourceUrl).digest = 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  const result = await checkAdvisorySchemaPinDrift({ manifest, fetcher, repoRoot: '.', now: '2026-06-05T16:05:00.000Z' });

  assert.equal(result.ok, false);
  assert.equal(result.summary.drifted, 1);
  assert.equal(result.liveFetchStillDisabled, true);
  assert.equal(result.upstreamChecks.some((check) => check.status === 'drifted' && check.expectedDigest.endsWith('bbbbbbbb')), true);
});

test('schema drift check reports fetch failures without mutating live fetch enablement', async () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const fetcher = async (url) => {
    if (url.includes('openvex')) throw new Error('temporary upstream outage');
    return Buffer.from('not matching but fetched');
  };

  const result = await checkAdvisorySchemaPinDrift({ manifest, fetcher, repoRoot: '.', now: '2026-06-05T16:10:00.000Z' });

  assert.equal(result.ok, false);
  assert.ok(result.summary.fetchFailed >= 1);
  assert.equal(result.liveFetchStillDisabled, true);
  assert.equal(manifest.liveFetchEnabled, false);
});

test('schema drift report is reviewable text and states that live fetchers are not auto-enabled', async () => {
  const manifest = loadAdvisorySchemaPinManifest();
  const fetcher = await fetcherForManifest(manifest);
  const result = await checkAdvisorySchemaPinDrift({ manifest, fetcher, repoRoot: '.', now: '2026-06-05T16:15:00.000Z' });
  const report = formatAdvisorySchemaPinDriftReport(result);

  assert.match(report, /Advisory Schema Pin Drift Check/);
  assert.match(report, /Overall status: PASS/);
  assert.match(report, /No live fetchers are enabled or auto-enabled/);
  assert.match(report, /Upstream artifact checks/);
});

test('check script is exposed as a package command', async () => {
  const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
  assert.equal(packageJson.scripts['check:advisory-schema-pins'], 'node scripts/check-advisory-schema-pins.mjs');
});
