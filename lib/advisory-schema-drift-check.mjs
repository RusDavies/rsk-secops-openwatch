import { createHash } from 'node:crypto';
import {
  DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH,
  loadAdvisorySchemaPinManifest,
  validateAdvisorySchemaPinManifest,
} from './advisory-schema-pin-manifest.mjs';

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function defaultFetchBytes(url) {
  const response = await fetch(url, { headers: { 'user-agent': 'OpenWatch advisory schema drift checker' } });
  if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);
  return Buffer.from(await response.arrayBuffer());
}

function sourceUrlArtifacts(source) {
  return (source.artifacts ?? []).filter((artifact) => artifact.sourceUrl && artifact.digest);
}

export async function checkAdvisorySchemaPinDrift({
  manifest = null,
  manifestPath = DEFAULT_ADVISORY_SCHEMA_PIN_MANIFEST_PATH,
  repoRoot = '.',
  fetcher = defaultFetchBytes,
  now = new Date().toISOString(),
} = {}) {
  const effectiveManifest = manifest ?? loadAdvisorySchemaPinManifest(manifestPath);
  const localValidation = validateAdvisorySchemaPinManifest(effectiveManifest, { repoRoot });
  const upstreamChecks = [];

  for (const source of effectiveManifest.sources ?? []) {
    for (const artifact of sourceUrlArtifacts(source)) {
      const check = {
        sourceType: source.sourceType,
        artifact: artifact.name,
        sourceUrl: artifact.sourceUrl,
        expectedDigest: artifact.digest,
        actualDigest: null,
        status: 'unknown',
        error: null,
      };
      try {
        const bytes = await fetcher(artifact.sourceUrl, { sourceType: source.sourceType, artifact });
        check.actualDigest = sha256(bytes);
        check.status = check.actualDigest === check.expectedDigest ? 'unchanged' : 'drifted';
      } catch (error) {
        check.status = 'fetch_failed';
        check.error = error.message;
      }
      upstreamChecks.push(check);
    }
  }

  const drifted = upstreamChecks.filter((check) => check.status === 'drifted');
  const fetchFailed = upstreamChecks.filter((check) => check.status === 'fetch_failed');
  const liveFetchStillDisabled = effectiveManifest.liveFetchEnabled === false
    && (effectiveManifest.sources ?? []).every((source) => source.enabledForLiveFetch === false);
  const ok = localValidation.ok && drifted.length === 0 && fetchFailed.length === 0 && liveFetchStillDisabled;

  return {
    ok,
    checkedAt: now,
    manifestPath,
    liveFetchStillDisabled,
    localValidation,
    upstreamChecks,
    summary: {
      sources: effectiveManifest.sources?.length ?? 0,
      upstreamArtifactsChecked: upstreamChecks.length,
      unchanged: upstreamChecks.filter((check) => check.status === 'unchanged').length,
      drifted: drifted.length,
      fetchFailed: fetchFailed.length,
      localErrors: localValidation.errors.length,
    },
  };
}

export function formatAdvisorySchemaPinDriftReport(result) {
  const lines = [];
  lines.push(`# Advisory Schema Pin Drift Check`);
  lines.push(``);
  lines.push(`Checked at: ${result.checkedAt}`);
  lines.push(`Manifest: ${result.manifestPath}`);
  lines.push(`Overall status: ${result.ok ? 'PASS' : 'REVIEW_REQUIRED'}`);
  lines.push(`Live fetch still disabled: ${result.liveFetchStillDisabled ? 'yes' : 'no'}`);
  lines.push(``);
  lines.push(`## Summary`);
  lines.push(`- Sources: ${result.summary.sources}`);
  lines.push(`- Upstream artifacts checked: ${result.summary.upstreamArtifactsChecked}`);
  lines.push(`- Unchanged: ${result.summary.unchanged}`);
  lines.push(`- Drifted: ${result.summary.drifted}`);
  lines.push(`- Fetch failed: ${result.summary.fetchFailed}`);
  lines.push(`- Local manifest errors: ${result.summary.localErrors}`);
  lines.push(``);
  if (result.localValidation.errors.length > 0) {
    lines.push(`## Local manifest errors`);
    for (const error of result.localValidation.errors) lines.push(`- ${error}`);
    lines.push(``);
  }
  lines.push(`## Upstream artifact checks`);
  for (const check of result.upstreamChecks) {
    const suffix = check.error ? ` (${check.error})` : '';
    lines.push(`- ${check.sourceType} / ${check.artifact}: ${check.status}${suffix}`);
    lines.push(`  - URL: ${check.sourceUrl}`);
    lines.push(`  - Expected: ${check.expectedDigest}`);
    lines.push(`  - Actual: ${check.actualDigest ?? 'n/a'}`);
  }
  lines.push(``);
  lines.push(`No live fetchers are enabled or auto-enabled by this command. Drift requires human review before manifest changes.`);
  return lines.join('\n');
}
