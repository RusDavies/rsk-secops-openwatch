import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ADVISORY_SOURCE_TYPES } from '../lib/advisory-source-normalization.mjs';
import {
  DEFAULT_ADVISORY_ADAPTER_LIMITS,
  assertProductionAdvisoryPayload,
  parseProductionAdvisoryPayload,
} from '../lib/advisory-production-adapters.mjs';
import {
  normalizeCsafDocumentFixture,
  normalizeFeedFixture,
  normalizeNvdFixture,
  normalizeOpenVexFixture,
  normalizeOsvFixture,
} from '../lib/advisory-fixture-parsers.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(__dirname, 'fixtures', 'advisory-sources');

async function jsonFixture(name) {
  return JSON.parse(await readFile(join(fixtureDir, name), 'utf8'));
}

async function textFixture(name) {
  return readFile(join(fixtureDir, name), 'utf8');
}

const SOURCE_URLS = Object.freeze({
  [ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT]: 'https://vendor.example/.well-known/csaf/advisories/example-2026-0001.json',
  [ADVISORY_SOURCE_TYPES.CSAF_VEX]: 'https://vendor.example/.well-known/csaf/vex/example-vex-2026-0002.json',
  [ADVISORY_SOURCE_TYPES.OPENVEX]: 'https://vendor.example/.well-known/openvex/example-2026-0003.json',
  [ADVISORY_SOURCE_TYPES.OSV]: 'https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz',
  [ADVISORY_SOURCE_TYPES.NVD]: 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5555',
  [ADVISORY_SOURCE_TYPES.RSS]: 'https://vendor.example/security/rss.xml',
  [ADVISORY_SOURCE_TYPES.ATOM]: 'https://vendor.example/security/atom.xml',
  [ADVISORY_SOURCE_TYPES.JSON_FEED]: 'https://vendor.example/security/feed.json',
});

test('production adapters preserve fixture normalization parity for structured advisory sources', async () => {
  const cases = [
    [ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT, await jsonFixture('csaf-2.0.json'), normalizeCsafDocumentFixture],
    [ADVISORY_SOURCE_TYPES.CSAF_VEX, await jsonFixture('csaf-vex.json'), normalizeCsafDocumentFixture],
    [ADVISORY_SOURCE_TYPES.OPENVEX, await jsonFixture('openvex.json'), normalizeOpenVexFixture],
    [ADVISORY_SOURCE_TYPES.OSV, await jsonFixture('osv.json'), normalizeOsvFixture],
    [ADVISORY_SOURCE_TYPES.NVD, await jsonFixture('nvd.json'), normalizeNvdFixture],
  ];

  for (const [sourceType, payload, fixtureParser] of cases) {
    const production = parseProductionAdvisoryPayload({ sourceType, payload, sourceUrl: SOURCE_URLS[sourceType] });
    const fixtureSignal = fixtureParser(payload, { sourceType, sourceUrl: SOURCE_URLS[sourceType] });

    assert.equal(production.ok, true, production.telemetry?.message);
    assert.equal(production.signal.sourceType, fixtureSignal.sourceType);
    assert.deepEqual(production.signal.upstreamIds, fixtureSignal.upstreamIds);
    assert.equal(production.signal.status, fixtureSignal.status);
    assert.deepEqual(production.signal.revisions, fixtureSignal.revisions);
    assert.equal(production.signal.canAuthorizeCustomerViewing, false);
  }
});

test('production adapters preserve fixture normalization parity for discovery feeds', async () => {
  const cases = [
    [ADVISORY_SOURCE_TYPES.RSS, await textFixture('rss.xml')],
    [ADVISORY_SOURCE_TYPES.ATOM, await textFixture('atom.xml')],
    [ADVISORY_SOURCE_TYPES.JSON_FEED, await jsonFixture('json-feed.json')],
  ];

  for (const [sourceType, payload] of cases) {
    const production = parseProductionAdvisoryPayload({ sourceType, payload, sourceUrl: SOURCE_URLS[sourceType] });
    const fixtureSignal = normalizeFeedFixture(payload, { sourceType, sourceUrl: SOURCE_URLS[sourceType] });

    assert.equal(production.ok, true, production.telemetry?.message);
    assert.equal(production.signal.discoveryOnly, true);
    assert.equal(production.signal.status, fixtureSignal.status);
    assert.equal(production.signal.upstreamIds.feedGuid, fixtureSignal.upstreamIds.feedGuid);
    assert.equal(production.signal.canAuthorizeCustomerViewing, false);
  }
});

test('production adapters reject malformed JSON, unsupported source types, and missing source URLs fail closed with telemetry', () => {
  const malformed = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    payload: '{not-json',
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.OSV],
  });
  assert.equal(malformed.ok, false);
  assert.equal(malformed.telemetry.code, 'parse_error');
  assert.equal(malformed.signal, null);

  const unsupported = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.VENDOR_HTML,
    payload: '<html><title>Advisory</title></html>',
    sourceUrl: 'https://vendor.example/security/advisory.html',
  });
  assert.equal(unsupported.ok, false);
  assert.equal(unsupported.telemetry.code, 'unsupported_source_type');

  const missingUrl = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    payload: { id: 'GHSA-abcd-1234-wxyz', summary: 'x' },
  });
  assert.equal(missingUrl.ok, false);
  assert.equal(missingUrl.telemetry.code, 'missing_source_url');
});

test('production adapters enforce payload size, JSON depth, and feed item limits before normalization', async () => {
  const tooLarge = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    payload: JSON.stringify(await jsonFixture('osv.json')),
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.OSV],
    limits: { maxPayloadBytes: 12 },
  });
  assert.equal(tooLarge.ok, false);
  assert.equal(tooLarge.telemetry.code, 'payload_too_large');

  const tooDeep = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.OSV,
    payload: { id: 'GHSA-abcd-1234-wxyz', summary: 'x', modified: '2026-06-01T00:00:00Z', affected: [{ package: { ecosystem: 'npm', name: 'p' } }], nested: { a: { b: { c: true } } } },
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.OSV],
    limits: { maxJsonDepth: 3 },
  });
  assert.equal(tooDeep.ok, false);
  assert.equal(tooDeep.telemetry.code, 'json_too_deep');

  const manyItems = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.RSS,
    payload: '<rss><channel><title>Too many</title><item><guid>a</guid><title>A</title><link>https://vendor.example/a</link></item><item><guid>b</guid><title>B</title><link>https://vendor.example/b</link></item></channel></rss>',
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.RSS],
    limits: { maxFeedItems: 1 },
  });
  assert.equal(manyItems.ok, false);
  assert.equal(manyItems.telemetry.code, 'schema_validation_failed');
  assert.match(manyItems.telemetry.detail.errors.join('\n'), /maxFeedItems/);
});

test('production adapters reject source-specific schema/profile violations before creating signals', async () => {
  const badCsaf = await jsonFixture('csaf-2.0.json');
  badCsaf.vulnerabilities[0].product_status = { vendor_says_relax: ['example-product-a-4.2.0'] };
  const csafResult = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT,
    payload: badCsaf,
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT],
  });
  assert.equal(csafResult.ok, false);
  assert.equal(csafResult.telemetry.code, 'schema_validation_failed');
  assert.match(csafResult.telemetry.detail.errors.join('\n'), /unsupported CSAF product_status field/);

  const badOpenVex = await jsonFixture('openvex.json');
  badOpenVex.statements[0].status = 'definitely_fine_trust_me';
  const openVexResult = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.OPENVEX,
    payload: badOpenVex,
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.OPENVEX],
  });
  assert.equal(openVexResult.ok, false);
  assert.match(openVexResult.telemetry.detail.errors.join('\n'), /OpenVEX status/);

  const badNvd = await jsonFixture('nvd.json');
  badNvd.vulnerabilities[0].cve.references[0].url = 'http://nvd.nist.gov/vuln/detail/CVE-2026-5555';
  const nvdResult = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.NVD,
    payload: badNvd,
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.NVD],
  });
  assert.equal(nvdResult.ok, false);
  assert.match(nvdResult.telemetry.detail.errors.join('\n'), /HTTPS URL/);
});

test('production XML feed validation rejects entity expansion inputs', () => {
  const result = parseProductionAdvisoryPayload({
    sourceType: ADVISORY_SOURCE_TYPES.RSS,
    payload: '<!DOCTYPE rss [<!ENTITY lol "lol">]><rss><channel><title>&lol;</title><item><guid>g</guid><title>T</title><link>https://vendor.example/t</link></item></channel></rss>',
    sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.RSS],
  });

  assert.equal(result.ok, false);
  assert.equal(result.telemetry.code, 'schema_validation_failed');
  assert.match(result.telemetry.detail.errors.join('\n'), /DOCTYPE or ENTITY/);
});

test('assertProductionAdvisoryPayload throws validation telemetry for fail-closed callers', () => {
  assert.throws(
    () => assertProductionAdvisoryPayload({
      sourceType: ADVISORY_SOURCE_TYPES.OSV,
      payload: { id: 'GHSA-abcd-1234-wxyz', summary: 'Missing affected package' },
      sourceUrl: SOURCE_URLS[ADVISORY_SOURCE_TYPES.OSV],
    }),
    (error) => error.code === 'schema_validation_failed' && /affected/.test(error.telemetry.detail.errors.join('\n')),
  );
});

test('production adapter defaults document operational safety limits', () => {
  assert.equal(DEFAULT_ADVISORY_ADAPTER_LIMITS.maxPayloadBytes, 512 * 1024);
  assert.equal(DEFAULT_ADVISORY_ADAPTER_LIMITS.maxJsonDepth, 32);
  assert.equal(DEFAULT_ADVISORY_ADAPTER_LIMITS.maxFeedItems, 50);
  assert.equal(DEFAULT_ADVISORY_ADAPTER_LIMITS.timeoutMs, 2_000);
});
