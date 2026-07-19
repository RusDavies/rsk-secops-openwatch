import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { ADVISORY_SOURCE_TYPES } from '../lib/advisory-source-normalization.mjs';
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

test('CSAF 2.0 fixture normalizes tracking ID, CVE, products, revisions, and no-publication semantics', async () => {
  const signal = normalizeCsafDocumentFixture(await jsonFixture('csaf-2.0.json'), {
    sourceUrl: 'https://vendor.example/.well-known/csaf/advisories/example-2026-0001.json',
  });

  assert.equal(signal.sourceType, 'csaf_document');
  assert.equal(signal.structured, true);
  assert.equal(signal.canAuthorizeCustomerViewing, false);
  assert.equal(signal.upstreamIds.csafDocumentTrackingId, 'EXAMPLE-2026-0001');
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-1111']);
  assert.equal(signal.upstreamIds.vendorAdvisoryId, 'EV-SEC-0001');
  assert.deepEqual(signal.affectedProducts, ['example-product-a-4.2.0', 'example-product-a-4.2.1']);
  assert.equal(signal.status, 'affected');
  assert.equal(signal.severity, 'high');
  assert.equal(signal.revisions.at(-1).version, '2');
  assert.match(signal.remediation, /Upgrade Product A/);
});

test('CSAF VEX fixture preserves native not-affected status without turning it into customer-facing authorization', async () => {
  const signal = normalizeCsafDocumentFixture(await jsonFixture('csaf-vex.json'), {
    sourceType: ADVISORY_SOURCE_TYPES.CSAF_VEX,
    sourceUrl: 'https://vendor.example/.well-known/csaf/vex/example-vex-2026-0002.json',
  });

  assert.equal(signal.sourceType, 'csaf_vex');
  assert.equal(signal.structured, true);
  assert.equal(signal.status, 'not_affected');
  assert.equal(signal.upstreamIds.csafDocumentTrackingId, 'EXAMPLE-VEX-2026-0002');
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-2222']);
  assert.deepEqual(signal.affectedProducts, ['example-product-b-9.0.0']);
  assert.equal(signal.canAuthorizeCustomerViewing, false);
});

test('OpenVEX fixture preserves statement status, product identity, and upstream advisory ID', async () => {
  const signal = normalizeOpenVexFixture(await jsonFixture('openvex.json'), {
    sourceUrl: 'https://vendor.example/.well-known/openvex/example-2026-0003.json',
  });

  assert.equal(signal.sourceType, 'openvex');
  assert.equal(signal.status, 'under_investigation');
  assert.equal(signal.upstreamIds.vendorAdvisoryId, 'https://vendor.example/.well-known/openvex/example-2026-0003.json');
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-3333']);
  assert.deepEqual(signal.affectedProducts, ['pkg:generic/example-product-c@3.1.0']);
  assert.equal(signal.canAuthorizeCustomerViewing, false);
});

test('OSV fixture preserves OSV ID, CVE alias, package coordinates, and revision timestamps', async () => {
  const signal = normalizeOsvFixture(await jsonFixture('osv.json'), {
    sourceUrl: 'https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz',
  });

  assert.equal(signal.sourceType, 'osv');
  assert.equal(signal.upstreamIds.osvId, 'GHSA-abcd-1234-wxyz');
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-4444']);
  assert.deepEqual(signal.affectedProducts, ['example-library', 'SEMVER']);
  assert.equal(signal.status, 'affected');
  assert.equal(signal.severity, 'high');
  assert.equal(signal.revisions.length, 2);
  assert.equal(signal.canAuthorizeCustomerViewing, false);
});

test('NVD fixture preserves NVD CVE ID, CPE criteria, modified timestamp, and severity', async () => {
  const signal = normalizeNvdFixture(await jsonFixture('nvd.json'), {
    sourceUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-5555',
  });

  assert.equal(signal.sourceType, 'nvd');
  assert.equal(signal.upstreamIds.nvdCveId, 'CVE-2026-5555');
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-5555']);
  assert.deepEqual(signal.affectedProducts, ['cpe:2.3:a:example:appliance:1.0:*:*:*:*:*:*:*']);
  assert.equal(signal.status, 'affected');
  assert.equal(signal.severity, 'critical');
  assert.equal(signal.observedAt, '2026-06-02T08:00:00.000Z');
  assert.equal(signal.canAuthorizeCustomerViewing, false);
});

test('RSS, Atom, and JSON Feed fixtures normalize as discovery-only evidence', async () => {
  const cases = [
    ['rss', () => textFixture('rss.xml'), 'EV-RSS-2026-0006', 'https://vendor.example/security/EV-RSS-2026-0006'],
    ['atom', () => textFixture('atom.xml'), 'tag:vendor.example,2026:EV-ATOM-0007', 'https://vendor.example/security/EV-ATOM-0007'],
    ['json_feed', () => jsonFixture('json-feed.json'), 'EV-JSON-2026-0008', 'https://vendor.example/security/EV-JSON-2026-0008'],
  ];

  for (const [sourceType, load, expectedGuid, expectedReference] of cases) {
    const signal = normalizeFeedFixture(await load(), {
      sourceType,
      sourceUrl: sourceType === 'json_feed' ? undefined : `https://vendor.example/security/${sourceType}.xml`,
    });
    assert.equal(signal.sourceType, sourceType);
    assert.equal(signal.discoveryOnly, true);
    assert.equal(signal.structured, false);
    assert.equal(signal.canAuthorizeCustomerViewing, false);
    assert.equal(signal.upstreamIds.feedGuid, expectedGuid);
    assert.equal(signal.references[0], expectedReference);
    assert.equal(signal.status, 'informational');
  }
});

test('malformed parser fixtures fail closed instead of creating low-confidence pseudo-signals', async () => {
  assert.throws(
    () => normalizeCsafDocumentFixture({ document: { tracking: { id: 'NO-CVE' } } }, { sourceUrl: 'https://vendor.example/bad.json' }),
    /requires document\.tracking\.id and vulnerabilities\[0\]\.cve/,
  );
  assert.throws(
    () => normalizeOsvFixture({ id: 'OSV-MISSING-SUMMARY' }, { sourceUrl: 'https://osv.dev/vulnerability/OSV-MISSING-SUMMARY' }),
    /requires id and summary/,
  );
  assert.throws(
    () => normalizeFeedFixture('<rss><channel></channel></rss>', { sourceType: 'rss', sourceUrl: 'https://vendor.example/rss.xml' }),
    /requires at least one feed item/,
  );
});
