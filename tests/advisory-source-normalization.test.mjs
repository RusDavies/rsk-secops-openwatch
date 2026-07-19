import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ADVISORY_SOURCE_TYPES,
  PROPRIETARY_ADVISORY_EXCHANGE_STATUS,
  classifyAdvisorySource,
  normalizeAdvisorySignal,
  normalizeAdvisorySourceRegistration,
} from '../lib/advisory-source-normalization.mjs';

test('source registry classifies structured, discovery, and authenticated sources', () => {
  assert.deepEqual(classifyAdvisorySource(ADVISORY_SOURCE_TYPES.CSAF_DOCUMENT), {
    sourceType: 'csaf_document',
    structured: true,
    discoveryOnly: false,
    requiresAuthentication: false,
    canAuthorizeCustomerViewing: false,
  });
  assert.equal(classifyAdvisorySource(ADVISORY_SOURCE_TYPES.JSON_FEED).discoveryOnly, true);
  assert.equal(classifyAdvisorySource(ADVISORY_SOURCE_TYPES.CUSTOMER_AUTHENTICATED_PORTAL).requiresAuthentication, true);
});

test('source registration normalizes URL, owner, authentication, and source semantics', () => {
  const source = normalizeAdvisorySourceRegistration({
    sourceType: 'rss',
    name: ' Vendor security blog ',
    url: 'https://vendor.example/security/feed.xml',
    vendorName: ' Vendor ',
    authentication: ' NONE ',
    owner: 'security-team',
  });
  assert.equal(source.name, 'Vendor security blog');
  assert.equal(source.url, 'https://vendor.example/security/feed.xml');
  assert.equal(source.vendorName, 'Vendor');
  assert.equal(source.authentication, 'none');
  assert.equal(source.discoveryOnly, true);
  assert.equal(source.canAuthorizeCustomerViewing, false);
});

test('advisory signals preserve upstream IDs and normalize source evidence', () => {
  const signal = normalizeAdvisorySignal({
    sourceType: 'csaf_vex',
    sourceName: 'Vendor CSAF VEX',
    sourceUrl: 'https://vendor.example/.well-known/csaf/advisories/vendor-2026-001.json',
    observedAt: '2026-06-03T12:00:00-04:00',
    upstreamIds: {
      cve: [' CVE-2026-1234 ', 'CVE-2026-1234'],
      csafDocumentTrackingId: 'VENDOR-2026-001',
      vendorAdvisoryId: 'SEC-001',
      signatureId: 'openpgp-key-1',
    },
    vendorCandidate: 'Vendor',
    affectedProducts: ['Product A', 'Product A', 'Product B'],
    category: 'vulnerability',
    status: 'under_investigation',
    severity: 'High',
    confidence: 2,
    title: ' Vendor investigates CVE-2026-1234 ',
    summary: 'Impact analysis is in progress.',
    remediation: 'Monitor vendor updates.',
    references: ['https://vendor.example/security/SEC-001'],
    revisions: [{ version: '1', date: '2026-06-03', summary: 'Initial advisory' }],
  });
  assert.equal(signal.sourceType, 'csaf_vex');
  assert.equal(signal.structured, true);
  assert.deepEqual(signal.upstreamIds.cve, ['CVE-2026-1234']);
  assert.equal(signal.upstreamIds.csafDocumentTrackingId, 'VENDOR-2026-001');
  assert.deepEqual(signal.affectedProducts, ['Product A', 'Product B']);
  assert.equal(signal.status, 'under_investigation');
  assert.equal(signal.severity, 'high');
  assert.equal(signal.confidence, 1);
  assert.equal(signal.observedAt, '2026-06-03T16:00:00.000Z');
  assert.equal(signal.revisions[0].date, '2026-06-03T00:00:00.000Z');
});

test('feed and HTML sources are discovery evidence only, not authorization to view customer shares', () => {
  const signal = normalizeAdvisorySignal({
    sourceType: 'json_feed',
    sourceName: 'Vendor trust feed',
    sourceUrl: 'https://vendor.example/feed.json',
    vendorCandidate: 'Vendor',
    title: 'Trust center update',
    category: 'trust_posture',
    status: 'informational',
  });
  assert.equal(signal.discoveryOnly, true);
  assert.equal(signal.canAuthorizeCustomerViewing, false);
});

test('unsupported source types and proprietary exchange claims fail closed', () => {
  assert.throws(() => classifyAdvisorySource('openwatch_federation'), /Unknown advisory source type/);
  assert.equal(PROPRIETARY_ADVISORY_EXCHANGE_STATUS.allowedForMvp, false);
  assert.match(PROPRIETARY_ADVISORY_EXCHANGE_STATUS.reason, /defer proprietary OpenWatch federation/);
});
