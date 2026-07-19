import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateVendorRisk, renewalUrgencyScore, sortByRisk } from '../lib/risk-score.mjs';

const now = new Date('2026-05-04T12:00:00-04:00');

test('risk score is explainable and bounded', () => {
  const risk = calculateVendorRisk({
    name: 'ExampleID',
    category: 'identity',
    dataSensitivity: 'high',
    criticality: 'high',
    renewalDate: '2026-05-20',
    lastReviewedAt: null,
    incidents: [{ severity: 'high', relevance: 'active' }],
  }, now);

  assert.equal(risk.score, 89);
  assert.equal(risk.tier, 'high');
  assert.match(risk.explanation, /high-sensitivity data/);
  assert.equal(risk.factors.renewalUrgency, 10);
});

test('renewal urgency drops when renewal is far away', () => {
  assert.equal(renewalUrgencyScore('2026-12-31', now), 0);
  assert.equal(renewalUrgencyScore('2026-05-31', now), 10);
});

test('vendors sort by descending risk', () => {
  const sorted = sortByRisk([
    { id: 'low', name: 'Low', category: 'productivity', dataSensitivity: 'low', criticality: 'low', renewalDate: '2026-12-31', lastReviewedAt: '2026-04-01', incidents: [] },
    { id: 'high', name: 'High', category: 'identity', dataSensitivity: 'high', criticality: 'high', renewalDate: '2026-05-10', lastReviewedAt: null, incidents: [{ severity: 'high', relevance: 'active' }] },
  ], now);

  assert.equal(sorted[0].id, 'high');
  assert.equal(sorted[1].id, 'low');
});
