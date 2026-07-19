const SENSITIVITY = { none: 0, low: 8, medium: 16, high: 25 };
const CRITICALITY = { low: 5, medium: 12, high: 20 };
const CATEGORY = {
  productivity: 3,
  identity: 10,
  infrastructure: 9,
  finance: 8,
  support: 6,
  marketing: 4,
  development: 7,
};

export function daysUntil(dateLike, now = new Date()) {
  const target = new Date(dateLike);
  const ms = target.getTime() - now.getTime();
  return Math.ceil(ms / 86400000);
}

export function renewalUrgencyScore(renewalDate, now = new Date()) {
  const days = daysUntil(renewalDate, now);
  if (Number.isNaN(days)) return 0;
  if (days < 0) return 10;
  if (days <= 30) return 10;
  if (days <= 60) return 7;
  if (days <= 90) return 4;
  return 0;
}

export function staleReviewScore(reviewedAt, now = new Date()) {
  if (!reviewedAt) return 10;
  const days = Math.abs(daysUntil(reviewedAt, now));
  if (days > 365) return 10;
  if (days > 180) return 6;
  if (days > 90) return 3;
  return 0;
}

export function incidentScore(incidents = []) {
  const relevant = incidents.filter((incident) => incident.relevance !== 'dismissed');
  const severe = relevant.filter((incident) => incident.severity === 'high').length;
  const medium = relevant.filter((incident) => incident.severity === 'medium').length;
  return Math.min(25, severe * 14 + medium * 8 + Math.max(0, relevant.length - severe - medium) * 4);
}

export function calculateVendorRisk(vendor, now = new Date()) {
  const factors = {
    dataSensitivity: SENSITIVITY[vendor.dataSensitivity] ?? 0,
    businessCriticality: CRITICALITY[vendor.criticality] ?? 0,
    incidents: incidentScore(vendor.incidents),
    renewalUrgency: renewalUrgencyScore(vendor.renewalDate, now),
    staleReview: staleReviewScore(vendor.lastReviewedAt, now),
    categoryRisk: CATEGORY[vendor.category] ?? 5,
  };
  const score = Math.min(100, Object.values(factors).reduce((sum, value) => sum + value, 0));
  const tier = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
  const explanation = explainRisk(vendor, factors, score, tier, now);
  return { score, tier, factors, explanation };
}

export function explainRisk(vendor, factors, score, tier, now = new Date()) {
  const reasons = [];
  if (factors.dataSensitivity >= 16) reasons.push(`${vendor.name} handles ${vendor.dataSensitivity}-sensitivity data`);
  if (factors.businessCriticality >= 12) reasons.push(`business criticality is ${vendor.criticality}`);
  if (factors.incidents > 0) reasons.push(`${vendor.incidents?.length ?? 0} active incident signal(s)`);
  if (factors.renewalUrgency >= 7) reasons.push(`renewal is due in ${daysUntil(vendor.renewalDate, now)} days`);
  if (factors.staleReview >= 6) reasons.push('review evidence is stale or missing');
  if (reasons.length === 0) reasons.push('no major risk drivers are currently active');
  return `${score}/100 ${tier} risk: ${reasons.join('; ')}.`;
}

export function sortByRisk(vendors, now = new Date()) {
  return [...vendors]
    .map((vendor) => ({ ...vendor, risk: calculateVendorRisk(vendor, now) }))
    .sort((a, b) => b.risk.score - a.risk.score);
}
