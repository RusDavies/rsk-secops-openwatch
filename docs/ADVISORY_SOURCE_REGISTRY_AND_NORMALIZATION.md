# Advisory source registry and normalization model

Status: MVP design baseline  
Date: 2026-06-03  
Related decision: [`docs/ADVISORY_EXCHANGE_STANDARDS_DUE_DILIGENCE.md`](ADVISORY_EXCHANGE_STANDARDS_DUE_DILIGENCE.md)

## Decision

OpenWatch should model advisory ingestion as a **source registry plus normalization adapters**, not as a single universal feed.

The product should ingest whichever advisory evidence a vendor or public ecosystem actually provides, preserve upstream semantics, and normalize it into a OpenWatch vendor-signal model for matching, triage, and customer review.

This is deliberately not a proprietary OpenWatch advisory exchange. CSAF/VEX/OpenVEX/OSV/NVD/feed ingestion comes first; federation or customer-scoped OpenWatch feeds stay deferred until beta evidence proves an actual gap.

## Source registry taxonomy

Each configured source should have a source type, source URL, optional vendor binding, authentication posture, owner, and health/freshness metadata.

Baseline source types:

| Source type | Use | Semantics | Customer-view authorization |
| --- | --- | --- | --- |
| `csaf_provider_metadata` | Discover a vendor CSAF provider and advisory locations. | Structured provider metadata. | Never. |
| `csaf_document` | Ingest a CSAF 2.0 security advisory. | Structured advisory evidence. | Never. |
| `csaf_vex` | Ingest CSAF-profile VEX status. | Structured vulnerability exploitability evidence. | Never. |
| `openvex` | Ingest lightweight VEX statements. | Structured vulnerability exploitability evidence. | Never. |
| `osv` | Ingest open-source vulnerability records. | Structured package vulnerability evidence. | Never. |
| `nvd` | Enrich CVE/CPE details from NVD APIs/feeds. | Public vulnerability enrichment. | Never. |
| `rss` | Monitor vendor advisory/blog/status-feed items. | Discovery/syndication only. | Never. |
| `atom` | Monitor vendor advisory/blog/status-feed items. | Discovery/syndication only. | Never. |
| `json_feed` | Monitor vendor advisory/blog/status-feed items. | Discovery/syndication only. | Never. |
| `vendor_html` | Monitor vendor advisory pages without feeds. | Discovery/evidence only. | Never. |
| `trust_center` | Monitor vendor trust/security-center changes. | Discovery/evidence only. | Never. |
| `customer_authenticated_portal` | Track customer-provided portal evidence where authorized. | Authenticated/customer-specific evidence. | Never by itself. |
| `manual_customer_evidence` | Track manually uploaded or recorded customer evidence. | Authenticated/manual evidence. | Never by itself. |
| `partner_feed` | Ingest licensed/partner source data. | Depends on partner contract/source. | Never by itself. |

Important boundary: **source evidence does not authorize customer-facing viewing**. Customer posture pages, notices, and evidence packages remain tenant workflows with named authenticated recipients, expiry, revocation, and audit.

## Source registration fields

Minimum registry fields:

- `sourceType`
- `name`
- `url`
- `vendorId` / `vendorName`, if bound to a known vendor
- `authentication`: `none`, `customer_provided`, `partner`, `api_key`, `oauth`, or future enum
- `owner`
- `notes`
- health/freshness fields added by source monitoring jobs

## Normalized advisory signal fields

Every parser/adapter should emit a normalized advisory signal with:

- source identity: `sourceType`, `sourceName`, `sourceUrl`
- source semantics: `structured`, `discoveryOnly`, `requiresAuthentication`, `canAuthorizeCustomerViewing=false`
- observation time: `observedAt`
- preserved upstream IDs:
  - `cve`
  - `csafDocumentTrackingId`
  - `osvId`
  - `nvdCveId`
  - `feedGuid`
  - `vendorAdvisoryId`
  - `signatureId`
- vendor/product matching hints:
  - `vendorCandidate`
  - `affectedProducts`
- normalized triage fields:
  - `category`: `vulnerability`, `breach`, `outage`, `trust_posture`, `compliance`, `security_advisory`, `other`
  - `status`: `new`, `under_investigation`, `affected`, `not_affected`, `fixed`, `mitigated`, `withdrawn`, `informational`, `unknown`
  - `severity`
  - `confidence`
  - `title`
  - `summary`
  - `remediation`
  - `references`
  - `revisions`
- `raw` payload pointer or bounded raw payload for audit/debugging

## Adapter expectations

Before claiming support for a source type, add fixture-based parser tests that prove:

1. The parser preserves upstream IDs and canonical URLs.
2. The parser maps source-native status into OpenWatch status without overclaiming.
3. The parser preserves enough raw/source evidence for human review.
4. The parser rejects unsupported or malformed source payloads safely.
5. The parser does not treat feed possession, domain match, or portal evidence as authorization to publish/share customer-facing information.
6. The parser handles updates/revisions without creating duplicate alerts solely because wording changed.

## Matching and triage implications

The normalized signal is not automatically true for a tenant. It is review evidence.

Matching should use:

- exact vendor binding where configured;
- vendor/product names and aliases;
- CVE/product/CPE/package references;
- source type and confidence;
- advisory status and revision history;
- customer-specific vendor inventory context.

A signal can create a reviewable alert, but a customer-facing status page or notice still requires explicit workflow approval.

## Non-claims for MVP

Until beta evidence proves otherwise, OpenWatch should not claim:

- proprietary advisory federation;
- a OpenWatch-standard customer-scoped advisory feed;
- complete CSAF ecosystem coverage;
- universal vendor advisory normalization;
- automatic truth or automatic publication from source evidence.

The accurate MVP claim is: **OpenWatch monitors and normalizes configured advisory sources into reviewable vendor-risk signals.**

## Live fetcher schema/parser pinning gate

Future live network fetchers must pass the schema/parser pinning gate before they can be enabled or described as standards-conformant. The gate is intentionally stricter than the local fixture parsers:

- CSAF 2.0 and CSAF VEX require pinned official CSAF JSON Schema evidence; VEX also requires profile/status validation evidence.
- OpenVEX, OSV, NVD, and JSON Feed require pinned schema/profile source URLs, versions/API versions where applicable, and sha256 digests.
- RSS and Atom require a maintained XML/feed parser pinned by package-lock evidence, with DOCTYPE and external entity handling disabled.
- Every live source type needs an accepted drift-test fixture so schema drift is detected before enabling ingestion.

A live fetcher request with missing pins, weak digests, non-HTTPS schema sources, or missing drift tests must stay disabled.

## Implementation anchor

The baseline model is encoded in `lib/advisory-source-normalization.mjs` with tests in `tests/advisory-source-normalization.test.mjs`. Concrete parser fixture coverage lives in `lib/advisory-fixture-parsers.mjs`, `tests/advisory-parser-fixtures.test.mjs`, and `tests/fixtures/advisory-sources/`; these fixtures prove normalization contracts for CSAF 2.0, CSAF VEX, OpenVEX, OSV, NVD, RSS, Atom, and JSON Feed inputs, including malformed-payload rejection and the rule that source evidence cannot authorize customer-facing publication. Production adapter hardening lives in `lib/advisory-production-adapters.mjs` with tests in `tests/advisory-production-adapters.test.mjs`; it adds fail-closed parsing/validation around the fixture parsers, including payload size limits, JSON depth limits, feed item limits, XML DOCTYPE/entity rejection, source-specific status/profile validation, malformed-payload telemetry, and fixture-parity checks. Live network fetcher readiness lives in `lib/advisory-schema-pinning.mjs` with tests in `tests/advisory-schema-pinning.test.mjs`; it requires official schema/parser artifacts, versions/digests, HTTPS schema source URLs, XML parser entity/DOCTYPE-disabled evidence, and accepted drift-test fixtures before standards conformance or live ingestion can be enabled. The concrete source-controlled pin manifest is `config/advisory-schema-pin-manifest.json`, validated by `lib/advisory-schema-pin-manifest.mjs` and `tests/advisory-schema-pin-manifest.test.mjs`; it records current CSAF/OpenVEX/OSV/NVD/JSON Feed schema/profile URLs and sha256 pins, RSS/Atom `fast-xml-parser` package-lock evidence, RSS/Atom upstream spec URL pins, and accepted drift fixture paths/digests while keeping `liveFetchEnabled: false`. Drift checking lives in `lib/advisory-schema-drift-check.mjs` and `scripts/check-advisory-schema-pins.mjs` (`npm run check:advisory-schema-pins`); it fetches pinned upstream artifacts, compares sha256 digests, validates local fixture/package-lock evidence, emits text or JSON review evidence, and never enables live fetchers automatically.
