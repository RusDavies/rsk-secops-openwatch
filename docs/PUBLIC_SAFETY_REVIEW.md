# Public Safety Review

Status: draft, not approved for public release claims

## Review Scope

The initial OpenWatch split includes public-safe advisory source helpers,
advisory parser fixtures, advisory schema pinning checks, and vendor-risk
scoring code.

## Required Checks

- No private customer, prospect, outreach, billing, pricing, Discord, or
  management-control material.
- No secrets, tokens, private domains, private support mailboxes, or deployment
  credentials.
- No private mixed-repository git history.
- No downstream-commercial product assumptions in README, package metadata,
  docs, tests, fixtures, or scripts.
- No generated screenshots, PDF manuals, private audit artifacts, or local build
  output.

## Current Decision

The repository is suitable for a clean public-safe initial push only after the
keyword and secret scans pass and the remote is created public intentionally.
