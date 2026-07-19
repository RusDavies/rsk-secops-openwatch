# RSK SecOps OpenWatch

OpenWatch is the public-safe core for vendor security advisory monitoring and
vendor-risk signal normalization.

This repository currently contains:

- Advisory source classification and normalization helpers.
- Fixture-backed parsers for CSAF, CSAF VEX/OpenVEX, OSV, NVD, RSS, Atom, and
  JSON Feed style sources.
- Production payload validation helpers for advisory inputs.
- Advisory schema pinning and drift-check helpers.
- A small explainable vendor-risk scoring model.
- Node test coverage and public-safe advisory fixtures.

## Development

Install dependencies:

```sh
npm install
```

Run checks:

```sh
npm test
```

## Public-Safety Boundary

This repository must stay downstream-agnostic. It should not describe private
products, private project management, customer/prospect data, billing strategy,
private deployment, support operations, or commercial roadmap details.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
