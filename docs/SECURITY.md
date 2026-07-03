# Security Policy

## Supported versions

This initial release is pre-1.0. Pin exact versions in regulated CI/CD workflows and vendor-review all transitive dependencies.

## Threat model

This library accepts untrusted public key input and produces deterministic audit reports. It must not parse private keys, store secrets, or make network calls.

## Security design

- `#![forbid(unsafe_code)]`
- No private key material accepted
- No background telemetry
- No network access
- JSON evidence suitable for immutable logging
- Public-key-only limitations explicitly represented in documentation

## Responsible disclosure

Report security defects privately through the approved vulnerability intake process before public disclosure.

## Known limitations

- Statistical tests are sanity checks, not proof of good key generation.
- Public keys alone cannot prove prime strength.
- ROCA and Debian weak-key databases are not bundled; integrate approved enterprise vulnerability intelligence if required.
- FIPS 140-3 validation applies to cryptographic modules, not this audit library by itself.
