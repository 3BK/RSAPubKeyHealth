# rsa-pub-key-health

`rsa-pub-key-health` is an audit-oriented Rust library for evaluating RSA public keys for statistical and structural red flags.

It is intended for certificate inventory review, crypto hygiene checks, CI/CD gates, and evidence generation. It does **not** certify that a key is authentic, trusted, unrevoked, quantum-safe, or generated from strong private primes.

## Checks

- RSA PEM/DER public key parsing
- Modulus bit length policy
- Public exponent sanity check
- Ones/zeros ratio
- Shannon entropy
- Monobit z-score and approximate p-value
- Longest zero run
- Longest one run
- Repeated byte block detection
- Sparse modulus window detection
- Small-factor trial division screen
- Optional shared-factor / shared-prime scan against a caller-provided modulus corpus
- JSON-serializable audit report
- Compliance evidence support mapping

## Important limits

A public RSA key does not expose `p` and `q`. Therefore, a public-key-only scanner cannot directly prove whether `p` and `q` are strong primes, whether `p-1` or `q-1` are smooth, or whether the key came from a weak RNG. Population tests such as GCD scans can detect shared factors when enough moduli are available.

## Example

```rust
use rsa_pub_key_health::{analyze_pem, AuditPolicy};

let pem = std::fs::read_to_string("public.pem")?;
let report = analyze_pem(&pem, &AuditPolicy::default())?;
println!("{report:#?}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

CLI-style example:

```bash
cargo run --example analyze -- public.pem
```

## Audit posture

The library emits supporting evidence for PCI DSS 4.x, NIST SP 800-53 Rev. 5, CIS Controls v8, and DISA STIG/SRG-style cryptographic review. It is not a substitute for organizational scoping, QSA/assessor review, FIPS validation, certificate path validation, revocation checking, or key lifecycle governance.
