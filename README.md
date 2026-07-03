# rsa_pub_key_health

Audit-oriented RSA public key health checks for institutional, compliance, and operational review workflows.

`rsa_pub_key_health` analyzes **public RSA key material** and emits a structured `HealthReport` containing statistical, structural, and vulnerability-oriented evidence. The crate is designed for repeatable review of RSA public keys used in certificates, SSH host keys, code-signing trust, service authentication, and other enterprise cryptographic inventories.

> This library analyzes public keys. It does not prove that a key is trustworthy, authorized, unrevoked, correctly issued, or suitable for every operational purpose. Statistical checks are sanity checks and anomaly indicators, not cryptographic proofs.

## Current capabilities

The library currently evaluates RSA public keys for:

- RSA modulus size policy compliance
- public exponent sanity, including non-`65537` detection
- ones/zeros bit balance
- byte-level Shannon entropy
- monobit frequency and approximate two-sided p-value
- longest zero-bit run
- longest one-bit run
- repeated byte blocks
- sparse byte windows
- small-factor trial division screening
- Fermat near-square / close-prime screening
- shared-factor detection against caller-provided modulus corpora
- Wiener small-private-exponent attack screening
- short-sleeve / sparse-limb RSA structure screening
- SPKI SHA-256 fingerprint generation
- compliance-oriented evidence mapping

## Supported key input formats

The parser supports:

- SPKI public key PEM:
  - `-----BEGIN PUBLIC KEY-----`
- PKCS#1 RSA public key PEM:
  - `-----BEGIN RSA PUBLIC KEY-----`
- SPKI DER
- PKCS#1 RSA public key DER

The parser also includes a custom large-key PKCS#1 path for RSA public keys larger than the default `rsa` crate public-key size limit. This allows inspection of high-assurance RSA public keys such as RSA-7680.

### Certificate input note

A PEM object beginning with:

```text
-----BEGIN CERTIFICATE-----
```

is an X.509 certificate, not a raw public key. Extract the embedded public key first, for example:

```bash
openssl x509 \
  -in certificate.pem \
  -pubkey \
  -noout \
  -out public.spki.pem
```

Then analyze `public.spki.pem`.

To emit a PKCS#1 RSA public key from the extracted SPKI public key:

```bash
openssl rsa \
  -pubin \
  -in public.spki.pem \
  -RSAPublicKey_out \
  -out public.pkcs1.pem
```

## Example usage

Analyze a PEM public key using the example binary:

```bash
cargo run --example analyze -- public.spki.pem
```

Run the full test suite:

```bash
cargo test --all-targets -- --nocapture
```

Run Clippy with warnings treated as errors:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Rust API example

```rust
use rsa_pub_key_health::{analyze_pem, AuditPolicy, HealthStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pem = std::fs::read_to_string("public.spki.pem")?;

    let report = analyze_pem(
        &pem,
        &AuditPolicy::default(),
    )?;

    println!("status: {:?}", report.status);
    println!("modulus bits: {}", report.modulus_bits);
    println!("SPKI SHA-256: {}", report.spki_sha256_hex);

    if report.status != HealthStatus::Pass {
        for finding in &report.findings {
            println!("{:?}: {}", finding.severity, finding.message);
        }
    }

    Ok(())
}
```

## Policy profiles

The crate includes policy constructors for common RSA key sizes:

```rust
AuditPolicy::rsa2048_policy();
AuditPolicy::rsa3072_policy();
AuditPolicy::rsa4096_policy();
AuditPolicy::rsa7680_policy();
```

The default policy is the institutional RSA-3072 baseline.

### RSA-2048

RSA-2048 is supported as a compatibility policy. It is useful for legacy certificates and existing deployments, but RSA-3072 or stronger should be preferred for new long-lived institutional systems where feasible.

Recommended Shannon entropy advisory floor:

```rust
minimum_shannon_entropy_bits_per_byte: 7.10
```

### RSA-3072

RSA-3072 is the default institutional baseline policy.

Recommended Shannon entropy advisory floor:

```rust
minimum_shannon_entropy_bits_per_byte: 7.39
```

### RSA-4096

RSA-4096 is supported for higher-assurance or longer-lived use cases.

Recommended Shannon entropy advisory floor:

```rust
minimum_shannon_entropy_bits_per_byte: 7.50
```

This value is intentionally advisory. Byte-level entropy over a finite RSA modulus is noisy and should not be treated as a standalone proof of key quality.

### RSA-7680

RSA-7680 is supported for high-assurance audit and inspection workflows. The parser includes a custom large-key PKCS#1 path because the standard `rsa` crate decode path may reject RSA keys larger than its default public-key size ceiling.

Recommended Shannon entropy advisory floor:

```rust
minimum_shannon_entropy_bits_per_byte: 7.77
```

## Shannon entropy interpretation

Byte-level Shannon entropy is an anomaly indicator only.

A maximum byte entropy value is `8.0 bits/byte`, but RSA moduli provide finite sample sizes:

| RSA size | Modulus bytes | Recommended advisory floor |
|---:|---:|---:|
| RSA-2048 | 256 | 7.10 |
| RSA-3072 | 384 | 7.39 |
| RSA-4096 | 512 | 7.50 |
| RSA-7680 | 960 | 7.77 |

Entropy findings should normally be `Low` severity unless correlated with stronger indicators such as sparse windows, repeated blocks, abnormal bit balance, weak-key blocklist matches, ROCA, Debian weak-key patterns, small factors, or shared factors.

## Wiener small-private-exponent check

The crate includes a Wiener check for RSA public keys whose private exponent may be unusually small.

The report includes negative evidence even when the key is clean:

```json
"wiener": {
  "checked": true,
  "convergents_tested": 8,
  "vulnerable": false,
  "recovered_d_bits": null,
  "recovered_p_bits": null,
  "recovered_q_bits": null
}
```

If the attack succeeds, the finding is emitted as:

```rust
TestId::WienerSmallPrivateExponent
FindingSeverity::Critical
```

A successful Wiener result means the key must be treated as compromised and should be revoked and replaced.

## Short-sleeve / sparse-limb RSA checks

The crate includes short-sleeve sparse-limb scanning. This looks for moduli with regularly sparse limb structure, which may indicate broken big-integer generation or polynomially structured RSA keys.

The report includes per-limb-width statistics even when clean:

```json
"short_sleeve": [
  {
    "limb_bits": 32,
    "limbs": 64,
    "sparse_limbs": 0,
    "sparse_ratio": 0.0,
    "max_nonzero_bytes_per_limb": 2,
    "minimum_sparse_ratio": 0.75,
    "finding_triggered": false
  }
]
```

Default limb widths:

```rust
&[32, 64, 128]
```

Default sparse-limb threshold:

```rust
short_sleeve_max_nonzero_bytes_per_limb: 2
short_sleeve_minimum_sparse_ratio: 0.75
```

A short-sleeve heuristic finding is emitted as:

```rust
TestId::ShortSleeveRsaPattern
FindingSeverity::High
```

This is an anomaly indicator. It should not be treated as confirmed factorization unless a separate polynomial/factor-recovery check actually recovers `p` and `q`.

## Shared-factor scanning

The policy can accept a caller-provided corpus of RSA moduli:

```rust
pub shared_moduli: &'a [&'a [u8]]
```

The analyzer computes pairwise GCD against the supplied corpus and emits a critical finding if a non-trivial shared factor is found:

```rust
TestId::SharedFactor
FindingSeverity::Critical
```

Shared RSA factors are catastrophic. Affected keys should be treated as compromised.

## Health status model

Overall status is derived from findings:

| Highest severity present | Status |
|---|---|
| No findings | `Pass` |
| Info / Low / Medium | `Review` |
| High | `Fail` |
| Critical | `Critical` |

Entropy-only findings should generally remain advisory so that statistically normal keys are not incorrectly treated as failed solely due to finite-sample entropy estimator noise.

## Current report fields

`HealthReport` includes:

- `status`
- `modulus_bits`
- `exponent_hex`
- `spki_sha256_hex`
- `ones`
- `zeros`
- `ones_ratio`
- `shannon_entropy_bits_per_byte`
- `monobit_z_score`
- `monobit_p_value`
- `longest_zero_run_bits`
- `longest_one_run_bits`
- `findings`
- `wiener`
- `short_sleeve`
- `compliance`

## Compliance evidence mapping

The compliance section is a support map, not a claim of certification or full compliance.

The current report maps evidence to:

- PCI DSS 4.x family
- NIST SP 800-53 Rev. 5
- CIS Controls v8
- DISA STIG / SRG cryptography evidence

The intent is to provide repeatable audit artifacts showing that cryptographic public-key material has been reviewed for structural and statistical anomalies.

## Important limitations

This crate does **not** currently prove:

- that a certificate is trusted
- that a certificate chain is valid
- that a certificate is unexpired
- that a certificate has not been revoked
- that the issuer was authorized
- that the private key is protected
- that the key was created inside an approved HSM
- that the key is free of all possible cryptographic weaknesses
- that the key is compliant with all organizational requirements

Use this crate as part of a broader PKI, certificate management, vulnerability management, and cryptographic governance process.

## Debug output

Parser debug output should be disabled or gated for production use. Development diagnostics such as parser path logging are useful during tests, but the library should not print key material or internal parser diagnostics by default.

Recommended pattern:

```rust
#[cfg(test)]
eprintln!("[DEBUG] Trying SPKI PEM parser");
```

## RSA-7680 testing note

RSA-7680 key generation is computationally expensive. Test profile optimization is recommended:

```toml
[profile.dev]
opt-level = 3

[profile.test]
opt-level = 3
```

For CI, consider marking RSA-7680 generated-key tests as ignored by default and running them explicitly during long-form validation.

```rust
#[ignore = "RSA-7680 key generation is slow; run explicitly for long-form validation"]
```

Run ignored tests explicitly:

```bash
cargo test --test rsa7680 -- --ignored --nocapture
```

## Security posture

This project is intended for defensive review of public cryptographic material. It should not be used to process private production keys unless there is a documented, approved, and controlled operational need.

For known-bad key detection, future work should add curated blocklist support with source provenance, artifact hashes, retrieval dates, approval records, and scanner version evidence.

## Suggested future work

Planned or recommended future enhancements:

- X.509 certificate input support
- CSR input support
- SSH public key parsing
- JWK / JWKS parsing
- DNSSEC DNSKEY parsing
- DKIM TXT public-key parsing
- generalized known-bad blocklist framework
- Fortinet/Fortigate leak blocklist matching
- keypair/GitKraken CVE-2021-41117 blocklist matching
- ROCA fingerprint integration
- Debian weak-key corpus integration
- public/private key exposure blocklist matching
- optional polynomial RSA confirmation for short-sleeve findings
- JSON schema documentation
- stable CLI exit-code contract
- fuzzing corpus for malformed PEM, DER, SSH, JWK, CSR, and certificate inputs

## License

Licensed under either of:

- MIT
- Apache-2.0

at your option.
