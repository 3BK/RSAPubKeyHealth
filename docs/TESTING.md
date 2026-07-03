# Testing

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run --example analyze -- public.pem
```

Recommended CI gates:

```bash
cargo audit
cargo deny check
cargo geiger
```

Recommended corpus tests:

- Known-good generated RSA-3072/4096 keys
- Moduli with long zero regions
- Moduli with repeated 16-byte blocks
- Known shared-factor fixtures
- Malformed PEM and DER inputs
- Keys with non-standard public exponents
