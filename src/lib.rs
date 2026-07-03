#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Audit-oriented RSA public key health checks.
//!
//! This crate evaluates *public* RSA keys for statistical and structural red flags:
//! bit balance, Shannon entropy, monobit frequency, long zero/one runs, repeated
//! byte blocks, sparse windows, suspicious public exponents, modulus length, and
//! optional shared-factor screening against a caller-provided corpus.
//!
//! Important: statistical tests are sanity checks, not proof of cryptographic
//! strength or authenticity. A well-balanced modulus can still be malicious,
//! revoked, wrongly issued, ROCA-affected, or generated from weak private primes.
//! Conversely, a single statistical warning should be triaged before operational
//! rejection.

mod math;
mod parser;
mod report;
mod short_sleeve;
mod tests;
mod wiener;

pub use parser::{PublicKeyMaterial, parse_rsa_public_key_der, parse_rsa_public_key_pem};
pub use report::{
    ComplianceControl, Finding, FindingSeverity, HealthReport, HealthStatus, ShortSleeveStatistics,
    TestId, WienerStatistics,
};

pub use tests::{AuditPolicy, SharedFactorFinding};

use crate::math::BigExt;
use crate::report::{FindingEvidence, Framework};
use sha2::{Digest, Sha256};

/// Analyze an RSA public key encoded as PEM.
pub fn analyze_pem(input: &str, policy: &AuditPolicy<'_>) -> Result<HealthReport, KeyHealthError> {
    let material = parse_rsa_public_key_pem(input)?;
    Ok(analyze_material(&material, policy))
}

/// Analyze an RSA public key encoded as DER.
pub fn analyze_der(input: &[u8], policy: &AuditPolicy<'_>) -> Result<HealthReport, KeyHealthError> {
    let material = parse_rsa_public_key_der(input)?;
    Ok(analyze_material(&material, policy))
}

/// Analyze extracted public key material.
pub fn analyze_material(material: &PublicKeyMaterial, policy: &AuditPolicy<'_>) -> HealthReport {
    let mut findings = Vec::new();
    let n = material.modulus.as_slice();
    let bit_len = material.modulus_bit_len;
    let ones = math::count_ones(n, bit_len);
    let zeros = bit_len.saturating_sub(ones);
    let ones_ratio = if bit_len == 0 {
        0.0
    } else {
        ones as f64 / bit_len as f64
    };
    let entropy = math::shannon_entropy(n);
    let monobit = math::monobit_z_score(bit_len, ones);
    let monobit_p = math::two_sided_normal_p_value(monobit.abs());
    let longest_zero_run = math::longest_bit_run(n, bit_len, false);
    let longest_one_run = math::longest_bit_run(n, bit_len, true);
    let repeated_block = math::repeated_block_report(
        n,
        policy.repeated_block_size,
        policy.repeated_block_min_count,
    );
    let sparse = math::sparse_window_report(
        n,
        policy.sparse_window_bytes,
        policy.sparse_window_max_nonzero_bytes,
    );
    let small_factor = math::small_factor_screen(n, policy.small_factor_limit);
    let fermat = math::fermat_near_square_screen(n, policy.fermat_iterations);
    let shared = tests::shared_factor_scan(n, policy.shared_moduli);

    let n_big = math::Big::from_be(material.modulus.as_slice());
    let e_big = math::Big::from_be(material.exponent.as_slice());

    let mut wiener_stats = WienerStatistics {
        checked: policy.enable_wiener_attack_check,
        convergents_tested: 0,
        vulnerable: false,
        recovered_d_bits: None,
        recovered_p_bits: None,
        recovered_q_bits: None,
    };

    let mut short_sleeve_stats = Vec::new();

    if bit_len < policy.minimum_modulus_bits {
        findings.push(Finding::new(
            TestId::ModulusSize,
            FindingSeverity::High,
            format!(
                "RSA modulus is {bit_len} bits; policy minimum is {} bits",
                policy.minimum_modulus_bits
            ),
            FindingEvidence::new("modulus_bits", bit_len.to_string()),
        ));
    }

    if material.exponent.as_slice() != [0x01, 0x00, 0x01] {
        findings.push(Finding::new(
            TestId::PublicExponent,
            FindingSeverity::Medium,
            "Public exponent is not 65537; verify this is intentional and accepted by policy"
                .to_string(),
            FindingEvidence::new("exponent_hex", math::hex(material.exponent.as_slice())),
        ));
    }

    if ones_ratio < policy.ones_ratio_min || ones_ratio > policy.ones_ratio_max {
        findings.push(Finding::new(
            TestId::BitBalance,
            FindingSeverity::High,
            format!(
                "Modulus bit balance is outside policy range: {:.4}% ones",
                ones_ratio * 100.0
            ),
            FindingEvidence::new("ones_ratio", format!("{ones_ratio:.8}")),
        ));
    }

    if entropy < policy.minimum_shannon_entropy_bits_per_byte {
        findings.push(Finding::new(
            TestId::ShannonEntropy,
            FindingSeverity::Low,
            format!("Byte Shannon entropy is below policy floor: {entropy:.6} bits/byte"),
            FindingEvidence::new("entropy_bits_per_byte", format!("{entropy:.8}")),
        ));
    }

    if monobit_p < policy.monobit_min_p_value {
        findings.push(Finding::new(
            TestId::Monobit,
            FindingSeverity::Medium,
            format!("Monobit test p-value below policy floor: {monobit_p:.8}"),
            FindingEvidence::new("monobit_z", format!("{monobit:.8}")),
        ));
    }

    if longest_zero_run >= policy.max_zero_run_bits {
        findings.push(Finding::new(
            TestId::LongZeroRun,
            FindingSeverity::High,
            format!(
                "Longest zero run is {longest_zero_run} bits; threshold is {}",
                policy.max_zero_run_bits
            ),
            FindingEvidence::new("longest_zero_run_bits", longest_zero_run.to_string()),
        ));
    }

    if longest_one_run >= policy.max_one_run_bits {
        findings.push(Finding::new(
            TestId::LongOneRun,
            FindingSeverity::Medium,
            format!(
                "Longest one run is {longest_one_run} bits; threshold is {}",
                policy.max_one_run_bits
            ),
            FindingEvidence::new("longest_one_run_bits", longest_one_run.to_string()),
        ));
    }

    if let Some(r) = repeated_block {
        findings.push(Finding::new(
            TestId::RepeatedBlocks,
            FindingSeverity::High,
            format!(
                "Repeated {}-byte block appears {} times",
                r.block_size, r.count
            ),
            FindingEvidence::new("block_hex", math::hex(&r.block)),
        ));
    }

    if let Some(s) = sparse {
        findings.push(Finding::new(
            TestId::SparseWindow,
            FindingSeverity::High,
            format!(
                "Sparse {}-byte window found with {} non-zero bytes",
                s.window_bytes, s.nonzero_bytes
            ),
            FindingEvidence::new("offset", s.offset.to_string()),
        ));
    }

    if let Some(factor) = small_factor {
        findings.push(Finding::new(
            TestId::SmallFactor,
            FindingSeverity::Critical,
            format!("Modulus is divisible by small factor {factor}"),
            FindingEvidence::new("factor", factor.to_string()),
        ));
    }

    if fermat {
        findings.push(Finding::new(
            TestId::FermatNearSquare,
            FindingSeverity::Critical,
            "Fermat screen indicates factors may be unusually close".to_string(),
            FindingEvidence::new("fermat_iterations", policy.fermat_iterations.to_string()),
        ));
    }

    for s in shared {
        findings.push(Finding::new(
            TestId::SharedFactor,
            FindingSeverity::Critical,
            format!(
                "Modulus shares a non-trivial factor with corpus entry {}",
                s.index
            ),
            FindingEvidence::new("gcd_hex", math::hex(&s.gcd_be)),
        ));
    }

    if policy.enable_wiener_attack_check {
        let check = wiener::wiener_check(&n_big, &e_big);

        wiener_stats.convergents_tested = check.convergents_tested;

        if let Some(result) = check.result {
            wiener_stats.vulnerable = true;
            wiener_stats.recovered_d_bits = Some(result.d.bits());
            wiener_stats.recovered_p_bits = Some(result.p.bits());
            wiener_stats.recovered_q_bits = Some(result.q.bits());

            findings.push(Finding::new(
                TestId::WienerSmallPrivateExponent,
                FindingSeverity::Critical,
                "RSA public key is vulnerable to Wiener's small-private-exponent attack"
                    .to_string(),
                FindingEvidence::new(
                    "wiener_recovery",
                    format!(
                        "d_bits={}, p_bits={}, q_bits={}",
                        result.d.bits(),
                        result.p.bits(),
                        result.q.bits()
                    ),
                ),
            ));
        }
    }

    for limb_bits in policy.short_sleeve_limb_bits {
        let scan = short_sleeve::scan_short_sleeve_statistics(
            material.modulus.as_slice(),
            *limb_bits,
            policy.short_sleeve_max_nonzero_bytes_per_limb,
            policy.short_sleeve_minimum_sparse_ratio,
        );

        if scan.finding_triggered {
            findings.push(Finding::new(
                TestId::ShortSleeveRsaPattern,
                FindingSeverity::High,
                format!(
                    "RSA modulus has sparse limb pattern consistent with short-sleeve RSA: \
                     {} sparse limbs out of {} at {}-bit limb width",
                    scan.sparse_limbs, scan.limbs, scan.limb_bits
                ),
                FindingEvidence::new("sparse_ratio", format!("{:.6}", scan.sparse_ratio)),
            ));
        }

        short_sleeve_stats.push(ShortSleeveStatistics {
            limb_bits: scan.limb_bits,
            limbs: scan.limbs,
            sparse_limbs: scan.sparse_limbs,
            sparse_ratio: scan.sparse_ratio,
            max_nonzero_bytes_per_limb: scan.max_nonzero_bytes_per_limb,
            minimum_sparse_ratio: scan.minimum_sparse_ratio,
            finding_triggered: scan.finding_triggered,
        });
    }

    let status = HealthStatus::from_findings(&findings);
    let spki_sha256 = Sha256::digest(material.subject_public_key_der.as_slice());

    HealthReport {
        status,
        modulus_bits: bit_len,
        exponent_hex: math::hex(material.exponent.as_slice()),
        spki_sha256_hex: math::hex(&spki_sha256),
        ones,
        zeros,
        ones_ratio,
        shannon_entropy_bits_per_byte: entropy,
        monobit_z_score: monobit,
        monobit_p_value: monobit_p,
        longest_zero_run_bits: longest_zero_run,
        longest_one_run_bits: longest_one_run,
        findings,
        wiener: wiener_stats,
        short_sleeve: short_sleeve_stats,
        compliance: compliance_controls(),
    }
}

/// Compliance-oriented mapping for generated evidence. This is a support map, not
/// a claim of full compliance or certification.
pub fn compliance_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl::new(
            Framework::PciDss40,
            "Req. 3/4/12",
            "Supports cryptographic key/certificate inventory quality evidence, transmission protection review, and repeatable security testing evidence.",
        ),
        ComplianceControl::new(
            Framework::NistSp80053Rev5,
            "SC-12, SC-13, SI-7, RA-5, CA-7, AU-12",
            "Supports cryptographic key establishment/management review, cryptographic protection review, integrity checking, vulnerability monitoring, continuous monitoring, and audit record generation.",
        ),
        ComplianceControl::new(
            Framework::CisControlsV8,
            "3, 4, 8",
            "Supports data protection, secure configuration evidence, and audit logging / monitoring evidence for cryptographic assets.",
        ),
        ComplianceControl::new(
            Framework::DisaStig,
            "Application Security and Development STIG cryptography findings",
            "Supports evidence that cryptographic use is reviewed, documented, and commensurate with data protection requirements.",
        ),
    ]
}

/// Library error type.
#[derive(Debug, thiserror::Error)]
pub enum KeyHealthError {
    /// Key parsing failed.
    #[error("failed to parse RSA public key: {0}")]
    Parse(String),
}
