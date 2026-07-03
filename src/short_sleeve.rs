//! Short-sleeve / sparse-limb RSA modulus structure checks.
//!
//! This module looks for RSA public moduli with regularly sparse limb structure.
//! Such structure may indicate broken big-integer generation where each limb
//! contains only a small amount of random material and the remaining bytes are
//! zero or otherwise highly constrained.
//!
//! These checks are anomaly detectors. A sparse-limb finding is not, by itself,
//! proof that the modulus has been factored. Confirmed factor recovery should
//! be reported separately as a critical finding.

/// Summary of a short-sleeve sparse-limb scan.
///
/// This structure is returned for every scan, even when no finding is triggered.
/// It is intended for audit evidence and JSON reporting.
#[derive(Debug, Clone, PartialEq)]
pub struct ShortSleeveScan {
    /// Limb width inspected, in bits.
    pub limb_bits: usize,

    /// Number of complete or partial limbs inspected.
    pub limbs: usize,

    /// Number of limbs considered sparse.
    pub sparse_limbs: usize,

    /// Ratio of sparse limbs to total inspected limbs.
    pub sparse_ratio: f64,

    /// Maximum number of non-zero bytes allowed before a limb is not considered sparse.
    pub max_nonzero_bytes_per_limb: usize,

    /// Minimum sparse-limb ratio required to trigger a finding.
    pub minimum_sparse_ratio: f64,

    /// Whether this scan exceeded the configured sparse-limb threshold.
    pub finding_triggered: bool,
}


/// Scan an RSA modulus for short-sleeve / sparse-limb structure.
///
/// This function always returns statistics, even when no finding is triggered.
///
/// The modulus is interpreted as a big-endian byte string and split from the
/// least-significant end into limbs of `limb_bits`. This is intentional because
/// big-integer limb layouts are usually least-significant-limb oriented.
///
/// A limb is considered sparse when it contains no more than
/// `max_nonzero_bytes_per_limb` non-zero bytes.
///
/// Invalid or unsupported `limb_bits` values return a non-triggered scan rather
/// than panicking.
///
/// # Parameters
///
/// - `modulus_be`: RSA modulus in minimally encoded big-endian form.
/// - `limb_bits`: limb width to evaluate, usually 32, 64, or 128.
/// - `max_nonzero_bytes_per_limb`: sparsity threshold per limb.
/// - `minimum_sparse_ratio`: ratio required to trigger a finding.
///
/// # Returns
///
/// A [`ShortSleeveScan`] containing scan statistics and trigger state.
#[must_use]
pub fn scan_short_sleeve_statistics(
    modulus_be: &[u8],
    limb_bits: usize,
    max_nonzero_bytes_per_limb: usize,
    minimum_sparse_ratio: f64,
) -> ShortSleeveScan {
    if limb_bits == 0 || limb_bits % 8 != 0 {
        return ShortSleeveScan {
            limb_bits,
            limbs: 0,
            sparse_limbs: 0,
            sparse_ratio: 0.0,
            max_nonzero_bytes_per_limb,
            minimum_sparse_ratio,
            finding_triggered: false,
        };
    }

    let limb_bytes = limb_bits / 8;

    if limb_bytes == 0 || modulus_be.is_empty() {
        return ShortSleeveScan {
            limb_bits,
            limbs: 0,
            sparse_limbs: 0,
            sparse_ratio: 0.0,
            max_nonzero_bytes_per_limb,
            minimum_sparse_ratio,
            finding_triggered: false,
        };
    }

    let mut limbs = 0usize;
    let mut sparse_limbs = 0usize;

    for limb in modulus_be.rchunks(limb_bytes) {
        limbs += 1;

        let nonzero_bytes = limb.iter().filter(|byte| **byte != 0).count();

        if nonzero_bytes <= max_nonzero_bytes_per_limb {
            sparse_limbs += 1;
        }
    }

    let sparse_ratio = if limbs == 0 {
        0.0
    } else {
        sparse_limbs as f64 / limbs as f64
    };

    let finding_triggered = sparse_ratio >= minimum_sparse_ratio;

    ShortSleeveScan {
        limb_bits,
        limbs,
        sparse_limbs,
        sparse_ratio,
        max_nonzero_bytes_per_limb,
        minimum_sparse_ratio,
        finding_triggered,
    }
}

#[cfg(test)]
mod unit_tests {
    use super::{scan_short_sleeve_statistics};

    #[test]
    fn normal_dense_modulus_does_not_trigger() {
        let modulus = vec![0xff; 256];

        let scan = scan_short_sleeve_statistics(&modulus, 32, 2, 0.75);

        assert_eq!(scan.limb_bits, 32);
        assert_eq!(scan.limbs, 64);
        assert_eq!(scan.sparse_limbs, 0);
        assert!(!scan.finding_triggered);
    }

    #[test]
    fn sparse_32_bit_limbs_trigger() {
        let mut modulus = Vec::new();

        for _ in 0..64 {
            modulus.extend_from_slice(&[0x00, 0x00, 0x12, 0x34]);
        }

        let scan = scan_short_sleeve_statistics(&modulus, 32, 2, 0.75);

        assert_eq!(scan.limb_bits, 32);
        assert_eq!(scan.limbs, 64);
        assert_eq!(scan.sparse_limbs, 64);
        assert_eq!(scan.sparse_ratio, 1.0);
        assert!(scan.finding_triggered);
    }

    #[test]
    fn invalid_limb_width_does_not_panic() {
        let modulus = vec![0x00, 0x01, 0x02, 0x03];

        let scan = scan_short_sleeve_statistics(&modulus, 7, 2, 0.75);

        assert_eq!(scan.limb_bits, 7);
        assert_eq!(scan.limbs, 0);
        assert_eq!(scan.sparse_limbs, 0);
        assert_eq!(scan.sparse_ratio, 0.0);
        assert!(!scan.finding_triggered);
    }

    #[test]
    fn empty_modulus_does_not_trigger() {
        let scan = scan_short_sleeve_statistics(&[], 32, 2, 0.75);

        assert_eq!(scan.limbs, 0);
        assert_eq!(scan.sparse_limbs, 0);
        assert_eq!(scan.sparse_ratio, 0.0);
        assert!(!scan.finding_triggered);
    }
}
