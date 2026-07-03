use crate::math;
use crate::math::BigExt;
use num_traits::{One, Zero};

/// Default limb widths used for short-sleeve / polynomial RSA structure checks.
///
/// These values look for sparse structure aligned on common machine-word or
/// big-integer limb boundaries.
pub const DEFAULT_SHORT_SLEEVE_LIMB_BITS: &[usize] = &[32, 64, 128];

/// Policy thresholds for audit execution.
#[derive(Debug, Clone)]
pub struct AuditPolicy<'a> {
    /// Minimum acceptable modulus size.
    pub minimum_modulus_bits: usize,

    /// Minimum ones ratio.
    pub ones_ratio_min: f64,

    /// Maximum ones ratio.
    pub ones_ratio_max: f64,

    /// Minimum byte Shannon entropy.
    pub minimum_shannon_entropy_bits_per_byte: f64,

    /// Minimum monobit p-value.
    pub monobit_min_p_value: f64,

    /// Maximum zero run before finding.
    pub max_zero_run_bits: usize,

    /// Maximum one run before finding.
    pub max_one_run_bits: usize,

    /// Repeated block size in bytes.
    pub repeated_block_size: usize,

    /// Repeated block count threshold.
    pub repeated_block_min_count: usize,

    /// Sparse window size in bytes.
    pub sparse_window_bytes: usize,

    /// Sparse window non-zero byte threshold.
    pub sparse_window_max_nonzero_bytes: usize,

    /// Trial division limit for small factors.
    pub small_factor_limit: u64,

    /// Fermat iterations for close-prime screen.
    pub fermat_iterations: usize,

    /// Optional corpus of modulus bytes for pairwise GCD shared-factor detection.
    pub shared_moduli: &'a [&'a [u8]],

    /// Enable the public-key Wiener small-private-exponent check.
    ///
    /// This check attempts to determine whether the public key is vulnerable
    /// to Wiener's attack by testing continued-fraction convergents of `e / n`.
    pub enable_wiener_attack_check: bool,

    /// Limb widths to inspect for short-sleeve / polynomial RSA structure.
    ///
    /// Common values are 32, 64, and 128 bits.
    pub short_sleeve_limb_bits: &'a [usize],

    /// Maximum number of non-zero bytes allowed in a limb before the limb is
    /// no longer considered sparse.
    pub short_sleeve_max_nonzero_bytes_per_limb: usize,

    /// Minimum ratio of sparse limbs required before raising a short-sleeve
    /// structural finding.
    pub short_sleeve_minimum_sparse_ratio: f64,
}

impl Default for AuditPolicy<'_> {
    fn default() -> Self {
        Self {
            minimum_modulus_bits: 3072,

            ones_ratio_min: 0.45,
            ones_ratio_max: 0.55,

            minimum_shannon_entropy_bits_per_byte: 7.39,

            monobit_min_p_value: 0.001,

            max_zero_run_bits: 96,
            max_one_run_bits: 128,

            repeated_block_size: 16,
            repeated_block_min_count: 4,

            sparse_window_bytes: 32,
            sparse_window_max_nonzero_bytes: 2,

            small_factor_limit: 10_000,
            fermat_iterations: 4096,

            shared_moduli: &[],

            enable_wiener_attack_check: true,

            short_sleeve_limb_bits: DEFAULT_SHORT_SLEEVE_LIMB_BITS,
            short_sleeve_max_nonzero_bytes_per_limb: 2,
            short_sleeve_minimum_sparse_ratio: 0.75,
        }
    }
}

impl<'a> AuditPolicy<'a> {
    /// Audit policy suitable for RSA-2048 public keys.
    ///
    /// NOTE:
    /// - Intended for compatibility with legacy RSA-2048 deployments.
    /// - Entropy thresholds are relaxed slightly because a 2048-bit modulus
    ///   only contains 256 bytes of sample data.
    /// - RSA-3072+ should remain the preferred policy for new systems.
    #[must_use]
    pub fn rsa2048_policy() -> Self {
        Self {
            minimum_modulus_bits: 2048,

            ones_ratio_min: 0.44,
            ones_ratio_max: 0.56,

            minimum_shannon_entropy_bits_per_byte: 7.10,

            monobit_min_p_value: 0.001,

            max_zero_run_bits: 96,
            max_one_run_bits: 128,

            repeated_block_size: 16,
            repeated_block_min_count: 4,

            sparse_window_bytes: 32,
            sparse_window_max_nonzero_bytes: 2,

            small_factor_limit: 10_000,
            fermat_iterations: 4096,

            shared_moduli: &[],

            enable_wiener_attack_check: true,

            short_sleeve_limb_bits: DEFAULT_SHORT_SLEEVE_LIMB_BITS,
            short_sleeve_max_nonzero_bytes_per_limb: 2,
            short_sleeve_minimum_sparse_ratio: 0.75,
        }
    }

    /// Audit policy suitable for RSA-3072 public keys.
    ///
    /// This is the default institutional baseline policy.
    #[must_use]
    pub fn rsa3072_policy() -> Self {
        Self::default()
    }

    /// Audit policy suitable for RSA-4096 public keys.
    #[must_use]
    pub fn rsa4096_policy() -> Self {
        Self {
            minimum_modulus_bits: 4096,

            ones_ratio_min: 0.44,
            ones_ratio_max: 0.555_555,

            minimum_shannon_entropy_bits_per_byte: 7.50,

            monobit_min_p_value: 0.001,

            max_zero_run_bits: 128,
            max_one_run_bits: 160,

            repeated_block_size: 16,
            repeated_block_min_count: 4,

            sparse_window_bytes: 32,
            sparse_window_max_nonzero_bytes: 2,

            small_factor_limit: 10_000,
            fermat_iterations: 8192,

            shared_moduli: &[],

            enable_wiener_attack_check: true,

            short_sleeve_limb_bits: DEFAULT_SHORT_SLEEVE_LIMB_BITS,
            short_sleeve_max_nonzero_bytes_per_limb: 2,
            short_sleeve_minimum_sparse_ratio: 0.75,
        }
    }

    /// Audit policy suitable for RSA-7680 public keys.
    #[must_use]
    pub fn rsa7680_policy() -> Self {
        Self {
            minimum_modulus_bits: 7680,

            ones_ratio_min: 0.45,
            ones_ratio_max: 0.55,

            minimum_shannon_entropy_bits_per_byte: 7.77,

            monobit_min_p_value: 0.001,

            max_zero_run_bits: 160,
            max_one_run_bits: 192,

            repeated_block_size: 16,
            repeated_block_min_count: 4,

            sparse_window_bytes: 32,
            sparse_window_max_nonzero_bytes: 2,

            small_factor_limit: 10_000,
            fermat_iterations: 16_384,

            shared_moduli: &[],

            enable_wiener_attack_check: true,

            short_sleeve_limb_bits: DEFAULT_SHORT_SLEEVE_LIMB_BITS,
            short_sleeve_max_nonzero_bytes_per_limb: 2,
            short_sleeve_minimum_sparse_ratio: 0.75,
        }
    }
}

/// Shared-factor finding against caller-provided corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFactorFinding {
    /// Index into policy.shared_moduli.
    pub index: usize,

    /// Non-trivial GCD in big-endian bytes.
    pub gcd_be: Vec<u8>,
}

/// Scan a corpus for shared non-trivial factors.
#[must_use]
pub fn shared_factor_scan(n_be: &[u8], corpus: &[&[u8]]) -> Vec<SharedFactorFinding> {
    let n = math::Big::from_be(n_be);
    let mut out = Vec::new();

    for (index, c) in corpus.iter().enumerate() {
        let m = math::Big::from_be(c);

        if m.is_zero() || m == n {
            continue;
        }

        let g = math::gcd(n.clone(), m.clone());

        if !g.is_one() && g != n && g != m {
            out.push(SharedFactorFinding {
                index,
                gcd_be: g.to_be(),
            });
        }
    }

    out
}
