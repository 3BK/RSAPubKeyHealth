/// Result of short-sleeve structure scanning.
#[derive(Debug, Clone)]
pub struct ShortSleeveFinding {
    /// Limb width in bits.
    pub limb_bits: usize,

    /// Number of limbs inspected.
    pub limbs: usize,

    /// Number of suspicious sparse limbs.
    pub sparse_limbs: usize,

    /// Sparse limb ratio.
    pub sparse_ratio: f64,
}

/// Scan for regularly sparse limbs in an RSA modulus.
///
/// This is an anomaly detector. It does not prove factorability by itself.
#[must_use]
pub fn scan_short_sleeve_pattern(
    modulus_be: &[u8],
    limb_bits: usize,
    max_nonzero_bytes_per_limb: usize,
    minimum_sparse_ratio: f64,
) -> Option<ShortSleeveFinding> {
    assert!(limb_bits % 8 == 0);

    let limb_bytes = limb_bits / 8;

    if limb_bytes == 0 || modulus_be.len() < limb_bytes {
        return None;
    }

    let mut limbs = 0usize;
    let mut sparse_limbs = 0usize;

    for limb in modulus_be.rchunks(limb_bytes) {
        limbs += 1;

        let nonzero = limb.iter().filter(|byte| **byte != 0).count();

        if nonzero <= max_nonzero_bytes_per_limb {
            sparse_limbs += 1;
        }
    }

    if limbs == 0 {
        return None;
    }

    let sparse_ratio = sparse_limbs as f64 / limbs as f64;

    if sparse_ratio >= minimum_sparse_ratio {
        Some(ShortSleeveFinding {
            limb_bits,
            limbs,
            sparse_limbs,
            sparse_ratio,
        })
    } else {
        None
    }
}
