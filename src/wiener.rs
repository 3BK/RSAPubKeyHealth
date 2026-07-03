use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

/// Successful Wiener attack result.
#[derive(Debug, Clone)]
pub struct WienerAttackResult {
    /// Recovered private exponent candidate.
    pub d: BigUint,

    /// Recovered factor p.
    pub p: BigUint,

    /// Recovered factor q.
    pub q: BigUint,
}

/// Result of running the Wiener small-private-exponent check.
#[derive(Debug, Clone)]
pub struct WienerCheck {
    /// Number of continued-fraction convergents evaluated.
    pub convergents_tested: usize,

    /// Recovered vulnerable key material, if the attack succeeded.
    pub result: Option<WienerAttackResult>,
}

/// Run Wiener's small-private-exponent check against public RSA values.
///
/// Normal RSA keys should return `result: None`.
#[must_use]
pub fn wiener_check(n: &BigUint, e: &BigUint) -> WienerCheck {
    let mut convergents_tested = 0usize;

    if n.is_zero() || e.is_zero() {
        return WienerCheck {
            convergents_tested,
            result: None,
        };
    }

    let cf = continued_fraction(e.clone(), n.clone());

    for (k, d) in convergents(&cf) {
        convergents_tested += 1;

        if k.is_zero() || d.is_zero() {
            continue;
        }

        let ed = e * &d;

        if ed <= BigUint::one() {
            continue;
        }

        let ed_minus_one = ed - BigUint::one();

        if &ed_minus_one % &k != BigUint::zero() {
            continue;
        }

        let phi = &ed_minus_one / &k;

        let n_plus_one = n + BigUint::one();

        if phi > n_plus_one {
            continue;
        }

        let s = &n_plus_one - &phi;

        let s_squared = &s * &s;
        let four_n = n << 2usize;

        if s_squared < four_n {
            continue;
        }

        let discriminant = s_squared - four_n;

        let Some(root) = sqrt_if_square(&discriminant) else {
            continue;
        };

        if (&s + &root).is_odd() || (&s - &root).is_odd() {
            continue;
        }

        let p = (&s + &root) >> 1usize;
        let q = (&s - &root) >> 1usize;

        if p.is_zero() || q.is_zero() {
            continue;
        }

        if &p * &q == *n {
            return WienerCheck {
                convergents_tested,
                result: Some(WienerAttackResult { d, p, q }),
            };
        }
    }

    WienerCheck {
        convergents_tested,
        result: None,
    }
}

fn continued_fraction(mut numerator: BigUint, mut denominator: BigUint) -> Vec<BigUint> {
    let mut out = Vec::new();

    while !denominator.is_zero() {
        let q = &numerator / &denominator;
        let r = &numerator % &denominator;

        out.push(q);

        numerator = denominator;
        denominator = r;
    }

    out
}

fn convergents(cf: &[BigUint]) -> Vec<(BigUint, BigUint)> {
    let mut result = Vec::new();

    let mut h_prev2 = BigUint::zero();
    let mut h_prev1 = BigUint::one();

    let mut k_prev2 = BigUint::one();
    let mut k_prev1 = BigUint::zero();

    for a in cf {
        let h = a * &h_prev1 + &h_prev2;
        let k = a * &k_prev1 + &k_prev2;

        result.push((h.clone(), k.clone()));

        h_prev2 = h_prev1;
        h_prev1 = h;

        k_prev2 = k_prev1;
        k_prev1 = k;
    }

    result
}

fn sqrt_if_square(n: &BigUint) -> Option<BigUint> {
    let r = sqrt_floor(n);

    if &r * &r == *n { Some(r) } else { None }
}

fn sqrt_floor(n: &BigUint) -> BigUint {
    if n.is_zero() {
        return BigUint::zero();
    }

    let two = BigUint::from(2u8);
    let mut x = BigUint::one() << n.bits().div_ceil(2);

    loop {
        let y = (&x + n / &x) / &two;

        if y >= x {
            return x;
        }

        x = y;
    }
}
