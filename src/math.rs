use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::collections::HashMap;

pub(crate) type Big = BigUint;

pub(crate) trait BigExt {
    fn from_be(bytes: &[u8]) -> Self;
    fn to_be(&self) -> Vec<u8>;
}

impl BigExt for BigUint {
    fn from_be(bytes: &[u8]) -> Self {
        BigUint::from_bytes_be(bytes)
    }
    fn to_be(&self) -> Vec<u8> {
        self.to_bytes_be()
    }
}

pub(crate) fn gcd(a: Big, b: Big) -> Big {
    a.gcd(&b)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn count_ones(bytes: &[u8], bit_len: usize) -> usize {
    let excess = bytes.len() * 8usize - bit_len;
    let mut total = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if i == 0 && excess > 0 {
            total += (b & (0xffu8 >> excess)).count_ones() as usize;
        } else {
            total += b.count_ones() as usize;
        }
    }
    total
}

pub(crate) fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

pub(crate) fn monobit_z_score(bit_len: usize, ones: usize) -> f64 {
    if bit_len == 0 {
        return 0.0;
    }
    let expected = bit_len as f64 / 2.0;
    let sd = (bit_len as f64 * 0.25).sqrt();
    (ones as f64 - expected) / sd
}

pub(crate) fn two_sided_normal_p_value(z: f64) -> f64 {
    erfc(z / std::f64::consts::SQRT_2)
}

fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

pub(crate) fn longest_bit_run(bytes: &[u8], bit_len: usize, bit: bool) -> usize {
    let mut best = 0;
    let mut cur = 0;
    let excess = bytes.len() * 8 - bit_len;
    for (i, b) in bytes.iter().enumerate() {
        let start = if i == 0 { excess } else { 0 };
        for j in start..8 {
            let is_one = (b & (0x80 >> j)) != 0;
            if is_one == bit {
                cur += 1;
                best = best.max(cur);
            } else {
                cur = 0;
            }
        }
    }
    best
}

pub(crate) struct RepeatedBlock {
    pub block_size: usize,
    pub count: usize,
    pub block: Vec<u8>,
}
pub(crate) fn repeated_block_report(
    bytes: &[u8],
    block_size: usize,
    min_count: usize,
) -> Option<RepeatedBlock> {
    if block_size == 0 || bytes.len() < block_size {
        return None;
    }
    let mut map: HashMap<&[u8], usize> = HashMap::new();
    for chunk in bytes.chunks_exact(block_size) {
        *map.entry(chunk).or_default() += 1;
    }
    map.into_iter()
        .filter(|(_, c)| *c >= min_count)
        .max_by_key(|(_, c)| *c)
        .map(|(b, c)| RepeatedBlock {
            block_size,
            count: c,
            block: b.to_vec(),
        })
}

pub(crate) struct SparseWindow {
    pub offset: usize,
    pub window_bytes: usize,
    pub nonzero_bytes: usize,
}
pub(crate) fn sparse_window_report(
    bytes: &[u8],
    window: usize,
    max_nonzero: usize,
) -> Option<SparseWindow> {
    if window == 0 || bytes.len() < window {
        return None;
    }
    for (offset, w) in bytes.windows(window).enumerate() {
        let nz = w.iter().filter(|b| **b != 0).count();
        if nz <= max_nonzero {
            return Some(SparseWindow {
                offset,
                window_bytes: window,
                nonzero_bytes: nz,
            });
        }
    }
    None
}

pub(crate) fn small_factor_screen(bytes: &[u8], limit: u64) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    for p in small_primes(limit) {
        let mut rem = 0u64;
        for b in bytes {
            rem = ((rem << 8) + *b as u64) % p;
        }
        if rem == 0 {
            return Some(p);
        }
    }
    None
}

fn small_primes(limit: u64) -> Vec<u64> {
    let mut out = Vec::new();
    'p: for n in 2..=limit {
        let r = (n as f64).sqrt() as u64;
        for d in 2..=r {
            if n % d == 0 {
                continue 'p;
            }
        }
        out.push(n);
    }
    out
}

pub(crate) fn fermat_near_square_screen(bytes: &[u8], iterations: usize) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let n = BigUint::from_bytes_be(bytes);
    if n.is_zero() || n.is_even() {
        return false;
    }
    let mut a = integer_sqrt_ceil(&n);
    for _ in 0..iterations {
        let b2 = (&a * &a) - &n;
        if is_square(&b2) {
            return true;
        }
        a += BigUint::one();
    }
    false
}

fn integer_sqrt_floor(n: &BigUint) -> BigUint {
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

fn integer_sqrt_ceil(n: &BigUint) -> BigUint {
    let f = integer_sqrt_floor(n);
    if &f * &f == *n { f } else { f + BigUint::one() }
}

fn is_square(n: &BigUint) -> bool {
    let r = integer_sqrt_floor(n);
    &r * &r == *n
}
