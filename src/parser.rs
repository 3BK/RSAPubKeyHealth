use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use rsa::pkcs1::DecodeRsaPublicKey;

use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

use crate::KeyHealthError;

/// Maximum RSA modulus size accepted by this analyzer.
///
/// This is intentionally larger than `rsa::RsaPublicKey::MAX_SIZE` because
/// this crate is an audit/inspection library and may need to analyze
/// high-assurance RSA public keys such as RSA-7680.
const MAX_RSA_PUBLIC_MODULUS_BITS: usize = 16_384;

/// Extracted RSA public key material in big-endian form.
#[derive(Debug, Clone)]
pub struct PublicKeyMaterial {
    /// RSA modulus, big-endian, minimally encoded.
    pub modulus: Vec<u8>,
    /// RSA public exponent, big-endian, minimally encoded.
    pub exponent: Vec<u8>,
    /// Modulus bit length.
    pub modulus_bit_len: usize,
    /// DER SubjectPublicKeyInfo representation used for fingerprinting.
    pub subject_public_key_der: Vec<u8>,
}

/// Parse a PEM-encoded RSA public key.
///
/// Supports:
/// - SubjectPublicKeyInfo PEM: `-----BEGIN PUBLIC KEY-----`
/// - PKCS#1 RSA public key PEM: `-----BEGIN RSA PUBLIC KEY-----`
///
/// For large RSA public keys, such as RSA-7680, this function falls back to a
/// custom PKCS#1 parser because `rsa::RsaPublicKey::from_pkcs1_pem` may reject
/// keys larger than the crate's default public-key size limit.
pub fn parse_rsa_public_key_pem(input: &str) -> Result<PublicKeyMaterial, KeyHealthError> {
    eprintln!(
        "[DEBUG] First PEM line: {}",
        input.lines().next().unwrap_or("<empty>")
    );

    eprintln!("[DEBUG] Trying SPKI PEM parser");

    match RsaPublicKey::from_public_key_pem(input) {
        Ok(key) => {
            eprintln!("[DEBUG] SPKI PEM parser succeeded");
            return material_from_key(&key);
        }

        Err(spki_err) => {
            eprintln!("[DEBUG] SPKI PEM parser failed: {spki_err}");
        }
    }

    eprintln!("[DEBUG] Trying standard PKCS#1 PEM parser");

    match RsaPublicKey::from_pkcs1_pem(input) {
        Ok(key) => {
            eprintln!(
                "[DEBUG] Standard PKCS#1 PEM parser succeeded: {} bits",
                key.n().bits()
            );

            return material_from_key(&key);
        }

        Err(pkcs1_err) => {
            eprintln!("[DEBUG] Standard PKCS#1 PEM parser failed: {pkcs1_err}");
        }
    }

    eprintln!("[DEBUG] Trying custom large-key PKCS#1 PEM parser");

    match pkcs1_pem_to_der(input) {
        Ok(der) => parse_rsa_public_key_pkcs1_der_large(&der),

        Err(custom_err) => Err(KeyHealthError::Parse(format!(
            "failed to parse RSA public key as SPKI/PUBLIC KEY or PKCS#1/RSA PUBLIC KEY; \
             custom PKCS#1 PEM error: {custom_err}"
        ))),
    }
}

/// Parse a DER-encoded RSA public key.
///
/// Supports:
/// - SubjectPublicKeyInfo DER
/// - PKCS#1 RSA public key DER
///
/// For large RSA public keys, such as RSA-7680, this function falls back to a
/// custom PKCS#1 DER parser using `RsaPublicKey::new_with_max_size`.
pub fn parse_rsa_public_key_der(input: &[u8]) -> Result<PublicKeyMaterial, KeyHealthError> {
    eprintln!("[DEBUG] Trying SPKI DER parser");

    match RsaPublicKey::from_public_key_der(input) {
        Ok(key) => {
            eprintln!("[DEBUG] SPKI DER parser succeeded");
            return material_from_key(&key);
        }

        Err(spki_err) => {
            eprintln!("[DEBUG] SPKI DER parser failed: {spki_err}");
        }
    }

    eprintln!("[DEBUG] Trying standard PKCS#1 DER parser");

    match RsaPublicKey::from_pkcs1_der(input) {
        Ok(key) => {
            eprintln!(
                "[DEBUG] Standard PKCS#1 DER parser succeeded: {} bits",
                key.n().bits()
            );

            return material_from_key(&key);
        }

        Err(pkcs1_err) => {
            eprintln!("[DEBUG] Standard PKCS#1 DER parser failed: {pkcs1_err}");
        }
    }

    eprintln!("[DEBUG] Trying custom large-key PKCS#1 DER parser");

    parse_rsa_public_key_pkcs1_der_large(input)
}

fn pkcs1_pem_to_der(input: &str) -> Result<Vec<u8>, KeyHealthError> {
    const BEGIN: &str = "-----BEGIN RSA PUBLIC KEY-----";
    const END: &str = "-----END RSA PUBLIC KEY-----";

    let mut in_body = false;
    let mut b64 = String::new();

    for line in input.lines().map(str::trim) {
        if line == BEGIN {
            in_body = true;
            continue;
        }

        if line == END {
            break;
        }

        if in_body {
            b64.push_str(line);
        }
    }

    if b64.is_empty() {
        return Err(KeyHealthError::Parse(
            "missing RSA PUBLIC KEY PEM body".to_string(),
        ));
    }

    STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| KeyHealthError::Parse(format!("base64 decode failed: {e}")))
}

fn parse_rsa_public_key_pkcs1_der_large(input: &[u8]) -> Result<PublicKeyMaterial, KeyHealthError> {
    let mut reader = DerReader::new(input);

    let sequence = reader.read_tlv(0x30)?;

    if !reader.is_eof() {
        return Err(KeyHealthError::Parse(
            "trailing bytes after PKCS#1 RSA public key sequence".to_string(),
        ));
    }

    let mut sequence_reader = DerReader::new(sequence);

    let modulus_bytes = sequence_reader.read_integer()?;
    let exponent_bytes = sequence_reader.read_integer()?;

    if !sequence_reader.is_eof() {
        return Err(KeyHealthError::Parse(
            "trailing bytes inside PKCS#1 RSA public key sequence".to_string(),
        ));
    }

    let modulus = BigUint::from_bytes_be(strip_positive_integer_prefix(modulus_bytes));
    let exponent = BigUint::from_bytes_be(strip_positive_integer_prefix(exponent_bytes));

    let key = RsaPublicKey::new_with_max_size(modulus, exponent, MAX_RSA_PUBLIC_MODULUS_BITS)
        .map_err(|e| {
            KeyHealthError::Parse(format!(
                "failed to construct RSA public key with max size \
             {MAX_RSA_PUBLIC_MODULUS_BITS}: {e}"
            ))
        })?;

    material_from_key(&key)
}

fn strip_positive_integer_prefix(bytes: &[u8]) -> &[u8] {
    if bytes.len() > 1 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    }
}

struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn is_eof(&self) -> bool {
        self.offset == self.input.len()
    }

    fn read_integer(&mut self) -> Result<&'a [u8], KeyHealthError> {
        self.read_tlv(0x02)
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], KeyHealthError> {
        let tag = self.read_byte()?;

        if tag != expected_tag {
            return Err(KeyHealthError::Parse(format!(
                "unexpected DER tag: expected 0x{expected_tag:02x}, got 0x{tag:02x}"
            )));
        }

        let len = self.read_len()?;

        if self.offset + len > self.input.len() {
            return Err(KeyHealthError::Parse(
                "DER length exceeds available input".to_string(),
            ));
        }

        let start = self.offset;
        self.offset += len;

        Ok(&self.input[start..start + len])
    }

    fn read_byte(&mut self) -> Result<u8, KeyHealthError> {
        if self.offset >= self.input.len() {
            return Err(KeyHealthError::Parse(
                "unexpected end of DER input".to_string(),
            ));
        }

        let byte = self.input[self.offset];
        self.offset += 1;

        Ok(byte)
    }

    fn read_len(&mut self) -> Result<usize, KeyHealthError> {
        let first = self.read_byte()?;

        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        let count = (first & 0x7f) as usize;

        if count == 0 {
            return Err(KeyHealthError::Parse(
                "indefinite DER lengths are not allowed".to_string(),
            ));
        }

        if count > 4 {
            return Err(KeyHealthError::Parse(
                "DER length field too large".to_string(),
            ));
        }

        let mut len = 0usize;

        for _ in 0..count {
            len = (len << 8) | self.read_byte()? as usize;
        }

        Ok(len)
    }
}

fn material_from_key(key: &RsaPublicKey) -> Result<PublicKeyMaterial, KeyHealthError> {
    let modulus = key.n().to_bytes_be();
    let exponent = key.e().to_bytes_be();
    let modulus_bit_len = key.n().bits();
    let subject_public_key_der = key
        .to_public_key_der()
        .map_err(|e| KeyHealthError::Parse(e.to_string()))?
        .as_bytes()
        .to_vec();
    Ok(PublicKeyMaterial {
        modulus,
        exponent,
        modulus_bit_len,
        subject_public_key_der,
    })
}
