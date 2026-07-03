use crate::KeyHealthError;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;

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

/// Parse a PEM-encoded public key. Supports SPKI and PKCS#1 RSA PUBLIC KEY PEM blocks.
pub fn parse_rsa_public_key_pem(input: &str) -> Result<PublicKeyMaterial, KeyHealthError> {
    let key = RsaPublicKey::from_public_key_pem(input)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(input))
        .map_err(|e| KeyHealthError::Parse(e.to_string()))?;
    material_from_key(&key)
}

/// Parse a DER-encoded public key. Supports SPKI and PKCS#1 RSA PUBLIC KEY DER.
pub fn parse_rsa_public_key_der(input: &[u8]) -> Result<PublicKeyMaterial, KeyHealthError> {
    let key = RsaPublicKey::from_public_key_der(input)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(input))
        .map_err(|e| KeyHealthError::Parse(e.to_string()))?;
    material_from_key(&key)
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
    Ok(PublicKeyMaterial { modulus, exponent, modulus_bit_len, subject_public_key_der })
}
