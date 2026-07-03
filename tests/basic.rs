use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePublicKey;
use rsa_pub_key_health::{analyze_pem, AuditPolicy, HealthStatus};

#[test]
fn generated_key_analyzes() {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 3072).unwrap();
    let public = RsaPublicKey::from(&private);
    let pem = public.to_public_key_pem(Default::default()).unwrap();
    let report = analyze_pem(&pem, &AuditPolicy::default()).unwrap();
    assert!(matches!(report.status, HealthStatus::Pass | HealthStatus::Review));
    assert_eq!(report.modulus_bits, 3072);
}
