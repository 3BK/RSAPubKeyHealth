use rsa::pkcs8::EncodePublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa_pub_key_health::{AuditPolicy, HealthStatus, analyze_pem};

#[test]
fn generated_key_analyzes() {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 3072).unwrap();
    let public = RsaPublicKey::from(&private);
    let pem = public.to_public_key_pem(Default::default()).unwrap();
    let report = analyze_pem(&pem, &AuditPolicy::default()).unwrap();

    dbg!(report.status);
    dbg!(&report.findings);

    println!("{:#?}", report);
    for finding in &report.findings {
        println!("{:?}: {}", finding.severity, finding.message);
    }

    assert!(matches!(
        report.status,
        HealthStatus::Pass | HealthStatus::Review
    ));
    assert_eq!(report.modulus_bits, 3072);
}
