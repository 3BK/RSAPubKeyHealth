use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa_pub_key_health::{AuditPolicy, HealthStatus, analyze_pem};

use std::io::Write;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn generated_key_analyzes() {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let start = Instant::now();

    let _heartbeat = thread::spawn(move || {
        eprintln!("[INFO] Heartbeat thread started.");
        std::io::stderr().flush().unwrap();
        while running_clone.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(60));

            if running_clone.load(Ordering::Relaxed) {
                eprintln!(
                    "[progress] elapsed: {} minutes ({} seconds)",
                    start.elapsed().as_secs() / 60,
                    start.elapsed().as_secs()
                );
                std::io::stderr().flush().unwrap();
            }
        }
    });

    let mut rng = rand::thread_rng();

    let gen_start = Instant::now();

    eprintln!("[INFO] Starting RSA-7680 key generation...");
    std::io::stderr().flush().unwrap();

    let private = RsaPrivateKey::new(&mut rng, 7680).unwrap();

    eprintln!(
        "[INFO] Key generation completed in {:.2} seconds",
        gen_start.elapsed().as_secs_f64()
    );
    std::io::stderr().flush().unwrap();

    eprintln!("[INFO] Deriving public key...");
    std::io::stderr().flush().unwrap();
    let public = RsaPublicKey::from(&private);

    use rsa::pkcs1::EncodeRsaPublicKey;

    eprintln!("[INFO] Encoding public key to PEM...");
    std::io::stderr().flush().unwrap();
    let pem = public.to_pkcs1_pem(Default::default()).unwrap();

    eprintln!("{}", pem);

    eprintln!("{}", pem.lines().next().unwrap());

    eprintln!("[INFO] Starting PEM analysis...");
    std::io::stderr().flush().unwrap();
    let report = analyze_pem(&pem, &AuditPolicy::rsa7680_policy()).unwrap();
    eprintln!("[INFO] PEM Analysis completed");
    std::io::stderr().flush().unwrap();

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
    assert_eq!(report.modulus_bits, 7680);
}
