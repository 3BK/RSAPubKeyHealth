use rsa_pub_key_health::{analyze_pem, AuditPolicy};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: analyze <public-key.pem>")?;
    let pem = fs::read_to_string(path)?;
    let report = analyze_pem(&pem, &AuditPolicy::default())?;
    #[cfg(feature = "serde")]
    println!("{}", serde_json::to_string_pretty(&report)?);
    #[cfg(not(feature = "serde"))]
    println!("{report:#?}");
    Ok(())
}
