/// Supported compliance framework labels.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Framework {
    /// PCI DSS 4.x family.
    PciDss40,
    /// NIST SP 800-53 Revision 5.
    NistSp80053Rev5,
    /// CIS Controls version 8 family.
    CisControlsV8,
    /// DISA STIG / SRG evidence.
    DisaStig,
}

/// Compliance control mapping note.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ComplianceControl {
    /// Framework.
    pub framework: Framework,
    /// Control or requirement family.
    pub control: String,
    /// Evidence statement.
    pub evidence: String,
}

impl ComplianceControl {
    /// Construct a compliance mapping.
    pub fn new(framework: Framework, control: &str, evidence: &str) -> Self {
        Self {
            framework,
            control: control.to_string(),
            evidence: evidence.to_string(),
        }
    }
}

/// Overall health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HealthStatus {
    /// No findings were produced.
    Pass,
    /// One or more low/medium findings were produced.
    Review,
    /// One or more high findings were produced.
    Fail,
    /// One or more critical findings were produced.
    Critical,
}

impl HealthStatus {
    /// Derive overall status from findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        if findings
            .iter()
            .any(|f| f.severity == FindingSeverity::Critical)
        {
            return Self::Critical;
        }
        if findings.iter().any(|f| f.severity == FindingSeverity::High) {
            return Self::Fail;
        }
        if findings.is_empty() {
            Self::Pass
        } else {
            Self::Review
        }
    }
}

/// Finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FindingSeverity {
    /// Informational.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// Test identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TestId {
    /// Modulus length.
    ModulusSize,

    /// Public exponent.
    PublicExponent,

    /// Ones/zeros balance.
    BitBalance,

    /// Shannon entropy.
    ShannonEntropy,

    /// Monobit frequency.
    Monobit,

    /// Long zero run.
    LongZeroRun,

    /// Long one run.
    LongOneRun,

    /// Repeated blocks.
    RepeatedBlocks,

    /// Sparse byte windows.
    SparseWindow,

    /// Trial division small factor.
    SmallFactor,

    /// Fermat close-prime screen.
    FermatNearSquare,

    /// Shared prime / shared factor with corpus.
    SharedFactor,

    /// RSA public key appears vulnerable to Wiener's small-private-exponent attack.
    WienerSmallPrivateExponent,

    /// RSA modulus has a sparse limb pattern consistent with short-sleeve RSA keys.
    ShortSleeveRsaPattern,

    /// RSA modulus has confirmed polynomial / structured factorization behavior.
    PolynomialRsaStructure,
    // /// RSA public key matched a known-bad key blocklist.
    //KnownBadKeyBlocklist,

    // /// RSA public key matched a Fortinet / Fortigate leak blocklist.
    //FortinetFortigateLeak,

    // /// RSA public key matched a keypair / GitKraken CVE-2021-41117 blocklist.
    //KeypairGitkrakenCve202141117,
}

/// Evidence key/value attached to a finding.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FindingEvidence {
    /// Evidence name.
    pub name: String,
    /// Evidence value.
    pub value: String,
}

impl FindingEvidence {
    /// Build evidence.
    pub fn new(name: &str, value: String) -> Self {
        Self {
            name: name.to_string(),
            value,
        }
    }
}

/// A single audit finding.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Finding {
    /// Test that emitted the finding.
    pub test_id: TestId,
    /// Severity.
    pub severity: FindingSeverity,
    /// Human-readable finding text.
    pub message: String,
    /// Machine-readable evidence.
    pub evidence: FindingEvidence,
}

impl Finding {
    /// Build a finding.
    pub fn new(
        test_id: TestId,
        severity: FindingSeverity,
        message: String,
        evidence: FindingEvidence,
    ) -> Self {
        Self {
            test_id,
            severity,
            message,
            evidence,
        }
    }
}

/// Health report suitable for JSON serialization and audit attachment.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HealthReport {
    /// Overall status.
    pub status: HealthStatus,
    /// RSA modulus size in bits.
    pub modulus_bits: usize,
    /// Public exponent as hex.
    pub exponent_hex: String,
    /// SHA-256 fingerprint of DER SubjectPublicKeyInfo.
    pub spki_sha256_hex: String,
    /// Count of one bits in modulus.
    pub ones: usize,
    /// Count of zero bits in modulus.
    pub zeros: usize,
    /// Ones / total modulus bits.
    pub ones_ratio: f64,
    /// Byte-level Shannon entropy.
    pub shannon_entropy_bits_per_byte: f64,
    /// Monobit z-score.
    pub monobit_z_score: f64,
    /// Approximate two-sided normal p-value for monobit z-score.
    pub monobit_p_value: f64,
    /// Longest contiguous zero-bit run.
    pub longest_zero_run_bits: usize,
    /// Longest contiguous one-bit run.
    pub longest_one_run_bits: usize,
    /// Findings.
    pub findings: Vec<Finding>,
    /// Compliance support mapping.
    pub compliance: Vec<ComplianceControl>,
}
