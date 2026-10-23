//! The eight compromised eMudhra intermediate CA certificates.
//!
//! Source of truth (CVE-2026-111943 / RHSB-2026-012, disclosed 2026-10-21):
//!   * Cisco Talos threat advisory "Compromised eMudhra intermediate certificates"
//!   * Red Hat RHSB-2026-012
//!   * Mozilla bug 2083449 / CCADB records A012294..A012308
//!
//! Each `der` blob below is the *actual* certificate, fetched from the
//! certificate-transparency log (crt.sh) and verified byte-for-byte against the
//! published SHA-256 fingerprints. Embedding the real bytes lets us match
//! exactly instead of guessing from names.
//!
//! `cert_sha256` is the SHA-256 over the whole DER certificate (as published).
//! `spki_sha256` is the SHA-256 over the DER SubjectPublicKeyInfo; this is the
//! value Go 1.27.3 / 1.26.10 filter on (crypto/x509), and is what actually
//! identifies the compromised *key* independent of any re-encoding.

/// One compromised intermediate certificate.
pub struct Target {
    /// Human-readable label, matches the published CN.
    pub name: &'static str,
    /// Organization that appears in the subject (eMudhra BV / eMudhra Inc).
    pub org: &'static str,
    /// Serial number, uppercase hex, no separators, as printed by OpenSSL.
    pub serial: &'static str,
    /// SHA-256 of the full DER certificate, lowercase hex.
    pub cert_sha256: &'static str,
    /// SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex.
    pub spki_sha256: &'static str,
    /// The certificate itself.
    pub der: &'static [u8],
}

macro_rules! target {
    ($name:literal, $org:literal, $serial:literal, $cert:literal, $spki:literal, $file:literal) => {
        Target {
            name: $name,
            org: $org,
            serial: $serial,
            cert_sha256: $cert,
            spki_sha256: $spki,
            der: include_bytes!(concat!("../certs/", $file)),
        }
    };
}

pub static TARGETS: &[Target] = &[
    target!(
        "EM EV TLS CA - G3B",
        "eMudhra BV",
        "C7C41EFE92D825F05EAE841A4A82C1",
        "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838",
        "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
        "ev_tls_g3b.der"
    ),
    target!(
        "EM OV TLS CA - G3B",
        "eMudhra BV",
        "6CADA367FB1C100088120EA202D568",
        "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b",
        "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
        "ov_tls_g3b.der"
    ),
    target!(
        "EM DV TLS CA - G3B",
        "eMudhra BV",
        "A4AEE678F23362B4C0E460B772F214",
        "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493",
        "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
        "dv_tls_g3b.der"
    ),
    target!(
        "EM EV TLS CA - G3C",
        "eMudhra Inc",
        "8009928A64107601AF05FA2F19F109",
        "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3",
        "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
        "ev_tls_g3c.der"
    ),
    target!(
        "EM OV TLS CA - G3C",
        "eMudhra Inc",
        "296926C227A3A1526392B19482A504",
        "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f",
        "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
        "ov_tls_g3c.der"
    ),
    target!(
        "EM DV TLS CA - G3C",
        "eMudhra Inc",
        "588B2E3C2BB8CDA13E1A1209254321",
        "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19",
        "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
        "dv_tls_g3c.der"
    ),
    target!(
        "EM OV CS CA - G3B",
        "eMudhra BV",
        "7818933F8F85B4619A2B35FBA83D0A",
        "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4",
        "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
        "ov_cs_g3b.der"
    ),
    target!(
        "EM OV CS CA - G3C",
        "eMudhra Inc",
        "544B7F922C31AE220A4A922916F6E6",
        "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1",
        "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
        "ov_cs_g3c.der"
    ),
];

/// Look up a target index by its human-readable name.
pub fn index_by_name(name: &str) -> Option<usize> {
    TARGETS.iter().position(|t| t.name == name)
}
