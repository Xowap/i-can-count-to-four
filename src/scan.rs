//! Deep inspection of candidate files and the findings we emit.

use std::collections::BTreeSet;

use memchr::memmem;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::matches::{Matchers, TextClass};
use crate::targets::TARGETS;

/// How a file relates to the compromised certificates, strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Finding {
    /// The exact DER certificate bytes are present (raw `.der`, keystore blob,
    /// memory dump, ...).
    ExactDer,
    /// The certificate was decoded from a PEM/base64 container.
    ExactPem,
    /// A parsed certificate whose SubjectPublicKeyInfo hash matches one of the
    /// compromised keys (this is what identifies the key even across
    /// re-encoding / re-signing).
    SpkiMatch,
    /// A whole-certificate SHA-256 fingerprint appears as text.
    CertFingerprintRef,
    /// An SPKI SHA-256 fingerprint appears as text.
    SpkiFingerprintRef,
    /// A certificate serial number appears as text.
    SerialRef,
    /// The compromised certificate's subject CN appears as text.
    SubjectRef,
    /// The signing root's CN appears as text.
    IssuerRef,
    /// A bare "eMudhra" mention.
    VendorRef,
}

impl Finding {
    /// True when the file provably contains the compromised material.
    pub fn is_high_confidence(self) -> bool {
        matches!(
            self,
            Finding::ExactDer | Finding::ExactPem | Finding::SpkiMatch
        )
    }

    /// Reverse of [`label`], for re-reading saved JSON.
    pub fn from_label(s: &str) -> Option<Finding> {
        Some(match s {
            "exact-cert-bytes" => Finding::ExactDer,
            "exact-cert-pem" => Finding::ExactPem,
            "subject-public-key" => Finding::SpkiMatch,
            "cert-sha256-fingerprint" => Finding::CertFingerprintRef,
            "spki-sha256-fingerprint" => Finding::SpkiFingerprintRef,
            "serial-number" => Finding::SerialRef,
            "subject-cn" => Finding::SubjectRef,
            "issuer-cn" => Finding::IssuerRef,
            "vendor-name" => Finding::VendorRef,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Finding::ExactDer => "exact-cert-bytes",
            Finding::ExactPem => "exact-cert-pem",
            Finding::SpkiMatch => "subject-public-key",
            Finding::CertFingerprintRef => "cert-sha256-fingerprint",
            Finding::SpkiFingerprintRef => "spki-sha256-fingerprint",
            Finding::SerialRef => "serial-number",
            Finding::SubjectRef => "subject-cn",
            Finding::IssuerRef => "issuer-cn",
            Finding::VendorRef => "vendor-name",
        }
    }
}

/// Parsed metadata for a certificate we actually decoded.
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub cert_sha256: String,
    pub spki_sha256: String,
    /// Target index when this is exactly one of the compromised certs.
    pub exact_target: Option<usize>,
    /// Target index when only the public key matches.
    pub spki_target: Option<usize>,
}

/// Everything we learned about one candidate file.
#[derive(Debug, Default)]
pub struct Analysis {
    pub findings: BTreeSet<Finding>,
    pub targets: BTreeSet<usize>,
    pub certs: Vec<CertInfo>,
    pub offsets: Vec<u64>,
}

impl Analysis {
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

const MAX_OFFSETS: usize = 16;
pub const MAX_HITS: usize = 4096;

/// Files up to this size are read into memory for the full analysis pass;
/// larger ones are memory-mapped instead. Only reached for candidates.
pub const MAX_HEAP_READ: u64 = 64 * 1024 * 1024;

/// Record an exact-DER hit at a file offset.
pub fn record_der(a: &mut Analysis, target: usize, offset: u64) {
    a.findings.insert(Finding::ExactDer);
    a.targets.insert(target);
    if a.offsets.len() < MAX_OFFSETS && !a.offsets.contains(&offset) {
        a.offsets.push(offset);
    }
}

/// Record a textual hit. Returns `true` if it was a PEM header.
pub fn record_text(a: &mut Analysis, class: TextClass) -> bool {
    let (finding, target) = match class {
        TextClass::CertFingerprint(t) => (Finding::CertFingerprintRef, t),
        TextClass::SpkiFingerprint(t) => (Finding::SpkiFingerprintRef, t),
        TextClass::Serial(t) => (Finding::SerialRef, t),
        TextClass::Subject(t) => (Finding::SubjectRef, t),
        TextClass::Issuer => (Finding::IssuerRef, None),
        TextClass::Vendor => (Finding::VendorRef, None),
        TextClass::PemHeader => return true,
    };
    a.findings.insert(finding);
    if let Some(t) = target {
        a.targets.insert(t);
    }
    false
}

/// Drop weak textual sub-matches when the certificate itself was found: the DER
/// bytes inherently contain the subject CN and vendor name, so those hits are
/// just noise.
pub fn finalize(a: &mut Analysis) {
    if a.findings.iter().any(|f| f.is_high_confidence()) {
        a.findings.remove(&Finding::SubjectRef);
        a.findings.remove(&Finding::IssuerRef);
        a.findings.remove(&Finding::VendorRef);
    }
}

pub fn analyze(m: &Matchers, bytes: &[u8]) -> Analysis {
    let mut a = Analysis::default();

    // 1. Exact DER bytes, wherever they appear. The DER automaton contains only
    //    full-cert needles, so every hit is an exact certificate.
    for (ti, off) in m.der_hits(bytes) {
        record_der(&mut a, ti, off as u64);
    }

    // 2. Textual traces.
    let mut saw_pem_header = false;
    for (class, _off) in m.text_hits(bytes, MAX_HITS) {
        if record_text(&mut a, class) {
            saw_pem_header = true;
        }
    }

    // 3. Decode PEM / base64 certificate containers.
    if saw_pem_header {
        for der in pem_certificates(bytes) {
            if let Some(info) = identify_der(&der) {
                if let Some(t) = info.exact_target {
                    a.targets.insert(t);
                    a.findings.insert(Finding::ExactPem);
                    push_cert(&mut a, info);
                } else if let Some(t) = info.spki_target {
                    a.targets.insert(t);
                    a.findings.insert(Finding::SpkiMatch);
                    push_cert(&mut a, info);
                }
            }
        }
    }

    // 4. The file might itself be a bare DER certificate (possibly a re-signed
    //    variant whose SPKI still matches). Exact matches were already caught
    //    in step 1, so only the SPKI-only case adds anything new here.
    if bytes.first() == Some(&0x30) {
        if let Some(info) = identify_der(bytes) {
            let exact = info.exact_target.is_some();
            let spki = info.spki_target.is_some();
            if exact || spki {
                if let Some(t) = info.exact_target.or(info.spki_target) {
                    a.targets.insert(t);
                }
                if !exact {
                    a.findings.insert(Finding::SpkiMatch);
                }
                if exact {
                    a.findings.insert(Finding::ExactDer);
                }
                push_cert(&mut a, info);
            }
        }
    }

    // 5. Prune noisy sub-matches and return.
    finalize(&mut a);
    a
}

fn push_cert(a: &mut Analysis, info: CertInfo) {
    if !a.certs.iter().any(|c| c.cert_sha256 == info.cert_sha256) {
        a.certs.push(info);
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Parse a DER certificate and figure out whether it is one of ours.
fn identify_der(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let cert_sha256 = sha256_hex(der);
    let spki_sha256 = sha256_hex(cert.tbs_certificate.subject_pki.raw);

    let exact_target = TARGETS.iter().position(|t| t.cert_sha256 == cert_sha256);
    let spki_target = if exact_target.is_none() {
        TARGETS.iter().position(|t| t.spki_sha256 == spki_sha256)
    } else {
        None
    };

    Some(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: hex::encode_upper(cert.raw_serial()),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        cert_sha256,
        spki_sha256,
        exact_target,
        spki_target,
    })
}

/// Extract every DER certificate from PEM/base64 blocks in a byte buffer.
fn pem_certificates(bytes: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let mut out = Vec::new();
    let mut search = 0usize;

    while let Some(rel) = memmem::find(&bytes[search..], BEGIN) {
        let begin = search + rel;
        let label_start = begin + BEGIN.len();
        let dashes_rel = match memmem::find(&bytes[label_start..], b"-----") {
            Some(d) => d,
            None => break,
        };
        let label = &bytes[label_start..label_start + dashes_rel];
        let body_start = label_start + dashes_rel + 5;

        if label != b"CERTIFICATE" && label != b"TRUSTED CERTIFICATE" {
            search = body_start;
            continue;
        }

        let mut end_marker = Vec::with_capacity(13 + label.len());
        end_marker.extend_from_slice(b"-----END ");
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(b"-----");

        let end_rel = match memmem::find(&bytes[body_start..], &end_marker) {
            Some(e) => e,
            None => break,
        };
        let body = &bytes[body_start..body_start + end_rel];
        if let Some(der) = base64_ws_decode(body) {
            out.push(der);
        }
        search = body_start + end_rel + end_marker.len();
    }

    out
}

fn base64_ws_decode(input: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn matchers() -> Matchers {
        Matchers::new()
    }

    #[test]
    fn embedded_spki_hashes_match_targets() {
        for t in TARGETS {
            let info = identify_der(t.der).expect("parse");
            assert_eq!(info.cert_sha256, t.cert_sha256, "cert hash for {}", t.name);
            assert_eq!(info.spki_sha256, t.spki_sha256, "spki hash for {}", t.name);
            assert_eq!(
                info.exact_target,
                Some(TARGETS.iter().position(|x| x.name == t.name).unwrap())
            );
        }
    }

    #[test]
    fn detects_raw_der_file() {
        let m = matchers();
        let bytes = TARGETS[0].der;
        assert!(m.is_candidate(bytes));
        let a = analyze(&m, bytes);
        assert!(a.findings.contains(&Finding::ExactDer));
        assert!(!a.findings.contains(&Finding::ExactPem));
        assert!(a.targets.contains(&0));
        assert_eq!(a.certs.len(), 1);
    }

    #[test]
    fn detects_pem_bundle_with_decoys() {
        let m = matchers();
        let pem = |der: &[u8]| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(der);
            let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
            for chunk in b64.as_bytes().chunks(64) {
                s.push_str(std::str::from_utf8(chunk).unwrap());
                s.push('\n');
            }
            s.push_str("-----END CERTIFICATE-----\n");
            s
        };
        // A decoy self-signed cert cannot be fabricated here, so just exercise
        // the bundle path with a compromised cert surrounded by noise.
        let mut bundle = String::from("# unrelated bundle header\n");
        bundle.push_str(&pem(TARGETS[3].der));
        bundle.push_str("\n# trailing noise\n");
        let bytes = bundle.as_bytes();
        assert!(m.is_candidate(bytes));
        let a = analyze(&m, bytes);
        assert!(a.findings.contains(&Finding::ExactPem));
        assert!(a.targets.contains(&3));
    }

    #[test]
    fn detects_text_fingerprint() {
        let m = matchers();
        let text = format!("revoked: {}\n", TARGETS[1].cert_sha256.to_uppercase());
        let bytes = text.as_bytes();
        assert!(m.is_candidate(bytes));
        let a = analyze(&m, bytes);
        assert!(a.findings.contains(&Finding::CertFingerprintRef));
        assert!(a.targets.contains(&1));
        assert!(!a.findings.iter().any(|f| f.is_high_confidence()));
    }

    #[test]
    fn detects_embedded_der_after_prefix() {
        let m = matchers();
        let der = TARGETS[6].der;
        let mut v = vec![0u8; 512];
        v.extend_from_slice(der);
        v.extend_from_slice(&[0xABu8; 64]);
        assert!(m.is_candidate(&v));
        let a = analyze(&m, &v);
        assert!(a.findings.contains(&Finding::ExactDer), "{:?}", a.findings);
        assert!(a.targets.contains(&6));
        assert_eq!(a.offsets, vec![512]);
    }

    #[test]
    fn detects_fingerprint_inside_embedded_cert_file() {
        // A text file that both embeds a certificate and references a serial.
        let m = matchers();
        let mut v = TARGETS[2].der.to_vec();
        v.extend_from_slice(b"\nrevoked serial A4AEE678F23362B4C0E460B772F214\n");
        let a = analyze(&m, &v);
        assert!(a.findings.contains(&Finding::ExactDer));
        assert!(a.findings.contains(&Finding::SerialRef));
    }

    #[test]
    fn clean_file_is_not_a_candidate() {
        let m = matchers();
        let data = vec![0u8; 1024];
        assert!(!m.is_candidate(&data));
        let a = analyze(&m, &data);
        assert!(a.is_empty());
    }
}
