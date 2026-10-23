//! Fast prefiltering.
//!
//! Two Aho-Corasick automata:
//!
//! * `bin` -- the eight raw DER certificates, matched case-sensitively. Because
//!   it contains *only* full-cert needles, its `find_iter` reports exact
//!   certificate hits without shorter patterns shadowing them.
//! * `text` -- ASCII case-insensitive textual traces: fingerprint hex, serial
//!   numbers, subject CNs, the issuer roots, the vendor name and the PEM
//!   header.
//!
//! Keeping the raw DER needles out of the text automaton matters: if they were
//! merged, `find_iter` could report a short string *inside* a certificate and
//! then skip the enclosing certificate as an overlapping match.
//!
//! The prefilter only answers "is this file worth looking at?"; both `is_match`
//! calls short-circuit on the first hit, so most files cost one linear scan.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::targets::TARGETS;

/// What a textual match means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextClass {
    /// A whole-certificate SHA-256 fingerprint.
    CertFingerprint(Option<usize>),
    /// An SPKI SHA-256 fingerprint.
    SpkiFingerprint(Option<usize>),
    /// A certificate serial number.
    Serial(Option<usize>),
    /// The compromised certificate's own subject CN.
    Subject(Option<usize>),
    /// The signing root's CN (`emSign Root ... CA - G3`).
    Issuer,
    /// A bare mention of "eMudhra".
    Vendor,
    /// A PEM certificate header (triggers PEM decoding).
    PemHeader,
}

pub struct Matchers {
    bin: AhoCorasick,
    text: AhoCorasick,
    classes: Vec<TextClass>,
    max_needle: usize,
}

/// Uppercase, colon-separated form of a lowercase hex string.
fn uppercase_colon(hex_lower: &str) -> String {
    let mut out = String::with_capacity(hex_lower.len() * 3);
    for (i, chunk) in hex_lower.as_bytes().chunks(2).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&String::from_utf8_lossy(chunk).to_uppercase());
    }
    out
}

impl Matchers {
    pub fn new() -> Self {
        // ---- binary: the raw DER certificates ----------------------------
        let bin = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(TARGETS.iter().map(|t| t.der))
            .expect("failed to build DER automaton");

        // ---- text: fingerprints, serials, names, PEM header --------------
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut classes: Vec<TextClass> = Vec::new();
        let mut push = |p: &[u8], class: TextClass| {
            patterns.push(p.to_vec());
            classes.push(class);
        };

        for (i, t) in TARGETS.iter().enumerate() {
            // Fingerprints (compact hex and colon-separated).
            push(
                t.cert_sha256.as_bytes(),
                TextClass::CertFingerprint(Some(i)),
            );
            push(
                uppercase_colon(t.cert_sha256).as_bytes(),
                TextClass::CertFingerprint(Some(i)),
            );
            push(
                t.spki_sha256.as_bytes(),
                TextClass::SpkiFingerprint(Some(i)),
            );
            push(
                uppercase_colon(t.spki_sha256).as_bytes(),
                TextClass::SpkiFingerprint(Some(i)),
            );

            // Serial numbers (compact + colon-separated, with and without the
            // ASN.1 DER 0x00 positive-integer prefix).
            let serial = t.serial.to_string();
            push(serial.as_bytes(), TextClass::Serial(Some(i)));
            push(
                uppercase_colon(&serial.to_lowercase()).as_bytes(),
                TextClass::Serial(Some(i)),
            );
            push(format!("00{serial}").as_bytes(), TextClass::Serial(Some(i)));
            push(
                uppercase_colon(&format!("00{}", serial.to_lowercase())).as_bytes(),
                TextClass::Serial(Some(i)),
            );

            // The subject CN of the compromised certificate itself.
            push(t.name.as_bytes(), TextClass::Subject(Some(i)));
        }

        push(b"emSign Root TLS CA - G3", TextClass::Issuer);
        push(b"emSign Root CS CA - G3", TextClass::Issuer);
        push(b"eMudhra", TextClass::Vendor);
        push(b"-----BEGIN CERTIFICATE-----", TextClass::PemHeader);
        push(b"-----BEGIN TRUSTED CERTIFICATE-----", TextClass::PemHeader);

        let max_needle = patterns
            .iter()
            .map(|p| p.len())
            .chain(TARGETS.iter().map(|t| t.der.len()))
            .max()
            .unwrap_or(0);

        let text = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(patterns.iter().map(|p| p.as_slice()))
            .expect("failed to build text automaton");

        Matchers {
            bin,
            text,
            classes,
            max_needle,
        }
    }

    /// Length of the longest needle; used to size chunk-boundary overlap.
    pub fn max_needle_len(&self) -> usize {
        self.max_needle
    }

    /// Cheap "is this file worth a closer look?" test. (Used by tests and kept
    /// as the natural single-shot predicate; the scanner streams instead.)
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub fn is_candidate(&self, bytes: &[u8]) -> bool {
        self.bin.is_match(bytes) || self.text.is_match(bytes)
    }

    /// Exact raw-DER hits as `(target index, byte offset)`.
    pub fn der_hits<'a>(&'a self, bytes: &'a [u8]) -> impl Iterator<Item = (usize, usize)> + 'a {
        self.bin
            .find_iter(bytes)
            .map(|m| (m.pattern().as_usize(), m.start()))
    }

    /// Textual hits as `(class, byte offset)`, capped at `limit`.
    pub fn text_hits<'a>(
        &'a self,
        bytes: &'a [u8],
        limit: usize,
    ) -> impl Iterator<Item = (TextClass, usize)> + 'a {
        self.text
            .find_iter(bytes)
            .take(limit)
            .map(|m| (self.classes[m.pattern().as_usize()], m.start()))
    }
}

impl Default for Matchers {
    fn default() -> Self {
        Self::new()
    }
}
