//! Content sniffing: decide how much of a file is worth reading.
//!
//! The whole-disk cost is dominated by a handful of enormous files that cannot
//! possibly be certificate stores (ML model weights, disk images, media). We
//! classify each file by its *content* (magic bytes / text-likeness) — never by
//! its name or location — and only read the whole thing when it is the kind of
//! thing a certificate can live in.
//!
//! This is a coverage trade-off, not a correctness guarantee: an opaque file is
//! only read at its head and tail. `--thorough` disables the trade-off.

use memchr::memmem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    /// Something that can literally hold a certificate: ASN.1/DER, PEM,
    /// PKCS#12, JKS, or a certificate database (SQLite / Berkeley DB).
    CertContainer,
    /// Plain-ish text: configs, scripts, logs, allowlists, CRLs.
    Text,
    /// Anything else (media, archives, executables, model weights, ...).
    Opaque,
}

pub fn classify(head: &[u8]) -> ContentKind {
    if head.is_empty() {
        return ContentKind::Opaque;
    }
    if is_der(head) || is_pem(head) || is_jks(head) || is_sqlite(head) || is_berkeley_db(head) {
        return ContentKind::CertContainer;
    }
    if is_text(head) {
        return ContentKind::Text;
    }
    ContentKind::Opaque
}

/// ASN.1 SEQUENCE with a long-form length: how DER certificates, PKCS#12
/// bundles, PKCS#7 blobs and private keys all begin.
fn is_der(head: &[u8]) -> bool {
    head.len() >= 2 && head[0] == 0x30 && head[1] & 0x80 != 0
}

fn is_pem(head: &[u8]) -> bool {
    memmem::find(head, b"-----BEGIN ").is_some()
}

/// Java KeyStore magic.
fn is_jks(head: &[u8]) -> bool {
    head.starts_with(&[0xFE, 0xED, 0xFE, 0xED])
}

/// SQLite database header — where NSS `cert9.db` / `key4.db` live.
fn is_sqlite(head: &[u8]) -> bool {
    head.starts_with(b"SQLite format 3\0")
}

/// Berkeley DB magic (legacy NSS `cert8.db` / `key3.db`), stored at offset 12.
fn is_berkeley_db(head: &[u8]) -> bool {
    head.len() >= 16
        && (&head[12..16] == b"\x00\x06\x15\x61" || &head[12..16] == b"\x00\x05\x31\x62")
}

/// Rough text test: no NUL bytes and overwhelmingly printable.
fn is_text(head: &[u8]) -> bool {
    if head.contains(&0) {
        return false;
    }
    let printable = head
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7E).contains(&b))
        .count();
    printable * 100 / head.len() >= 95
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_containers_and_text() {
        assert_eq!(
            classify(&[0x30, 0x82, 0x03, 0x00]),
            ContentKind::CertContainer
        );
        assert_eq!(
            classify(b"-----BEGIN CERTIFICATE-----\nMIID"),
            ContentKind::CertContainer
        );
        assert_eq!(
            classify(b"SQLite format 3\0rest"),
            ContentKind::CertContainer
        );
        assert_eq!(
            classify(b"root:x:0:0:root:/root:/bin/bash\n"),
            ContentKind::Text
        );
        // GGUF model magic, contains NULs.
        assert_eq!(classify(b"GGUF\x03\0\0\0\x00\x01"), ContentKind::Opaque);
        // ELF executable.
        assert_eq!(
            classify(b"\x7fELF\x02\x01\x01\x00\x00"),
            ContentKind::Opaque
        );
    }
}
