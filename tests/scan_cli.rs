//! End-to-end test: build a small tree full of both real traces and decoys,
//! then check that the binary finds exactly the real ones.

use std::path::{Path, PathBuf};
use std::process::Command;

fn certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs")
}

fn read_der(name: &str) -> Vec<u8> {
    std::fs::read(certs_dir().join(name)).unwrap()
}

fn pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

fn setup() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("emudhra-scan-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("nested")).unwrap();

    // 1. A raw DER certificate on disk.
    std::fs::write(dir.join("intermediate.der"), read_der("ev_tls_g3b.der")).unwrap();

    // 2. A PEM bundle wrapping a different compromised certificate.
    std::fs::write(
        dir.join("ca-bundle.crt"),
        format!(
            "# combined trust bundle\n{}\n# end\n",
            pem(&read_der("dv_tls_g3c.der"))
        ),
    )
    .unwrap();

    // 3. A text file that only references a serial number.
    std::fs::write(
        dir.join("revocations.txt"),
        "revoked serial 6CADA367FB1C100088120EA202D568\n",
    )
    .unwrap();

    // 4. A fake binary keystore with a certificate buried in it.
    let mut keystore = vec![0x00u8; 512];
    keystore.extend_from_slice(&read_der("ov_cs_g3b.der"));
    keystore.extend_from_slice(&[0xABu8; 64]);
    std::fs::write(dir.join("nested").join("keystore.bin"), keystore).unwrap();

    // 5. Decoys that must NOT be reported.
    let garbage: Vec<u8> = (0..120u32).map(|i| (i * 7 + 13) as u8).collect();
    std::fs::write(dir.join("decoy.pem"), pem(&garbage)).unwrap();
    std::fs::write(dir.join("notes.txt"), "just some unrelated notes\n").unwrap();

    // 6. A decoy mentioning a different CA vendor name (not eMudhra, not the
    //    compromised issuer CNs).
    std::fs::write(dir.join("other-ca.txt"), "EM DV TLS CA - NOT-A-REAL-NAME\n").unwrap();

    dir
}

fn findings_for<'a>(json: &'a serde_json::Value, suffix: &str) -> Option<&'a serde_json::Value> {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with(suffix))
}

#[test]
fn end_to_end_finds_real_traces_and_ignores_decoys() {
    let dir = setup();
    let out = Command::new(env!("CARGO_BIN_EXE_i-can-count-to-four"))
        .arg(&dir)
        .args(["--json", "--quiet"])
        .output()
        .expect("failed to run binary");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");

    assert_eq!(json["summary"]["high_confidence"], 3, "json: {json}");

    // Raw DER file: exact bytes.
    let der = findings_for(&json, "intermediate.der").expect("intermediate.der reported");
    assert!(der["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "exact-cert-bytes"));
    assert_eq!(der["targets"][0], "EM EV TLS CA - G3B");

    // PEM bundle: decoded.
    let bundle = findings_for(&json, "ca-bundle.crt").expect("ca-bundle.crt reported");
    assert!(bundle["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "exact-cert-pem"));
    assert_eq!(bundle["targets"][0], "EM DV TLS CA - G3C");

    // Keystore: embedded DER bytes.
    let ks = findings_for(&json, "keystore.bin").expect("keystore.bin reported");
    assert!(ks["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "exact-cert-bytes"));
    assert_eq!(ks["targets"][0], "EM OV CS CA - G3B");

    // Text reference only: low confidence.
    let refs = findings_for(&json, "revocations.txt").expect("revocations.txt reported");
    assert!(refs["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "serial-number"));
    assert_eq!(refs["high_confidence"], false);

    // Decoys.
    assert!(findings_for(&json, "decoy.pem").is_none());
    assert!(findings_for(&json, "notes.txt").is_none());
    assert!(findings_for(&json, "other-ca.txt").is_none());

    let _ = std::fs::remove_dir_all(Path::new(&dir));
}

/// A certificate placed so that it straddles the streaming buffer boundary must
/// still be detected (this exercises the chunk-overlap logic).
#[test]
fn detects_certificate_straddling_chunk_boundary() {
    // Keep in sync with `CHUNK` in src/main.rs (8 MiB).
    const CHUNK: u64 = 8 * 1024 * 1024;

    let dir = std::env::temp_dir().join(format!("emudhra-scan-boundary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let der = read_der("ev_tls_g3c.der");
    let offset = (CHUNK - 400) as usize; // DER starts just before the boundary
    let mut blob = vec![0u8; offset];
    blob.extend_from_slice(&der);
    blob.extend_from_slice(&[0u8; 1024]);
    std::fs::write(dir.join("straddle.bin"), &blob).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_i-can-count-to-four"))
        .arg(&dir)
        .args(["--json", "--quiet"])
        .output()
        .expect("failed to run binary");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    let f = findings_for(&json, "straddle.bin").expect("straddle.bin reported");
    assert!(f["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "exact-cert-bytes"));
    assert_eq!(f["targets"][0], "EM EV TLS CA - G3C");

    let _ = std::fs::remove_dir_all(Path::new(&dir));
}

/// Large opaque files are only read at head and tail by default, so a
/// certificate buried in the middle is missed unless `--thorough` is used.
#[test]
fn large_opaque_files_are_sampled_unless_thorough() {
    let dir = std::env::temp_dir().join(format!("emudhra-scan-sample-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let der = read_der("ov_tls_g3b.der");
    let mut blob = vec![0xAAu8; 20 * 1024 * 1024];
    let mid = blob.len() / 2;
    blob[mid..mid + der.len()].copy_from_slice(&der);
    std::fs::write(dir.join("big.bin"), &blob).unwrap();

    // Default (sane) mode: not read in full, so not found.
    let out = Command::new(env!("CARGO_BIN_EXE_i-can-count-to-four"))
        .arg(&dir)
        .args(["--json", "--quiet"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(findings_for(&json, "big.bin").is_none(), "json: {json}");
    assert!(json["summary"]["partially_read"].as_u64().unwrap() >= 1);

    // Thorough mode: read fully, so found.
    let out = Command::new(env!("CARGO_BIN_EXE_i-can-count-to-four"))
        .arg(&dir)
        .args(["--json", "--quiet", "--thorough"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = findings_for(&json, "big.bin").expect("found with --thorough");
    assert!(f["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "exact-cert-bytes"));

    let _ = std::fs::remove_dir_all(Path::new(&dir));
}
