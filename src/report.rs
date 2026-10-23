//! Turning findings into output.

use std::path::PathBuf;

use crate::scan::{Analysis, Finding};
use crate::targets::TARGETS;

pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub analysis: Analysis,
}

impl FileReport {
    pub fn is_high_confidence(&self) -> bool {
        self.analysis
            .findings
            .iter()
            .any(|f| f.is_high_confidence())
    }

    pub fn to_json(&self) -> serde_json::Value {
        let findings: Vec<&str> = self.analysis.findings.iter().map(|f| f.label()).collect();
        let targets: Vec<&str> = self
            .analysis
            .targets
            .iter()
            .map(|&i| TARGETS[i].name)
            .collect();
        let certs: Vec<serde_json::Value> = self
            .analysis
            .certs
            .iter()
            .map(|c| {
                serde_json::json!({
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "serial": c.serial,
                    "not_before": c.not_before,
                    "not_after": c.not_after,
                    "cert_sha256": c.cert_sha256,
                    "spki_sha256": c.spki_sha256,
                })
            })
            .collect();
        let offsets: Vec<u64> = self.analysis.offsets.to_vec();

        let owner = crate::provenance::classify(&self.path, self.is_high_confidence());
        let provenance = serde_json::json!({
            "id": owner.id,
            "title": owner.title,
            "why": owner.why,
            "fix": owner.fix,
            "action": match owner.action {
                crate::provenance::Action::Update => "update",
                crate::provenance::Action::Informational => "info",
            },
        });

        serde_json::json!({
            "path": self.path.to_string_lossy(),
            "size": self.size,
            "high_confidence": self.is_high_confidence(),
            "provenance": provenance,
            "findings": findings,
            "targets": targets,
            "offsets": offsets,
            "certs": certs,
        })
    }
}

/// Rebuild reports and a summary from a previously saved `--json` file, so a
/// report can be re-rendered without re-scanning.
pub fn load_json(
    path: &std::path::Path,
) -> Result<(Vec<FileReport>, crate::render::Summary), String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&data).map_err(|e| e.to_string())?;

    let mut reports = Vec::new();
    if let Some(arr) = v["findings"].as_array() {
        for f in arr {
            let mut analysis = Analysis::default();
            if let Some(fs) = f["findings"].as_array() {
                for x in fs {
                    if let Some(k) = x.as_str().and_then(Finding::from_label) {
                        analysis.findings.insert(k);
                    }
                }
            }
            if let Some(ts) = f["targets"].as_array() {
                for x in ts {
                    if let Some(i) = x.as_str().and_then(crate::targets::index_by_name) {
                        analysis.targets.insert(i);
                    }
                }
            }
            reports.push(FileReport {
                path: PathBuf::from(f["path"].as_str().unwrap_or_default()),
                size: f["size"].as_u64().unwrap_or(0),
                analysis,
            });
        }
    }

    let sm = &v["summary"];
    let summary = crate::render::Summary {
        files: sm["files_scanned"].as_u64().unwrap_or(0),
        bytes: sm["bytes_scanned"].as_u64().unwrap_or(0),
        elapsed: sm["elapsed_secs"].as_f64().unwrap_or(0.0),
        high: sm["high_confidence"].as_u64().unwrap_or(0) as usize,
        partial: sm["partially_read"].as_u64().unwrap_or(0),
        thorough: sm["thorough"].as_bool().unwrap_or(false),
    };

    Ok((reports, summary))
}

/// Order reports: strongest findings first, then by path.
pub fn sort_reports(reports: &mut [FileReport]) {
    reports.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.path.cmp(&b.path)));
}

/// Rank a report for output ordering: strong findings first.
pub fn rank(f: &FileReport) -> u8 {
    if f.analysis.findings.contains(&Finding::ExactDer)
        || f.analysis.findings.contains(&Finding::ExactPem)
        || f.analysis.findings.contains(&Finding::SpkiMatch)
    {
        0
    } else if f.analysis.findings.contains(&Finding::CertFingerprintRef)
        || f.analysis.findings.contains(&Finding::SpkiFingerprintRef)
        || f.analysis.findings.contains(&Finding::SerialRef)
    {
        1
    } else {
        2
    }
}
