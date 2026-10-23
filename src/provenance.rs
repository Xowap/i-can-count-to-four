//! Provenance: why is this file here, and what should be done about it?
//!
//! This is the one place where path/ecosystem knowledge is *deliberately*
//! allowed: the scan stays name-agnostic, but explaining a hit to a human
//! requires knowing that `site-packages/certifi/cacert.pem` came from a Python
//! package and `~/.mozilla/firefox/...` came from Firefox.

use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// There is a concrete update/refresh you should perform.
    Update,
    /// Explained, but there is nothing to update (cache, log, your own copies).
    Informational,
}

pub struct Owner {
    pub id: &'static str,
    pub title: &'static str,
    pub why: &'static str,
    pub action: Action,
    pub fix: &'static [&'static str],
}

pub static OWNERS: &[Owner] = &[
    Owner {
        id: "own_project",
        title: "Your own project, build artifacts and test fixtures",
        why: "Copies you created yourself: the certificates embedded in this tool's certs/, \
              the compiled artifacts in target/, and the fixture trees in /tmp used by the tests.",
        action: Action::Informational,
        fix: &["# Nothing to update \u{2014} these are your own copies.", "cargo clean        # if you want to drop the build artifacts"],
    },
    Owner {
        id: "system_apt",
        title: "System trust store (APT / Debian, Ubuntu)",
        why: "The ca-certificates package ships the CA bundle; it contains the eMudhra roots. \
              Updating it is the supported fix for RHSB-2026-012.",
        action: Action::Update,
        fix: &[
            "sudo apt update && sudo apt install --only-upgrade ca-certificates",
            "sudo update-ca-certificates -f",
        ],
    },
    Owner {
        id: "system_rpm",
        title: "System trust store (RPM / Fedora, RHEL, CentOS)",
        why: "The ca-certificates package populates /etc/pki/ca-trust; it contains the eMudhra roots.",
        action: Action::Update,
        fix: &["sudo dnf upgrade ca-certificates", "sudo update-ca-trust extract"],
    },
    Owner {
        id: "flatpak",
        title: "Flatpak runtimes",
        why: "Runtime bundles such as org.gnome.Platform / org.kde.Platform ship their own CA \
              bundle (java cacerts, ca-bundle.trust, p11-kit) containing the eMudhra roots.",
        action: Action::Update,
        fix: &["flatpak update", "flatpak uninstall --unused"],
    },
    Owner {
        id: "snap",
        title: "Snap packages",
        why: "Snap payloads can carry their own CA bundle.",
        action: Action::Update,
        fix: &["sudo snap refresh"],
    },
    Owner {
        id: "docker",
        title: "Docker / containerd images and layers",
        why: "Container images ship their distro's CA bundle. Update the base image and rebuild.",
        action: Action::Update,
        fix: &["docker pull <image>            # refreshed base images", "# then rebuild your images from the updated base"],
    },
    Owner {
        id: "java",
        title: "Java keystore (JDK / JRE cacerts)",
        why: "Java keeps its own trust store. On Debian it is generated from the system store; \
              otherwise it is updated with the JDK or edited with keytool.",
        action: Action::Update,
        fix: &[
            "sudo update-ca-certificates -f          # Debian: regenerates the cacerts keystore",
            "# or update the JDK, or drop the alias:",
            "sudo keytool -delete -alias <alias> -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit",
        ],
    },
    Owner {
        id: "python",
        title: "Python packages (certifi, virtualenvs, pip/uv/poetry caches)",
        why: "The certifi package bundles a CA set that includes the eMudhra roots. It is pulled \
              in by pip/uv/poetry and copied into virtualenvs and package caches.",
        action: Action::Update,
        fix: &[
            "pip install --upgrade certifi",
            "uv sync --upgrade               # refresh uv-managed environments",
            "poetry update",
            "rm -rf ~/.cache/uv ~/.cache/pip # then re-resolve; old venvs should be recreated",
        ],
    },
    Owner {
        id: "node",
        title: "Node.js / npm packages",
        why: "A dependency (or npm's own cache) carries a CA bundle.",
        action: Action::Update,
        fix: &["npm update", "npm cache clean --force"],
    },
    Owner {
        id: "rust",
        title: "Rust / Cargo build artifacts",
        why: "Compiled artifacts that embedded a certificate or CA blob at build time.",
        action: Action::Informational,
        fix: &["cargo clean          # rebuild from source"],
    },
    Owner {
        id: "go",
        title: "Go toolchain and module cache",
        why: "Go has its own X.509 verifier. The upstream fix filters these certificates by SPKI \
              hash (CVE-2026-111943), so update Go itself.",
        action: Action::Update,
        fix: &[
            "# Requires Go 1.27.3+ or 1.26.10+:",
            "go install golang.org/dl/go1.27.3@latest && go1.27.3 download",
            "go clean -modcache",
        ],
    },
    Owner {
        id: "browser_firefox",
        title: "Firefox profile (security state + cert DB)",
        why: "Firefox stores the intermediates it was told to distrust (security_state/data.safe.bin) \
              and its cached downloads. This is browser-managed.",
        action: Action::Informational,
        fix: &["# Update Firefox; it refreshes security-state data automatically.", "# Nothing to hand-edit."],
    },
    Owner {
        id: "chrome_trust",
        title: "Chrome / Chromium PKI data (NSS DB, CRLSet metadata)",
        why: "Chrome/Chromium keep a trust store and a CRLSet in their profile. The CRLSet is \
              Chrome's own revocation list and is refreshed by Chrome itself.",
        action: Action::Update,
        fix: &[
            "# Update Chrome/Chromium (refreshes the CRLSet automatically).",
            "certutil -D -n '<nickname>' -d sql:$HOME/.pki/nssdb   # to drop an entry by hand",
        ],
    },
    Owner {
        id: "chrome_profile",
        title: "Chrome / Chromium profile data and caches",
        why: "Browser history, session/indexedDB/levelDB and caches that merely recorded a page \
              mentioning eMudhra. Not a trust store.",
        action: Action::Informational,
        fix: &["# No trust impact. Clear if you like: chrome://settings/clearBrowserData"],
    },
    Owner {
        id: "browser_cache",
        title: "Browser HTTP cache",
        why: "Cached HTTP responses (for example the certificate files Firefox downloaded from \
              Mozilla's security-state CDN). These are just downloads, not a trust store.",
        action: Action::Informational,
        fix: &["# No trust impact. Clear if you like:", "#   Firefox: Settings \u{2192} Privacy \u{2192} Clear Data", "#   Chrome:  chrome://settings/clearBrowserData"],
    },
    Owner {
        id: "app_cache",
        title: "Application / tool caches",
        why: "Extracted or downloaded data kept by tools and IDEs (uv, poetry, JetBrains, Playwright, \u{2026}).",
        action: Action::Informational,
        fix: &["# Safe to clear:  rm -rf ~/.cache/<tool>"],
    },
    Owner {
        id: "tool_logs",
        title: "Tool logs and shell output",
        why: "Logs that captured the fingerprints/hashes you were working with.",
        action: Action::Informational,
        fix: &[],
    },
    Owner {
        id: "tmp",
        title: "Temporary files",
        why: "Copies in /tmp or /var/tmp \u{2014} usually scratch data or test fixtures.",
        action: Action::Informational,
        fix: &["# Temporary; remove when convenient."],
    },
    Owner {
        id: "reference",
        title: "Text references (fingerprints, serials, names)",
        why: "Files that merely mention a fingerprint, serial or CN as text \u{2014} logs, configs, \
              lockfiles, docs, source. They do not carry a usable certificate.",
        action: Action::Informational,
        fix: &[],
    },
    Owner {
        id: "unknown",
        title: "Unknown / unclassified",
        why: "We could not attribute these to a known package, store or cache.",
        action: Action::Informational,
        fix: &[],
    },
];

pub fn by_id(id: &str) -> &'static Owner {
    OWNERS
        .iter()
        .find(|o| o.id == id)
        .unwrap_or_else(|| by_id("unknown"))
}

/// Does this path look like it holds a certificate or CA bundle (as opposed to
/// merely being some file that happens to live inside a package directory)?
fn looks_like_store(path: &str) -> bool {
    const MARKERS: &[&str] = &[
        "cacert",
        "cacerts",
        "ca-bundle",
        "ca_bundle",
        "ca-certificates",
        "certificates.crt",
        "cert.pem",
        "certs.pem",
        "roots.pem",
        "root.pem",
        "truststore",
        "cert9.db",
        "cert8.db",
        "key4.db",
        "key3.db",
        "nssdb",
        ".crt",
        ".cer",
        ".pem",
        ".der",
        ".p12",
        ".pfx",
        ".jks",
        ".p7b",
    ];
    MARKERS.iter().any(|m| path.contains(m))
}

/// Classify a finding path. `has_high_confidence` is true when the file
/// provably contains the certificate (rather than merely mentioning it).
pub fn classify(path: &Path, has_high_confidence: bool) -> &'static Owner {
    let p = path.to_string_lossy();
    let has = |s: &str| p.contains(s);

    // Ordered, most specific first. Folders/ecosystems are matched on the path
    // only for *explanation*, never to skip scanning.

    // --- your own stuff, logs, scratch -----------------------------------
    if has("/i-can-count-to-four/") {
        return by_id("own_project");
    }
    if has("/.local/share/opencode/") {
        return by_id("tool_logs");
    }
    if has("/tmp/") || has("/var/tmp/") {
        return by_id("tmp");
    }

    // --- browsers ---------------------------------------------------------
    if has("/cache2/") || has("/Cache_Data/") {
        return by_id("browser_cache");
    }
    if has("/.mozilla/") {
        return by_id("browser_firefox");
    }
    if has("/.pki/nssdb") || has("/PKIMetadata/") {
        return by_id("chrome_trust");
    }
    if has("/google-chrome/") || has("/chromium/") {
        return by_id("chrome_profile");
    }

    // --- packaged / system trust stores ----------------------------------
    if has("/flatpak/") {
        return by_id("flatpak");
    }
    if has("/snap/") || has("/snapd/") {
        return by_id("snap");
    }
    if has("/docker/") || has("/containerd/") || has("/overlay2/") {
        return by_id("docker");
    }
    if has("/lib/security/cacerts") || has("/certs/java/") || has("/java/cacerts") || has("/jvm/") {
        return by_id("java");
    }
    if has("/usr/share/ca-certificates/")
        || has("/etc/ssl/certs/")
        || has("/usr/lib/ssl/")
        || has("/etc/ca-certificates")
    {
        return by_id("system_apt");
    }
    if has("/etc/pki/") {
        return by_id("system_rpm");
    }

    // --- language package ecosystems -------------------------------------
    // Only call it a package-CA issue when the file really looks like a store
    // (a CA bundle) or provably contains the certificate. Otherwise it is just
    // a text mention inside some package and gets the "reference" bucket.
    let meaningful = has_high_confidence || looks_like_store(&p);
    if meaningful
        && (has("/site-packages/")
            || has("/dist-packages/")
            || has("certifi")
            || has("/.venv/")
            || has("/virtualenv")
            || has("/.cache/uv/")
            || has("/.cache/pip")
            || has("/.cache/pypoetry")
            || has("/conda")
            || has("/miniconda")
            || has("/depot_tools"))
    {
        return by_id("python");
    }
    if meaningful && (has("/node_modules/") || has("/.npm/") || has("/nvm/")) {
        return by_id("node");
    }
    if meaningful && (has("/go/pkg/mod") || has("/pkg/mod/") || has("/gopath/")) {
        return by_id("go");
    }
    if meaningful && (has("/target/debug/") || has("/target/release/") || has("/.cargo/")) {
        return by_id("rust");
    }

    // --- caches and the rest ---------------------------------------------
    if has("/.cache/") {
        return by_id("app_cache");
    }
    if has_high_confidence {
        by_id("unknown")
    } else {
        by_id("reference")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn id(p: &str, hc: bool) -> &'static str {
        classify(Path::new(p), hc).id
    }

    #[test]
    fn classifies_common_locations() {
        assert_eq!(
            id("/usr/share/ca-certificates/mozilla/x.crt", true),
            "system_apt"
        );
        assert_eq!(id("/etc/ssl/certs/java/cacerts", false), "java");
        assert_eq!(
            id(
                "/var/lib/flatpak/runtime/org.gnome.Platform/x/files/etc/pki/ca-trust/extracted/java/cacerts",
                false
            ),
            "flatpak"
        );
        assert_eq!(
            id(
                "/home/u/.local/lib/python3.12/site-packages/certifi/cacert.pem",
                true
            ),
            "python"
        );
        assert_eq!(
            id("/home/u/.cache/uv/archive/certifi/cacert.pem", true),
            "python"
        );
        assert_eq!(id("/home/u/proj/node_modules/x/ca.pem", true), "node");
        assert_eq!(
            id("/home/u/proj/node_modules/x/domain-map.csv", false),
            "reference"
        );
        assert_eq!(
            id(
                "/home/u/.cache/google-chrome/Default/Cache/Cache_Data/e704",
                false
            ),
            "browser_cache"
        );
        assert_eq!(
            id(
                "/home/u/.config/google-chrome/PKIMetadata/1810/crs.pb",
                false
            ),
            "chrome_trust"
        );
        assert_eq!(
            id("/home/u/.config/google-chrome/Default/History", false),
            "chrome_profile"
        );
        assert_eq!(
            id(
                "/home/u/.mozilla/firefox/abc/security_state/data.safe.bin",
                true
            ),
            "browser_firefox"
        );
        assert_eq!(id("/tmp/foo/bar.der", true), "tmp");
        assert_eq!(id("/etc/passwd", false), "reference");
        assert_eq!(id("/home/u/weird/thing.bin", true), "unknown");
    }
}
