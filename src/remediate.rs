//! Remediation plan: collapse thousands of file hits into the *things to
//! upgrade* (a project, a Flatpak runtime, a JDK, a tool) plus a command for
//! each.
//!
//! For Python virtualenvs and `node_modules` the correct fix is to re-resolve
//! the owning *project*, so we resolve the venv back to its project directory
//! (via `pyvenv.cfg` and editable `.pth` / `direct_url.json`) and detect the
//! package manager from the project's lockfiles, then emit the re-lock command.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::report::FileReport;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PlanAction {
    /// Install a newer version of a package/tool/runtime.
    Upgrade,
    /// Clear a cache or let the application refresh itself.
    Clear,
    /// Delete scratch/duplicate copies.
    Remove,
}

impl PlanAction {
    pub fn label(self) -> &'static str {
        match self {
            PlanAction::Upgrade => "UPGRADE",
            PlanAction::Clear => "CLEAR",
            PlanAction::Remove => "REMOVE",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlanItem {
    pub action: PlanAction,
    pub kind: &'static str,
    pub unit: String,
    pub command: Vec<String>,
    pub files: usize,
    pub intermediate: bool,
    pub intermediate_files: usize,
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn short(path: &str) -> String {
    let h = home();
    if !h.is_empty() {
        if let Some(rest) = path.strip_prefix(&h) {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

fn before<'a>(path: &'a str, marker: &str) -> &'a str {
    match path.find(marker) {
        Some(i) => &path[..i],
        None => path,
    }
}

/// A shell-safe (quoted) path for a `cd`, using `$HOME` so quotes are safe.
fn shell_path(p: &Path) -> String {
    let h = home();
    let s = p.to_string_lossy();
    let with = if !h.is_empty() && s.starts_with(&h) {
        format!("$HOME{}", &s[h.len()..])
    } else {
        s.to_string()
    };
    format!("\"{with}\"")
}

fn item(action: PlanAction, kind: &'static str, unit: String, command: &[&str]) -> PlanItem {
    PlanItem {
        action,
        kind,
        unit,
        command: command.iter().map(|s| s.to_string()).collect(),
        files: 0,
        intermediate: false,
        intermediate_files: 0,
    }
}

// ---------------------------------------------------------------------------
// Python project / manager detection
// ---------------------------------------------------------------------------

/// `<venv>/lib/python*/site-packages` directories.
fn site_packages(venv: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(venv.join("lib")) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with("python") {
                let sp = e.path().join("site-packages");
                if sp.is_dir() {
                    out.push(sp);
                }
            }
        }
    }
    out
}

/// Editable install targets recorded inside a venv (project roots).
fn editable_projects(venv: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for sp in site_packages(venv) {
        let Ok(rd) = std::fs::read_dir(&sp) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let p = e.path();
            if name.ends_with(".pth") {
                if let Ok(txt) = std::fs::read_to_string(&p) {
                    for line in txt.lines() {
                        let line = line.trim();
                        if line.starts_with('/') {
                            out.push(PathBuf::from(line));
                        }
                    }
                }
            } else if name.ends_with(".dist-info") {
                if let Ok(txt) = std::fs::read_to_string(p.join("direct_url.json")) {
                    if let Some(u) = txt.split("file://").nth(1) {
                        let path = u.split('"').next().unwrap_or("");
                        if path.starts_with('/') {
                            out.push(PathBuf::from(path));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Poetry/uv name a cache venv after the project; derive that hint.
fn venv_hint(name: &str) -> String {
    let parts: Vec<&str> = name.split('-').collect();
    let mut end = parts.len();
    if end > 0 {
        let last = parts[end - 1];
        if last.starts_with("py")
            && last[2..].chars().all(|c| c.is_ascii_digit() || c == '.')
            && last.len() > 2
        {
            end -= 1;
        }
    }
    if end > 1 {
        let h = parts[end - 1];
        if h.len() == 8 && h.chars().all(|c| c.is_ascii_alphanumeric()) {
            end -= 1;
        }
    }
    parts[..end].join("-").to_lowercase()
}

/// Poetry stores a clean `<name>-py<ver>` prompt in pyvenv.cfg.
fn venv_prompt(venv: &Path) -> Option<String> {
    let cfg = std::fs::read_to_string(venv.join("pyvenv.cfg")).ok()?;
    cfg.lines()
        .find_map(|l| l.strip_prefix("prompt = "))
        .map(|s| s.trim().to_string())
}

fn strip_py_suffix(s: &str) -> String {
    if let Some(i) = s.rfind("-py") {
        let tail = &s[i + 3..];
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return s[..i].to_string();
        }
    }
    s.to_string()
}

fn detect_manager(project: &Path, venv: &Path) -> &'static str {
    if project.join("uv.lock").exists() {
        return "uv";
    }
    if project.join("poetry.lock").exists() {
        return "poetry";
    }
    if project.join("pdm.lock").exists() {
        return "pdm";
    }
    if project.join("Pipfile.lock").exists() {
        return "pipenv";
    }
    if let Ok(cfg) = std::fs::read_to_string(venv.join("pyvenv.cfg")) {
        if cfg.contains("uv = ") {
            return "uv";
        }
    }
    if venv.to_string_lossy().contains("/.cache/pypoetry/") {
        return "poetry";
    }
    if project.join("requirements.txt").exists() {
        return "pip";
    }
    if project.join("pyproject.toml").exists() {
        return "pyproject";
    }
    "pip"
}

fn python_commands(manager: &str, project: &Path) -> String {
    let p = shell_path(project);
    match manager {
        "uv" => format!("cd {p} && uv lock --upgrade && uv sync"),
        "poetry" => format!("cd {p} && poetry update"),
        "pdm" => format!("cd {p} && pdm update"),
        "pipenv" => format!("cd {p} && pipenv update"),
        "pyproject" => {
            format!("cd {p} && <your manager> lock --upgrade   # pyproject.toml, no lockfile")
        }
        _ => format!("cd {p} && pip install --upgrade certifi"),
    }
}

fn python_kind(manager: &str) -> &'static str {
    match manager {
        "uv" => "Python project (uv)",
        "poetry" => "Python project (poetry)",
        "pdm" => "Python project (pdm)",
        "pipenv" => "Python project (pipenv)",
        _ => "Python project (pip)",
    }
}

/// Resolve a virtualenv to (project dir, package manager), if possible.
fn resolve_python(venv_root: &str) -> Option<(PathBuf, &'static str)> {
    let venv = Path::new(venv_root);
    if !venv.join("pyvenv.cfg").exists() {
        return None;
    }
    let name = venv.file_name()?.to_string_lossy().to_string();

    let project = if name == ".venv" || name == "venv" || name == ".virtualenv" {
        venv.parent()?.to_path_buf()
    } else {
        let hint = venv_prompt(venv)
            .map(|p| strip_py_suffix(&p))
            .unwrap_or_else(|| venv_hint(&name))
            .to_lowercase();
        let mut candidates: Vec<PathBuf> = editable_projects(venv)
            .into_iter()
            .filter(|c| c.exists())
            .collect();
        candidates.sort();
        candidates.dedup();
        let norm = |c: &PathBuf| c.to_string_lossy().replace('/', "-").to_lowercase();
        let by_hint = candidates
            .iter()
            .find(|c| !hint.is_empty() && norm(c).contains(&hint))
            .cloned();
        let by_project = candidates
            .iter()
            .filter(|c| {
                c.join("pyproject.toml").exists()
                    || c.join("uv.lock").exists()
                    || c.join("poetry.lock").exists()
            })
            .min_by_key(|c| c.as_os_str().len())
            .cloned();
        by_hint.or(by_project)?
    };
    if !project.exists() {
        return None;
    }
    let manager = detect_manager(&project, venv);
    Some((project, manager))
}

// ---------------------------------------------------------------------------
// Node project / manager detection
// ---------------------------------------------------------------------------

fn node_manager(project: &Path) -> &'static str {
    if project.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if project.join("yarn.lock").exists() {
        "yarn"
    } else if project.join("bun.lockb").exists() || project.join("bun.lock").exists() {
        "bun"
    } else {
        "npm"
    }
}

fn node_command(manager: &str, project: &Path) -> String {
    let p = shell_path(project);
    match manager {
        "pnpm" => format!("cd {p} && pnpm update"),
        "yarn" => format!("cd {p} && yarn up"),
        "bun" => format!("cd {p} && bun update"),
        _ => format!("cd {p} && npm update"),
    }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Cache {
    python: HashMap<String, Option<(PathBuf, &'static str)>>,
    node: HashMap<String, (&'static str, PathBuf)>,
}

fn classify(path: &str, cache: &mut Cache) -> Option<PlanItem> {
    if path.contains("/i-can-count-to-four/") {
        return Some(item(
            PlanAction::Remove,
            "Your own copies",
            "i-can-count-to-four project (certs/, target/, fixtures)".into(),
            &["cargo clean   # drop build artifacts if you like"],
        ));
    }
    if path.contains("/tmp/") || path.contains("/var/tmp/") {
        return Some(item(
            PlanAction::Remove,
            "Temporary files",
            "/tmp".into(),
            &["# delete when convenient"],
        ));
    }
    if path.contains("/cache2/") || path.contains("/Cache_Data/") {
        return Some(item(
            PlanAction::Clear,
            "Browser cache",
            "cached downloads (Firefox/Chrome)".into(),
            &[
                "# just cached files, no trust impact",
                "# clear via the browser's Clear Data",
            ],
        ));
    }
    if path.contains("/.mozilla/") {
        return Some(item(
            PlanAction::Clear,
            "Firefox",
            "profile security state".into(),
            &[
                "# update Firefox; it refreshes security-state data itself",
                "# or clear cached data: Settings \u{2192} Privacy \u{2192} Clear Data",
            ],
        ));
    }
    if path.contains("/PKIMetadata/") || path.contains("/.pki/nssdb") {
        return Some(item(
            PlanAction::Upgrade,
            "Browser",
            "Chrome / Chromium".into(),
            &["# update Chrome/Chromium (it refreshes its CRLSet itself)"],
        ));
    }
    if let Some(i) = path.find("/flatpak/") {
        let rest = &path[i + "/flatpak/".len()..];
        let parts: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
        let unit = match parts.first().copied() {
            Some(k @ ("runtime" | "app")) if parts.len() >= 4 => {
                format!("{k} {} {}/{}", parts[1], parts[2], parts[3])
            }
            Some(".removed") => "orphaned runtime files (garbage-collect)".to_string(),
            Some("repo") => "ostree repo objects (content-addressed)".to_string(),
            _ => parts.first().copied().unwrap_or("flatpak").to_string(),
        };
        return Some(item(
            PlanAction::Upgrade,
            "Flatpak runtime",
            unit,
            &["flatpak update", "flatpak uninstall --unused"],
        ));
    }
    if path.contains("/lib/security/cacerts")
        || path.contains("/certs/java/")
        || path.contains("/jvm/")
    {
        let root = if let Some(i) = path.find("/lib/security/cacerts") {
            &path[..i]
        } else {
            before(path, "/certs/java")
        };
        return Some(item(
            PlanAction::Upgrade,
            "JDK / JRE",
            short(root),
            &[
                "sudo update-ca-certificates -f   # Debian regenerates the cacerts keystore",
                "sudo keytool -delete -alias <alias> -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit",
            ],
        ));
    }
    if path.contains("/usr/share/ca-certificates/")
        || path.contains("/etc/ssl/certs/")
        || path.contains("/etc/ca-certificates")
    {
        return Some(item(
            PlanAction::Upgrade,
            "System CA store (apt)",
            "ca-certificates (Debian/Ubuntu)".into(),
            &[
                "sudo apt update && sudo apt install --only-upgrade ca-certificates",
                "sudo update-ca-certificates -f",
            ],
        ));
    }
    if path.contains("/etc/pki/") {
        return Some(item(
            PlanAction::Upgrade,
            "System CA store (rpm)",
            "ca-certificates (Fedora/RHEL)".into(),
            &[
                "sudo dnf upgrade ca-certificates",
                "sudo update-ca-trust extract",
            ],
        ));
    }

    // --- Node: resolve the project and its package manager ----------------
    if path.contains("/node_modules/") {
        let proj = PathBuf::from(before(path, "/node_modules"));
        let (manager, _) = cache
            .node
            .entry(proj.to_string_lossy().to_string())
            .or_insert_with(|| (node_manager(&proj), proj.clone()))
            .clone();
        let cmd = node_command(manager, &proj);
        let kind = match manager {
            "pnpm" => "Node project (pnpm)",
            "yarn" => "Node project (yarn)",
            "bun" => "Node project (bun)",
            _ => "Node project (npm)",
        };
        return Some(item(
            PlanAction::Upgrade,
            kind,
            short(&proj.to_string_lossy()),
            &[cmd.as_str()],
        ));
    }

    // --- Python -----------------------------------------------------------
    if path.contains("/site-packages/")
        || path.contains("/dist-packages/")
        || path.contains("certifi")
    {
        let root = if let Some(i) = path.find("/lib/python") {
            &path[..i]
        } else {
            before(path, "/site-packages")
        };

        if path.contains("/.cache/uv/") {
            return Some(item(
                PlanAction::Upgrade,
                "uv cache (Python)",
                "uv package cache".into(),
                &["uv cache clean", "uv sync   # re-resolve each project"],
            ));
        }
        if path.contains("google-cloud-sdk") {
            return Some(item(
                PlanAction::Upgrade,
                "Google Cloud SDK",
                "gcloud".into(),
                &["gcloud components update"],
            ));
        }
        if path.contains("/.local/share/uv/tools/") {
            let name = path
                .split("/uv/tools/")
                .nth(1)
                .and_then(|r| r.split('/').next())
                .unwrap_or("uv tool");
            return Some(item(
                PlanAction::Upgrade,
                "uv tool",
                format!("uv tool: {name}"),
                &["uv tool upgrade --all"],
            ));
        }
        if path.contains("/.local/share/uv/python/") {
            return Some(item(
                PlanAction::Upgrade,
                "uv Python toolchain",
                "uv-managed CPython builds".into(),
                &["uv python upgrade"],
            ));
        }
        if path.contains("/.cache/virtualenv/") || path.contains("/.local/share/virtualenv/") {
            return Some(item(
                PlanAction::Remove,
                "virtualenv wheel cache",
                "~/.cache/virtualenv".into(),
                &["rm -rf ~/.cache/virtualenv ~/.local/share/virtualenv"],
            ));
        }
        if path.contains("vpython") {
            return Some(item(
                PlanAction::Remove,
                "vpython cache",
                "~/.cache/vpython-root*".into(),
                &["rm -rf ~/.cache/vpython-root*"],
            ));
        }
        if path.contains("/JetBrains/") || path.contains("/Toolbox/") {
            return Some(item(
                PlanAction::Upgrade,
                "JetBrains bundled runtime",
                "IDE + bundled JBR/lldb".into(),
                &["# update via JetBrains Toolbox"],
            ));
        }
        if path.contains("activitywatch") {
            return Some(item(
                PlanAction::Upgrade,
                "ActivityWatch",
                "bundled Python (aw-*)".into(),
                &["# update/reinstall ActivityWatch"],
            ));
        }
        if path.contains("/conda/") || path.contains("/miniconda") || path.contains("/anaconda") {
            return Some(item(
                PlanAction::Upgrade,
                "conda environment",
                short(root),
                &["conda update certifi", "conda update --all"],
            ));
        }
        if path.contains("/usr/lib/python") || path.contains("/usr/local/lib/python") {
            return Some(item(
                PlanAction::Upgrade,
                "System Python",
                short(root),
                &[
                    "sudo apt install --only-upgrade python3-certifi",
                    "sudo update-ca-certificates",
                ],
            ));
        }

        // Poetry's own tool environment.
        if path.contains("/pypoetry/venv") {
            return Some(item(
                PlanAction::Upgrade,
                "Poetry (tool env)",
                "poetry".into(),
                &["poetry self update"],
            ));
        }

        // A real virtualenv: resolve it to its project + manager and re-lock.
        let resolved = cache
            .python
            .entry(root.to_string())
            .or_insert_with(|| resolve_python(root))
            .clone();
        if let Some((project, manager)) = resolved {
            let cmd = python_commands(manager, &project);
            return Some(item(
                PlanAction::Upgrade,
                python_kind(manager),
                short(&project.to_string_lossy()),
                &[cmd.as_str()],
            ));
        }

        // Could not map this env back to a project. If it is a Poetry cache
        // venv we at least know the manager.
        if root.contains("/.cache/pypoetry/") {
            return Some(item(
                PlanAction::Upgrade,
                "Poetry virtualenv (owner project unknown)",
                short(root),
                &[
                    "# owner project not recorded in the venv; in each project run: poetry update",
                    "for e in ~/.cache/pypoetry/virtualenvs/*/; do \"$e/bin/pip\" install --upgrade certifi; done",
                ],
            ));
        }
        let kind = if path.contains("/.venv/") || path.contains("/virtualenv") {
            "Virtualenv"
        } else {
            "Python environment"
        };
        return Some(item(
            PlanAction::Upgrade,
            kind,
            short(root),
            &["pip install --upgrade certifi   # inside each environment below"],
        ));
    }

    None
}

/// Build the deduplicated remediation plan from the findings.
pub fn plan(reports: &[FileReport]) -> Vec<PlanItem> {
    let mut items: Vec<PlanItem> = Vec::new();
    let mut index: BTreeMap<(PlanAction, &'static str, String), usize> = BTreeMap::new();
    let mut cache = Cache::default();

    for r in reports {
        let path = r.path.to_string_lossy();
        let Some(proto) = classify(&path, &mut cache) else {
            continue;
        };
        let has_cert = r.is_high_confidence();
        match index.get(&(proto.action, proto.kind, proto.unit.clone())) {
            Some(&i) => {
                items[i].files += 1;
                if has_cert {
                    items[i].intermediate = true;
                    items[i].intermediate_files += 1;
                }
            }
            None => {
                let mut it = proto;
                it.files = 1;
                it.intermediate = has_cert;
                it.intermediate_files = usize::from(has_cert);
                index.insert((it.action, it.kind, it.unit.clone()), items.len());
                items.push(it);
            }
        }
    }

    // Tools and version managers that are installed (they carry CA data too and
    // usually need updating in step with the projects that use them).
    items.extend(toolchain());

    items.sort_by(|a, b| {
        b.intermediate
            .cmp(&a.intermediate)
            .then(a.action.cmp(&b.action))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| b.files.cmp(&a.files))
    });
    items
}

const TOOLCHAIN: &str = "Toolchain (managers & version managers)";

fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

fn home_dir(sub: &str) -> bool {
    let h = home();
    !h.is_empty() && Path::new(&h).join(sub).is_dir()
}

/// Tools, package managers and version managers present on this machine.
fn toolchain() -> Vec<PlanItem> {
    let mut out: Vec<PlanItem> = Vec::new();
    let mut add = |unit: &str, cmd: &str| {
        out.push(item(
            PlanAction::Upgrade,
            TOOLCHAIN,
            unit.to_string(),
            &[cmd],
        ));
    };

    // Node version managers.
    if home_dir(".nvm") || on_path("nvm") {
        add(
            "nvm (Node versions)",
            "nvm install --lts --reinstall-packages-from=current && nvm alias default 'lts/*'",
        );
    }
    if home_dir(".local/share/fnm") || home_dir(".fnm") || on_path("fnm") {
        add(
            "fnm (Node versions)",
            "fnm install --lts && fnm default lts-latest",
        );
    }
    if home_dir(".volta") || on_path("volta") {
        add("volta (Node)", "volta install node@latest npm@latest");
    }
    if home_dir(".asdf") || on_path("asdf") {
        add(
            "asdf (multi-language)",
            "asdf plugin update --all && asdf install",
        );
    }
    if home_dir(".local/share/mise") || home_dir(".config/mise") || on_path("mise") {
        add("mise (multi-language)", "mise upgrade");
    }
    // Python version managers.
    if home_dir(".pyenv") || on_path("pyenv") {
        add(
            "pyenv (Python versions)",
            "pyenv update && pyenv install <latest>",
        );
    }
    if on_path("conda") {
        add("conda", "conda update -n base conda && conda update --all");
    }
    // Package managers / runtimes.
    if on_path("uv") {
        add("uv", "uv self update");
    }
    if on_path("poetry") {
        add("poetry", "poetry self update");
    }
    if on_path("pdm") {
        add("pdm", "pdm self update");
    }
    if on_path("pipenv") {
        add("pipenv", "pipenv --upgrade");
    }
    if on_path("python3") || on_path("python") {
        add("pip", "python3 -m pip install --upgrade pip");
    }
    if on_path("npm") {
        add("npm", "npm install -g npm@latest");
    }
    if on_path("pnpm") {
        add("pnpm", "pnpm add -g pnpm@latest");
    }
    if on_path("yarn") {
        add("yarn", "corepack up   # or: yarn set version latest");
    }
    if on_path("corepack") {
        add("corepack", "corepack up");
    }
    if on_path("gcloud") {
        add("gcloud", "gcloud components update");
    }
    if on_path("rustup") {
        add("rustup", "rustup update");
    }
    if on_path("go") {
        add(
            "go",
            "go install golang.org/dl/go1.27.3@latest && go1.27.3 download   # CVE-2026-111943 fix",
        );
    }
    out
}
