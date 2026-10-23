# i-can-count-to-four

> [“I can count to four!”](https://www.youtube.com/watch?v=u8ccGjar4Es) — because
> at least one of the leaked eMudhra private keys turned out to be the integer
> `4`. The name is the joke; the tool is serious.

A small, fast Rust tool that walks a whole filesystem and tells you **what to
upgrade** because of the **compromised eMudhra intermediate CA certificates** —
the ones behind **CVE-2026-111943** (Red Hat tracking: **CVE-2026-114406** /
**RHSB-2026-012**).

It answers one question: *which programs on this machine still trust that CA, and
how do I fix them?*

```
① CONTAINS THE COMPROMISED CERTIFICATE — act on these
   CLEAR   Browser cache • cached downloads (Firefox/Chrome)      6 file(s)

② UPGRADE PLAN — 485 files across 126 items
   Python project (poetry) • 60 files, 17 unit(s)
        • ~/dev/jonator/api (9)
            cd "$HOME/dev/jonator/api" && poetry update
   Toolchain (managers & version managers) • 10 tool(s)
        • uv
            uv self update
```

## Background

In April 2025 an eMudhra key-generation ceremony produced a second, weak set of
P-384 keys during a wrap/unwrap step. Eight intermediate CA certificates were
issued with those keys. The private keys turned out to be single- and
double-digit integers, so anyone can recover them from the public certificates
and mint fraudulent certificates for any domain.

The eight certificates are shipped in the crate (see [`certs/`](certs/README.md)),
verified byte-for-byte against the published SHA-256 fingerprints. Embedding the
real bytes is what makes matching exact instead of guesswork.

For a deeper write-up, see the [Cisco Talos advisory](https://blog.talosintelligence.com/compromised-intermediate-certificates/),
Mozilla's [Firefox](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
and [Chrome](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
posts, and the [Red Hat bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012).

## How it looks for traces

Detection is layered, cheap first:

1. **Fast prefilter** — each file that is read is streamed through two
   Aho-Corasick automata in a single linear pass, with a needle-sized overlap
   across chunk boundaries (large opaque files are only read at head/tail — see
   [Design notes](#design-notes)):
   - the eight **raw DER certificates** (finds `.der` files, blobs inside NSS /
     JKS / PKCS#12 keystores, memory dumps, ...);
   - **textual traces**: SHA-256 fingerprints (compact and colon-separated),
     serial numbers, the subject CNs, the issuer roots (`emSign Root … CA - G3`),
     the vendor name, and the PEM header.
2. **Deep analysis** (only for files that matched, so it stays cheap):
   - exact **DER bytes** anywhere in the file, by byte offset;
   - **PEM / base64** certificate blocks are decoded, and each certificate is
     hashed (whole-cert SHA-256 *and* SPKI SHA-256) and parsed;
   - any **bare DER certificate** is parsed so a re-signed variant whose public
     key still matches is caught by its SPKI hash;
   - everything else is reported as a lower-confidence *reference*.

Every match is classified and ranked:

| Rank | Findings | Meaning |
|------|----------|---------|
| HIGH | `exact-cert-bytes`, `exact-cert-pem`, `subject-public-key` | The certificate (or its key) is provably present. |
| low  | `cert-sha256-fingerprint`, `spki-sha256-fingerprint`, `serial-number` | The value is referenced as text (configs, CRLs, logs, allowlists). |
| low  | `subject-cn`, `issuer-cn`, `vendor-name` | A weaker mention worth a look. |

## Design notes

- **No name allow-lists.** It does not skip `/usr`, `node_modules`, `.git`, or
  any tool directory. The *only* thing it refuses to descend into is the
  kernel's **pseudo filesystems**, discovered from `/proc/self/mounts`
  (`proc`, `sysfs`, `devtmpfs`, `cgroup2`, ...). So `/dev` and `/sys` are
  skipped, but `/tmp`, `/run`, `/dev/shm`, overlayfs and network mounts are all
  scanned.
- **Content sniffing, not name sniffing.** The bulk of a disk is a handful of
  enormous files that cannot hold a certificate (model weights, disk images,
  media). Each file's head is classified by *content*:
  - **certificate containers** — ASN.1/DER, PEM, PKCS#12, JKS, SQLite/Berkeley
    DB — are read in full;
  - **text** (configs, logs, scripts, CRLs) is read in full up to a cap;
  - small files are always read in full;
  - anything else that is large is read only at the **head and tail** and
    counted as *partially read*, so coverage is never silently overstated.

  `--thorough` disables the shortcut and reads every file completely. On a
  machine with an 82 GiB model-blob directory this turns a ~160 s pass into
  ~0.02 s while still inspecting every file's head and tail.
- **Symlinks are not followed** (avoids loops and double-reporting) and only
  regular files are read.
- **Streaming, not slurping.** Files are read in 8 MiB chunks with a bounded
  per-thread buffer, so memory stays flat regardless of file size.
- **Parallel** across files, with `--threads` workers (default: CPU count).

## Build

```sh
cargo build --release
# binary at target/release/i-can-count-to-four
```

## Usage

```sh
# Scan the whole disk from / (default)
sudo ./target/release/i-can-count-to-four

# Scan specific roots, human-readable output
./target/release/i-can-count-to-four /etc /home /opt

# Machine-readable JSON
./target/release/i-can-count-to-four / --json > findings.json

# Stay on one filesystem, limit depth, pick thread count
./target/release/i-can-count-to-four / --one-file-system --max-depth 4 --threads 8

# CI: exit non-zero (status 2) if the certificate is actually present
./target/release/i-can-count-to-four / --quiet --fail-on-found

# Show what is being hunted
./target/release/i-can-count-to-four --list-targets
```

Running as root avoids `permission denied` noise; without root the tool simply
counts unreadable files and keeps going.

### Options

| Flag | Description |
|------|-------------|
| `ROOT...` | One or more roots to scan (default `/`). |
| `--json` | Emit JSON (summary + findings) instead of text. |
| `--one-file-system` | Do not cross mount points. |
| `--follow-links` | Follow symlinks (off by default). |
| `--max-depth N` | Limit directory depth. |
| `--max-file-size BYTES` | Skip files larger than N bytes (default: no limit). |
| `--thorough` | Read every file in full (disables content sniffing). |
| `--threads N` | Worker threads (default: CPU count). |
| `-q`, `--quiet` | Suppress the progress line. |
| `--fail-on-found` | Exit `2` if any high-confidence finding exists. |
| `--list-targets` | Print the embedded target certificates and exit. |
| `--no-color` | Disable ANSI colors in the report (auto-off when not a TTY). |
| `--from-json FILE` | Re-render the grouped report from a saved `--json` file (no scan). |
| `--html FILE` | Also write a self-contained colored HTML report. |

Exit codes: `0` success, `2` high-confidence finding present (with
`--fail-on-found`), `3` could not read the `--from-json` file.

## The report

The default output is a **remediation plan**, not a file dump. Findings are
collapsed into the things you actually act on, with the right command for each:

```
① CONTAINS THE COMPROMISED CERTIFICATE — act on these
   CLEAR   Browser cache • cached downloads (Firefox/Chrome)      6 file(s)
   REMOVE  Temporary files • /tmp                                29 file(s)

② UPGRADE PLAN — 485 files across 126 items
   Python project (poetry) • 60 files, 17 unit(s)
        • ~/dev/jonator/api (9)
            cd "$HOME/dev/jonator/api" && poetry update
        • ~/dev/activeseed/api (6)
            cd "$HOME/dev/activeseed/api" && poetry update
   Python project (uv) • 36 files, 27 unit(s)
        • ~/dev/livesrt (2)
            cd "$HOME/dev/livesrt" && uv lock --upgrade && uv sync
   Toolchain (managers & version managers) • 10 tool(s)
        • uv
            uv self update
        • nvm (Node versions)
            nvm install --lts --reinstall-packages-from=current && nvm alias default 'lts/*'

③ CLEAR / REMOVE — no software to upgrade
   REMOVE  virtualenv wheel cache • 9 files — ~/.cache/virtualenv
```

For a Python virtualenv or a `node_modules` tree the fix is to re-resolve the
**owning project**, so the tool resolves the venv back to its project (via
`pyvenv.cfg` and editable `.pth` / `direct_url.json`) and detects the package
manager from the project's lockfiles — **uv, Poetry, PDM, pipenv, pip** for
Python and **npm, pnpm, yarn, bun** for Node — then prints that manager's
re-lock command. It also lists the **toolchains and version managers** present
(nvm, fnm, volta, asdf, mise, pyenv, conda, uv, poetry, pip, npm, pnpm, yarn,
corepack, gcloud, rustup, go), because those carry CA data too.

A file "contains" a compromised certificate only when the exact bytes of one of
the 8 TLS/code-signing intermediates (or that key's SPKI hash) are present.
Everything else merely mentions `eMudhra` (usually the eMudhra **root** inside a
CA bundle, or plain text) and is ignored by the plan — the count is still shown
so nothing is hidden. Full per-file detail is always in `--json`.

Re-render a saved scan without re-scanning:

```sh
i-can-count-to-four / --json > scan.json
i-can-count-to-four --from-json scan.json
i-can-count-to-four --from-json scan.json --html report.html   # colored, shareable
```

### Typical places it finds things

- `/etc/ssl/certs/`, `/etc/pki/`, and the combined `ca-certificates.crt` /
  `ca-bundle.crt` / `tls-ca-bundle.pem` bundles;
- NSS databases (`~/.pki/nssdb/cert9.db`, Firefox/Chromium profiles) — matched
  as raw DER blobs;
- Java trust stores (`/etc/ssl/certs/java/cacerts`, `$JAVA_HOME/lib/security/cacerts`);
- server keystores (`.p12`, `.pfx`, `.jks`), CI caches, container layers,
  backups, and log/CRL/allowlist files that reference a fingerprint or serial.

## Limitations

- Large **opaque** files (model weights, disk images, media, big binaries) are
  only inspected at the head and tail by default, so a certificate buried in
  the middle of one is not found unless you pass `--thorough`. The summary always
  reports how many files were only partially read.
- Data inside **compressed archives** (`.gz`, `.xz`, `.zip`, `.zst`, container
  image layers) is not decompressed, so certificates hidden inside them are not
  found. Extract first, or point the tool at a mounted/expanded tree.
- Text encoded in **UTF-16** (some Windows-origin files) is not matched; the
  needles are plain ASCII/UTF-8.
- The prefilter is substring-based, so a *reference* finding is a pointer for a
  human to review, not proof — only the HIGH-confidence findings are proof.

## Tests

```sh
cargo test
```

Unit tests cover the certificate metadata, the matcher and the content sniffer,
and integration tests build a tree with real traces (raw DER, PEM bundle,
embedded keystore blob, text reference) plus decoys, and assert the tool finds
exactly the real ones — including a certificate straddling the streaming buffer
boundary, and the head/tail-only behavior of the content sniffing (with
`--thorough` finding the same file).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
