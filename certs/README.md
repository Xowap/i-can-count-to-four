# Embedded certificates

These are the eight compromised eMudhra intermediate CA certificates tracked by
**CVE-2026-111943** (and downstream advisories such as Red Hat
[RHSB-2026-012](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)).

They were fetched from the certificate-transparency log
([crt.sh](https://crt.sh)) and each one was verified byte-for-byte against the
SHA-256 fingerprint published in [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
and the [Cisco Talos advisory](https://blog.talosintelligence.com/compromised-intermediate-certificates/).

| File | Subject CN | Issuer | Serial | cert SHA-256 |
|------|-----------|--------|--------|--------------|
| `ev_tls_g3b.der` | EM EV TLS CA - G3B | emSign Root TLS CA - G3 | C7C41EFE92D825F05EAE841A4A82C1 | `e7568fe6…4333838` |
| `ov_tls_g3b.der` | EM OV TLS CA - G3B | emSign Root TLS CA - G3 | 6CADA367FB1C100088120EA202D568 | `98b89662…c25b` |
| `dv_tls_g3b.der` | EM DV TLS CA - G3B | emSign Root TLS CA - G3 | A4AEE678F23362B4C0E460B772F214 | `42c4accd…1493` |
| `ev_tls_g3c.der` | EM EV TLS CA - G3C | emSign Root TLS CA - G3 | 8009928A64107601AF05FA2F19F109 | `432ec25f…61f3` |
| `ov_tls_g3c.der` | EM OV TLS CA - G3C | emSign Root TLS CA - G3 | 296926C227A3A1526392B19482A504 | `cb6e1516…7c3f` |
| `dv_tls_g3c.der` | EM DV TLS CA - G3C | emSign Root TLS CA - G3 | 588B2E3C2BB8CDA13E1A1209254321 | `0164d7ce…4d19` |
| `ov_cs_g3b.der` | EM OV CS CA - G3B | emSign Root CS CA - G3 | 7818933F8F85B4619A2B35FBA83D0A | `9e39de28…67b4` |
| `ov_cs_g3c.der` | EM OV CS CA - G3C | emSign Root CS CA - G3 | 544B7F922C31AE220A4A922916F6E6 | `4b2460a4…30b1` |

The tool additionally derives the SHA-256 of each certificate's
SubjectPublicKeyInfo (SPKI). That is the value the Go standard library's fix
(Go 1.27.3 / 1.26.10) filters on, and it identifies the compromised *key* even
if the certificate is re-encoded or re-signed.

To regenerate them:

```sh
# Verify a local copy against the published fingerprint
openssl x509 -inform DER -in certs/ev_tls_g3b.der -noout -fingerprint -sha256
```
