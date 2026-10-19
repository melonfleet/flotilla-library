# Captured platform sources (test_report.py `PlatformSources`)

Every file here is a response saved as it came, on **19 October 2026**, from the URL given. None is
written by hand. To refresh one, fetch it again the same way and update the tests that pin its
contents.

| File | URL | How |
| --- | --- | --- |
| `gdmf-pmv.json` | https://gdmf.apple.com/v2/pmv | `curl --cacert tools/apple-root-ca.pem` |
| `apple-security-releases-100100.html` | https://support.apple.com/en-us/100100 | `curl` |
| `apple-note-149228.html` | https://support.apple.com/en-us/149228 (macOS Tahoe 26.7.1: one CVE, exploited) | `curl` |
| `apple-note-125886.html` | https://support.apple.com/en-us/125886 (macOS Tahoe 26.2: two exploited, each naming the other "also issued") | `curl` |
| `apple-note-148281.html` | https://support.apple.com/en-us/148281 (macOS Tahoe 26.6.2: 34 CVEs, none exploited) | `curl` |
| `container-1.5.0-ContainerSystemConfig.swift` | https://raw.githubusercontent.com/apple/container/1.5.0/Sources/ContainerPersistence/ContainerSystemConfig.swift | `curl` |
| `container-1.2.2-ContainerSystemConfig.swift` | https://raw.githubusercontent.com/apple/container/1.2.2/Sources/ContainerPersistence/ContainerSystemConfig.swift | `curl` |
| `container-ls-remote-tags.txt` | https://github.com/apple/container.git | `git ls-remote --tags --refs` |
| `osv-linux-sample.zip` | https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip | see below |

The latest release (`1.5.0`) was read the way the workflow reads it, from where
https://github.com/apple/container/releases/latest redirects: `…/releases/tag/1.5.0`.

## osv-linux-sample.zip

The whole export is 58 MB (33,014 records), too big to keep here. This zip holds **20 of its
records, byte for byte**, re-zipped with a fixed date. They were picked to cover each case for the
recommended kernel 6.18.35 and the older 6.18.15:

- fixed by 6.18.35, affecting 6.18.15, critical (9.0+): CVE-2026-23240, CVE-2026-23455, CVE-2026-31402;
- the same, high (7.0–8.9): CVE-2026-23239, CVE-2026-23245, CVE-2026-23246, CVE-2026-23248;
- the same, medium (not counted): CVE-2026-31617, CVE-2026-53059;
- the same, with no CVSS vector (counted as unscored): CVE-2026-23241, CVE-2026-23244;
- high or critical but 6.18.35 still has it (not counted): CVE-2026-100075, CVE-2026-23270;
- high or critical but 6.18.15 never had it (not counted): CVE-2026-22980, CVE-2026-22984;
- unusual version shapes: CVE-2026-98353 (`7.3-rc1.0`), CVE-2026-89623 (fixed `7.3-rc1`),
  CVE-2023-54069 (introduced `0`), CVE-2026-23352 (`2.6.39.2`);
- CVE-2025-38079, whose ranges were checked against the kernel CNA's own record
  (https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2025/CVE-2025-38079.json):
  the same "unaffected from" versions, and the CNA's CVSS 3.1 vector, base score 7.8.

## tools/apple-root-ca.pem

Apple Root CA, from https://www.apple.com/appleca/AppleIncRootCertificate.cer (DER, converted to
PEM). SHA-256 of the DER: `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024`, the
same certificate gdmf.apple.com's chain ends in (`Apple Server Authentication CA` under it). The
scan job checks that hash before trusting the file, and trusts it **only** for gdmf.apple.com.
