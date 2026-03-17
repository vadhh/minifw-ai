# MiniFW-AI Release Verification

## Package Integrity

Every release ships with one `.deb` per sector. From 2.2.0 the sector is part of
the version string (`X.Y.Z-<sector>`), making parallel builds unambiguous:

- `minifw-ai_X.Y.Z-<sector>_amd64.deb` — the installable package
- `minifw-ai_X.Y.Z-<sector>_amd64.deb.sha256` — SHA-256 checksum
- `minifw-ai_X.Y.Z-<sector>_amd64.deb.asc` — detached GPG signature (ASCII-armored)
- `minifw-ai-release.asc` — signing key public key

---

## Signing Key

```
Key ID  : BDB471E1FB46F58A
Fingerprint: 3413 D033 1456 05FD F7C8  C7FA BDB4 71E1 FB46 F58A
UID     : MiniFW-AI Release (MiniFW-AI 2.0.0 Release Signing Key) <release@minifw.local>
Created : 2026-03-16
Expires : 2028-03-15
Algorithm: RSA 4096-bit
```

---

## Verification Steps

### 1. Import the signing key

```bash
gpg --import minifw-ai-release.asc
```

Expected output:
```
gpg: key BDB471E1FB46F58A: public key "MiniFW-AI Release ..." imported
```

### 2. Verify the SHA-256 checksum

```bash
sha256sum -c minifw-ai_2.2.0-establishment_amd64.deb.sha256
# or
sha256sum -c minifw-ai_2.2.0-hospital_amd64.deb.sha256
```

Expected: `minifw-ai_2.2.0-<sector>_amd64.deb: OK`

### 3. Verify the GPG signature

```bash
gpg --verify minifw-ai_2.2.0-establishment_amd64.deb.asc minifw-ai_2.2.0-establishment_amd64.deb
# or
gpg --verify minifw-ai_2.2.0-hospital_amd64.deb.asc minifw-ai_2.2.0-hospital_amd64.deb
```

Expected output:
```
gpg: Signature made ...
gpg:                using RSA key 3413D033145605FDF7C8C7FABDB471E1FB46F58A
gpg: Good signature from "MiniFW-AI Release ... <release@minifw.local>"
```

A `Good signature` result confirms the package has not been tampered with since signing.

> **Note:** You may see `WARNING: This key is not certified with a trusted signature!`
> if you have not explicitly trusted the key. This is expected for a self-managed
> signing key. Verify the fingerprint out-of-band with the release publisher.

---

## Release 2.2.0 Checksums (2026-03-17)

```
9434eb27a89333f2d5b0aaa6f8f1ac98a55694b7a52af97dbf24041531964c2d  minifw-ai_2.2.0-establishment_amd64.deb
2f9bd834a0ffe5d4cb213043c7c9371fa506a24778f8585b789692a489b89823  minifw-ai_2.2.0-hospital_amd64.deb
```

---

## Release 2.0.0 Checksums

```
6fd629ac4b5601d438d9b151f53b9ff9c1f237ab64c1fdcf8809e8fd6221604c  minifw-ai_2.0.0_amd64.deb
```
