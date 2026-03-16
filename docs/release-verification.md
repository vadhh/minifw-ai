# MiniFW-AI Release Verification

## Package Integrity

Every release ships with:
- `minifw-ai_X.Y.Z_amd64.deb` — the installable package
- `minifw-ai_X.Y.Z_amd64.deb.sha256` — SHA-256 checksum
- `minifw-ai_X.Y.Z_amd64.deb.asc` — detached GPG signature (ASCII-armored)
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
sha256sum -c minifw-ai_2.0.0_amd64.deb.sha256
```

Expected: `minifw-ai_2.0.0_amd64.deb: OK`

### 3. Verify the GPG signature

```bash
gpg --verify minifw-ai_2.0.0_amd64.deb.asc minifw-ai_2.0.0_amd64.deb
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

## Release 2.0.0 Checksums

```
SHA256: 4c6094228feabdcf6b297ad3f29303eaaebab854755691ceab6408e44f5a548e  minifw-ai_2.0.0_amd64.deb
```
