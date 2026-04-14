# MiniFW-AI — Rollback Procedure

## Rolling Back to a Previous Version

### 1. Stop current services

```bash
sudo systemctl stop minifw-ai minifw-ai-web
```

### 2. Back up current state

```bash
sudo cp -a /opt/minifw_ai/config /tmp/minifw-backup-config-$(date +%Y%m%d)
sudo cp /opt/minifw_ai/minifw.db /tmp/minifw-backup-$(date +%Y%m%d).db
sudo cp /opt/minifw_ai/logs/audit.jsonl /tmp/minifw-backup-audit-$(date +%Y%m%d).jsonl
```

### 3. Install the previous .deb

```bash
sudo dpkg -i minifw-ai_<previous-version>_amd64.deb
```

dpkg will overwrite application code but preserve conffiles (policy.json, feed files).

### 4. Restore config if needed

If the previous version used a different config schema:

```bash
sudo cp /tmp/minifw-backup-config-<date>/policy.json /opt/minifw_ai/config/policy.json
```

### 5. Verify rollback

```bash
systemctl status minifw-ai
journalctl -u minifw-ai -n 20
sudo nft list table inet minifw
```

---

## Emergency: Full Removal

```bash
sudo systemctl stop minifw-ai minifw-ai-web
sudo dpkg -r minifw-ai        # remove (keeps /etc/minifw and feeds)
sudo dpkg -P minifw-ai        # purge (removes venv, logs, db, /etc/minifw)
sudo nft delete table inet minifw 2>/dev/null || true
```

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| 2.0.0 | 2026-03-16 | Security hardening, CVE fixes, GPG signed — current |
| 1.0.0 | 2026-03-11 | Initial release — do not use in production (GAMBLING_ONLY guard present) |
