#!/usr/bin/env bash
# In-place upgrade C13 (root dashboard) -> C15 (minifw-web) on the Education lab VM only.
set -euo pipefail
[[ "$(hostname)" == minifw-monday-education ]] || exit 1
C14_DEB=/home/lab/v2210-c15-candidate/minifw-ai-education-v2.2.10-source-assessment/build/minifw-ai_2.2.10-education_amd64.deb
redact() { python3 -c 'import re,sys
for l in sys.stdin: print("[credential line redacted]" if re.search(r"password|secret|token",l,re.I) else l,end="")'; }

echo "== 1. clean C13 install (root-run dashboard layout)"
rm -rf /var/tmp/minifw-lab-cached-venv
bash /var/tmp/minifw-install-c13-candidate.sh education > /var/tmp/minifw-c15-upgrade-c13-install.log 2>&1
dpkg-query -W minifw-ai; id minifw-web 2>&1 || true
stat -c '%U:%G %a %n' /opt/minifw_ai/minifw.db /opt/minifw_ai/logs

echo "== 2. seed old-layout state"
python3 - <<'PY'
import sqlite3
with sqlite3.connect("/opt/minifw_ai/minifw.db") as c:
    c.execute("CREATE TABLE upgrade_marker (v TEXT)"); c.execute("INSERT INTO upgrade_marker VALUES ('kept-from-c13')")
PY
printf '{"placeholder":"upgrade migration test, not a license"}\n' > /etc/minifw/license.json
chmod 600 /etc/minifw/license.json
admin_hash_before=$(python3 -c 'import sqlite3;print(sqlite3.connect("/opt/minifw_ai/minifw.db").execute("select hashed_password from users where username=\"admin\"").fetchone()[0][:12])')

echo "== 3. dpkg -i C15 over C13, no purge"
set +e
MINIFW_SECTOR=education PRODUCT_MODE=minifw_school dpkg -i "$C14_DEB" 2>&1 | redact > /var/tmp/minifw-c15-upgrade-dpkg.log
echo "DPKG_UPGRADE_EXIT=${PIPESTATUS[0]}"
set -e
sleep 3

echo "== 4. verify migration and ownership"
dpkg-query -W minifw-ai
test ! -e /opt/minifw_ai/minifw.db && echo "OLD_DB_REMOVED"
python3 - <<'PY'
import sqlite3
c = sqlite3.connect("/var/lib/minifw-ai/minifw.db")
print("MIGRATED_ROW", c.execute("SELECT v FROM upgrade_marker").fetchall())
print("INTEGRITY", c.execute("PRAGMA integrity_check").fetchone()[0])
PY
admin_hash_after=$(python3 -c 'import sqlite3;print(sqlite3.connect("/var/lib/minifw-ai/minifw.db").execute("select hashed_password from users where username=\"admin\"").fetchone()[0][:12])')
[[ "$admin_hash_before" == "$admin_hash_after" ]] && echo "ADMIN_ACCOUNT_PRESERVED"
test ! -e /etc/minifw/license.json && test -f /var/lib/minifw-ai/license.json && echo "LICENSE_MOVED"
stat -c '%U:%G %a %n' /var/lib/minifw-ai /var/lib/minifw-ai/minifw.db /var/lib/minifw-ai/license.json \
  /opt/minifw_ai /opt/minifw_ai/logs /opt/minifw_ai/logs/audit.jsonl /etc/minifw/minifw.env /etc/minifw/tls/server.key \
  /opt/minifw_ai/config/feeds/deny_domains.txt /opt/minifw_ai/config/modes/minifw_school /opt/minifw_ai/config/modes/minifw_school/policy.json
systemctl is-active minifw-ai minifw-ai-web || true
pid=$(systemctl show minifw-ai-web -p MainPID --value)
grep -E '^(Uid|Gid|CapBnd|CapEff|NoNewPrivs):' /proc/$pid/status
dpkg --verify minifw-ai; echo "DPKG_VERIFY_EXIT=$?"
systemctl stop minifw-ai minifw-ai-web dnsmasq
echo UPGRADE_CHECK_DONE
