#!/bin/bash
# C22 (2.2.13) lab steps on minifw-monday-<edition>, run as root via systemd-run. Usage: c22_phase2.sh EDITION STEP...
# Steps: build (both editions, as user lab, fresh extraction) | upgrade | regression | ai [scenario,...]
set -uo pipefail
ED=$1; shift
W=/var/tmp/c22; OUT=$W/out; mkdir -p "$OUT"
[ "$(hostname)" = "minifw-monday-$ED" ] || { echo "wrong host"; exit 9; }
SECTOR=$([ "$ED" = education ] && echo education || echo finance)
MODE=$([ "$ED" = education ] && echo minifw_school || echo minifw_financial)
POLICY=/opt/minifw_ai/config/modes/$MODE/policy.json
SRC=$(readlink -f $W/src-current 2>/dev/null || true)
DEB=$SRC/build/minifw-ai_2.2.13-${SECTOR}_amd64.deb
for step in "$@"; do
  echo "=== $step $(date -Is)"
  case $step in
  build)
    (cd $W && echo "7184a0039d852bfff6069b402589b859b1ffcf0ee8300fff41f151048106963f  source.tar.gz" | sha256sum -c) || exit 3
    SRC=$W/src-$(date +%Y%m%dT%H%M%S); mkdir "$SRC"; tar -xzf $W/source.tar.gz -C "$SRC"; chown -R lab:lab "$SRC"
    ln -sfn "$SRC" $W/src-current
    for s in finance; do
      runuser -u lab -- env SOURCE_DATE_EPOCH=1793836800 bash "$SRC/scripts/build_deb.sh" $s 2.2.13 > "$OUT/build-$s.log" 2>&1 || { echo "BUILD_FAIL $s"; exit 4; }
    done
    (cd "$SRC/build" && sha256sum *.deb) | tee "$OUT/debs.sha256"
    dpkg-deb --version | head -1 > "$OUT/build-env.txt"; sed --version | head -1 >> "$OUT/build-env.txt"; uname -r >> "$OUT/build-env.txt"
    DEB=$SRC/build/minifw-ai_2.2.13-${SECTOR}_amd64.deb ;;
  upgrade)
    { dpkg-query -W minifw-ai; dpkg --verify minifw-ai; echo "verify_rc=$?"
      sha256sum "$POLICY"; echo "ai_enforcement_lines=$(grep -c '"ai_enforcement"' "$POLICY")"
      dpkg-query -W -f='${Conffiles}\n' minifw-ai | grep -E 'policy.json|txt'
      for u in minifw-ai minifw-ai-web dnsmasq; do echo "$u $(systemctl is-active $u)"; done; } > "$OUT/pre-upgrade.txt" 2>&1
    # confdef+confold: unmodified conffiles take the new version (same as plain dpkg -i); locally modified ones are kept
    # instead of an interactive prompt (plain dpkg -i would stop and ask). pre-upgrade.txt shows which case applied.
    DEBIAN_FRONTEND=noninteractive dpkg -i --force-confdef --force-confold "$DEB" < /dev/null > "$OUT/upgrade-dpkg.log" 2>&1
    echo "dpkg_rc=$?" >> "$OUT/upgrade-dpkg.log"
    sleep 8
    { dpkg-query -W minifw-ai; dpkg --verify minifw-ai; echo "verify_rc=$?"
      for u in minifw-ai minifw-ai-web dnsmasq; do echo "$u $(systemctl is-active $u)"; done
      sha256sum /opt/minifw_ai/models/client_window_v1.json; stat -c '%U:%G %a %n' /opt/minifw_ai/models/client_window_v1.json
      sha256sum "$POLICY"; ls -la "$(dirname "$POLICY")"
      echo "active_policy_ai_enforcement_lines=$(grep -c '"ai_enforcement"' "$POLICY")"
      for f in "$POLICY".dpkg-dist "$POLICY".dpkg-new; do [ -e "$f" ] && echo "$f ai_enforcement_lines=$(grep -c '"ai_enforcement"' "$f") $(sha256sum "$f")"; done
      echo "shipped_c20_policy_sha256=$(dpkg-deb --fsys-tarfile "$DEB" | tar -xO ".$POLICY" | sha256sum)"
      echo "env_file_MINIFW_AI_lines(count only)=$(grep -c '^MINIFW_AI_' /etc/minifw/minifw.env)"
      echo "env_commented_AI_ENFORCE_lines=$(grep -c '^#MINIFW_AI_ENFORCE_MODEL_SHA256=$' /etc/minifw/minifw.env) env_commented_AI_WINDOW_lines=$(grep -c '^#MINIFW_AI_WINDOW_MODEL=$' /etc/minifw/minifw.env)"
      stat -c '%U:%G %a %n' /etc/minifw/minifw.env
      python3 -c 'import json;d=json.load(open("/opt/minifw_ai/logs/runtime-health.json"));print("runtime_health_keys",sorted(d));print("protection_state",d.get("protection_state"));print("ai_window",d.get("ai_window"))'
      journalctl -u minifw-ai --since "-2min" --no-pager -o cat | grep -E 'WARNING' | tail -5
      grep -n EnvironmentFile /etc/systemd/system/minifw-ai.service; ls /etc/systemd/system/minifw-ai.service.d/ 2>&1
      journalctl -u minifw-ai --since "-2min" --no-pager -o cat | grep -E 'AI_WINDOW|STATE' | tail -5; } > "$OUT/post-upgrade.txt" 2>&1 ;;
  regression)
    (cd "$SRC" && runuser -u lab -- /opt/minifw_ai/venv/bin/python -m pytest -q -p no:cacheprovider testing/ -m 'not integration') > "$OUT/regression.txt" 2>&1
    echo "pytest_rc=$?" >> "$OUT/regression.txt"; tail -3 "$OUT/regression.txt" ;;
  ai)
    cp -f $W/scripts/heldout_client.py $W/scripts/lab_c20_ai.py "$OUT/" 2>/dev/null
    /opt/minifw_ai/venv/bin/python $W/scripts/lab_c20_ai.py "$ED" "$DEB" "$SRC" ${AI_ONLY:-} > "$OUT/ai-driver-$(date +%H%M%S).log" 2>&1
    echo "ai_rc=$?" ;;
  esac
done
echo "=== done $(date -Is)"
