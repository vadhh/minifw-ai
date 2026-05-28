# Recovery Guide — MiniFW-AI Financial Demo

## Automatic Recovery

```bash
bash recover_demo.sh
```

Kills stale processes, resets a corrupt database, clears stale logs, and relaunches.

---

## Manual Steps

### Dashboard not loading
```bash
lsof -ti:8443 | xargs kill -9 2>/dev/null || true
bash run_demo.sh
```

### BLOCK not firing after 2 minutes
```bash
# Check scheduler is running
pgrep -f demo_scheduler.py
# Check scheduler log
cat logs/scheduler.log
# Check events log
wc -l logs/events.jsonl
```

### Cert warning in browser
```bash
bash teardown_demo.sh
bash setup_tls.sh
# Close and reopen browser fully
```

### Database error on login
```bash
rm -f minifw.db
bash run_demo.sh
```

### Engine crash
```bash
grep -i "error\|critical" logs/engine.log | tail -20
```
