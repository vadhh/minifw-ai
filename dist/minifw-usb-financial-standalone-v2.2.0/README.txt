MiniFW-AI Financial Sector Executive Demo v2.2.0
================================================

QUICK START
-----------
1. bash setup_tls.sh     (one-time, requires sudo)
2. bash run_demo.sh      (starts demo + opens browser)
3. Login: admin / Finance1!  at  https://localhost:8443

WHAT HAPPENS
------------
- Normal trading floor traffic for ~60 seconds (Bloomberg, Reuters, SWIFT)
- At T+75s: banking trojan C2 + card exfiltration detected from 10.50.0.1
- BLOCK event fires on trading segment -- dashboard alert, audit log written

AFTER THE MEETING
-----------------
bash teardown_demo.sh    (removes demo CA from trust stores)

FULL GUIDE: see INSTALL.md
