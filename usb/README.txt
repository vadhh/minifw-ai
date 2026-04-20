MiniFW-AI — Establishment Sector Demo
======================================

Requirements
------------
  - Windows 10/11 with WSL2 + Docker Desktop, OR native Linux with Docker
  - Docker Compose v2  (docker compose version  — should print v2.x)
  - Port 8444 free on localhost

Run the Demo
------------
  bash demo.sh

  First run on a new machine: loads Docker images from USB (~2-3 min, one-time).
  Subsequent runs: starts immediately.

  Dashboard → https://localhost:8444
  Login     → admin / SME_Demo1!

  Accept the self-signed certificate warning in your browser.
  Wait ~33 seconds for the first injector loop to populate events.

Stop
----
  Ctrl+C in the terminal. The demo script will print the cleanup command.
  To force-stop manually (run from the USB root directory):

  docker compose -f docker/docker-compose.usb-sme.yml down

Troubleshooting
---------------
  Port 8444 in use?
    (from the USB root directory)
    docker compose -f docker/docker-compose.usb-sme.yml down
    then re-run demo.sh

  Docker not found?
    Windows: open Docker Desktop and ensure WSL integration is enabled.
    Linux:   sudo systemctl start docker

Full demo script: ask your MiniFW-AI contact for DEMO_MASTER_SCRIPT.md
