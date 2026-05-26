import os
import sys
from pathlib import Path

# Setup path
APP_DIR = Path(__file__).resolve().parent / "app"
sys.path.insert(0, str(APP_DIR))
os.environ["PYTHONPATH"] = str(APP_DIR)
os.environ["DEV_MODE"] = "1"

try:
    from app.services.events.get_events_service import get_collector_status
    print("Testing get_collector_status()...")
    cs = get_collector_status()
    print(f"✅ get_collector_status: {cs}")

    from app.controllers.admin.dashboard_controller import get_service_status
    print("Testing get_service_status()...")
    ss = get_service_status()
    print(f"✅ get_service_status: {ss}")

    from app.services.events.get_events_service import get_recent_events
    print("Testing get_recent_events()...")
    re = get_recent_events()
    print(f"✅ get_recent_events: {len(re)} events")

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
