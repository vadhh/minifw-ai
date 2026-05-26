import sys
import os
from pathlib import Path

# Setup path like run_web.py
APP_DIR = Path(__file__).resolve().parent / "app"
sys.path.insert(0, str(APP_DIR))

try:
    import minifw_ai
    print("✅ import minifw_ai worked")
except ImportError:
    print("❌ import minifw_ai failed")

try:
    import app.minifw_ai
    print("✅ import app.minifw_ai worked")
except ImportError:
    print("❌ import app.minifw_ai failed")
