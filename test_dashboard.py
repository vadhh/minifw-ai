import os
import sys
from pathlib import Path

# Setup path
APP_DIR = Path(__file__).resolve().parent / "app"
sys.path.insert(0, str(APP_DIR))
os.environ["PYTHONPATH"] = str(APP_DIR)
os.environ["DEV_MODE"] = "1"

from app.controllers.admin.dashboard_controller import dashboard_controller

class MockRequest:
    def __init__(self):
        self.scope = {"type": "http"}
        self.headers = {}

try:
    print("Testing dashboard_controller...")
    # We need a proper starlette Request object or something that TemplateResponse can use.
    from fastapi import Request
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
    request = Request(scope=scope)
    
    # We might need to mock templates too or just see if the logic before TemplateResponse fails.
    res = dashboard_controller(request)
    print("✅ dashboard_controller executed successfully")
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
