import json
import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from minifw_ai.runtime_health import assess

router = APIRouter()


@router.get("/")
def health_check():
    path = Path(os.environ.get("MINIFW_HEALTH_FILE", "/opt/minifw_ai/logs/runtime-health.json"))
    try:
        result = assess(json.loads(path.read_text()))
    except (OSError, ValueError):
        result = {"status": "not_ready", "reason": "engine evidence unavailable"}
    return JSONResponse(result, status_code=200 if result["status"] == "ready" else 503)
