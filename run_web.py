import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure 'app/' is on the path so bare imports like `from minifw_ai.audit import …`
# resolve correctly both in this process and in uvicorn's reload subprocess.
APP_DIR = Path(__file__).resolve().parent / "app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
os.environ.setdefault("PYTHONPATH", str(APP_DIR))

# Load .env if present, otherwise fall back to a sector-specific file.
def _load_env():
    env = Path(".env")
    if env.exists():
        load_dotenv(env)
        return

    # Pick a sector file based on PRODUCT_MODE, defaulting to establishment.
    mode = os.environ.get("PRODUCT_MODE", "minifw_establishment")
    fallback = Path(f".env.{mode}")
    if fallback.exists():
        load_dotenv(fallback)
        return

    # Last resort: any .env.minifw_* file present.
    for candidate in sorted(Path(".").glob(".env.minifw_*")):
        load_dotenv(candidate)
        return

_load_env()

# In DEV_MODE, allow a dummy secret so the server starts without a real .env.
if os.environ.get("DEV_MODE") == "1":
    os.environ.setdefault("MINIFW_SECRET_KEY", "dev-secret-not-for-production")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.web.app:app", host="0.0.0.0", port=8443, reload=True)
