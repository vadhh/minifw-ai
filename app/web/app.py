import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
from fastapi.exception_handlers import http_exception_handler

from app.web.routers import health, status, admin, auth
from fastapi.staticfiles import StaticFiles
from app.database import init_db
from app.middleware.auth_middleware import require_auth


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    if os.environ.get("DEMO_MODE") == "attack_simulation":
        from app.services.demo import attack_simulator
        attack_simulator.start(os.environ.get("MINIFW_LOG", "logs/events.jsonl"))
    yield
    if os.environ.get("DEMO_MODE") == "attack_simulation":
        from app.services.demo import attack_simulator
        attack_simulator.stop()


app = FastAPI(title="RITAPI Sentinel MiniFW AI", version="1.0.0", lifespan=_lifespan)


# Custom exception handler untuk redirect ke login jika 401
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    # Jika 401 dan request dari browser (bukan API)
    if exc.status_code == 401:
        accept_header = request.headers.get("accept", "")
        # Check if request expects HTML
        if "text/html" in accept_header or not accept_header:
            return RedirectResponse(url="/auth/login", status_code=303)

    # Force password change redirect
    if exc.status_code == 303 and exc.detail == "Password change required":
        return RedirectResponse(url="/auth/change-password", status_code=303)

    # Untuk request lainnya, return normal error
    return await http_exception_handler(request, exc)


# static adminlte
app.mount("/static", StaticFiles(directory="app/web/static"), name="static")


# register routers
app.include_router(auth.router)  # Auth router - TIDAK DI-PROTECT
app.include_router(
    admin.router, dependencies=[Depends(require_auth)]
)  # Admin protected
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(status.router, prefix="/status", tags=["Status"])


@app.get("/")
def root():
    return RedirectResponse(url="/admin/", status_code=303)
