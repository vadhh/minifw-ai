from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from collections import OrderedDict
import time

from app.database import get_db
from app.schemas.auth import LoginRequest, Verify2FARequest
from app.services.auth.user_service import (
    authenticate_user,
    get_user_by_username,
    update_last_login,
)
from app.services.auth.token_service import create_access_token
from app.services.auth.totp_service import verify_totp
from minifw_ai.audit import (
    audit_login_success, audit_login_failed,
    audit_2fa_success, audit_2fa_failed,
    audit_logout, audit_password_change,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
templates = Jinja2Templates(directory="app/web/templates")

# --- Login Rate Limiter (IP-based) ---
MAX_LOGIN_ATTEMPTS_PER_IP = 10  # per window
LOGIN_WINDOW_SECONDS = 300  # 5 minutes
MAX_FAILED_BEFORE_LOCKOUT = 5  # per user account
LOCKOUT_DURATION_MINUTES = 15

# IP -> deque of timestamps
_login_attempts: OrderedDict[str, list] = OrderedDict()
_MAX_IPS_TRACKED = 5000


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _check_ip_rate_limit(ip: str) -> bool:
    """Returns True if IP is rate-limited (too many attempts)."""
    now = time.time()
    if ip not in _login_attempts:
        if len(_login_attempts) >= _MAX_IPS_TRACKED:
            _login_attempts.popitem(last=False)
        _login_attempts[ip] = []
    else:
        _login_attempts.move_to_end(ip)

    attempts = _login_attempts[ip]
    # Prune old attempts
    _login_attempts[ip] = [t for t in attempts if (now - t) < LOGIN_WINDOW_SECONDS]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS_PER_IP


def _record_login_attempt(ip: str) -> None:
    """Record a login attempt for rate limiting."""
    now = time.time()
    if ip not in _login_attempts:
        if len(_login_attempts) >= _MAX_IPS_TRACKED:
            _login_attempts.popitem(last=False)
        _login_attempts[ip] = []
    _login_attempts[ip].append(now)


def _check_account_lockout(user) -> bool:
    """Returns True if user account is locked."""
    if not user.is_locked:
        return False
    if user.locked_until and datetime.utcnow() > user.locked_until:
        return False  # Lockout expired
    return True


def _handle_failed_login(db: Session, user) -> None:
    """Increment failed attempts and lock account if threshold reached."""
    if user is None:
        return
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= MAX_FAILED_BEFORE_LOCKOUT:
        user.is_locked = True
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    db.commit()


def _reset_failed_attempts(db: Session, user) -> None:
    """Reset on successful login."""
    user.failed_login_attempts = 0
    user.is_locked = False
    user.locked_until = None
    db.commit()


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Show login page"""
    return templates.TemplateResponse(request, "auth/login.html")


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Handle login with rate limiting and account lockout."""
    ip = _client_ip(request)

    # IP-based rate limiting
    if _check_ip_rate_limit(ip):
        audit_login_failed(username, ip)
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": "Too many login attempts. Try again later."},
        )

    _record_login_attempt(ip)

    # Check account lockout before authentication
    user_check = get_user_by_username(db, username)
    if user_check and _check_account_lockout(user_check):
        audit_login_failed(username, ip)
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": "Account is temporarily locked. Try again later."},
        )

    user = authenticate_user(db, username, password)

    if not user:
        audit_login_failed(username, ip)
        # Increment failed attempts on the looked-up user (if exists)
        if user_check:
            _handle_failed_login(db, user_check)
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": "Invalid username or password"},
        )

    # Successful authentication — reset lockout
    _reset_failed_attempts(db, user)

    # If 2FA enabled, redirect to 2FA page
    if user.is_2fa_enabled:
        response = RedirectResponse(url="/auth/2fa", status_code=303)
        response.set_cookie(
            key="temp_username", value=username, httponly=True, max_age=300
        )
        return response

    # No 2FA, create token and redirect
    access_token = create_access_token(data={"sub": user.username})
    update_last_login(db, user)
    audit_login_success(username, ip)

    # Redirect to change-password if flagged
    redirect_url = "/auth/change-password" if user.must_change_password else "/admin/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response


@router.get("/2fa", response_class=HTMLResponse)
def twofa_page(request: Request):
    """Show 2FA verification page"""
    return templates.TemplateResponse(request, "auth/2fa.html")


@router.post("/2fa/verify")
def verify_2fa(
    request: Request, totp_code: str = Form(...), db: Session = Depends(get_db)
):
    """Verify 2FA code"""
    username = request.cookies.get("temp_username")

    if not username:
        raise HTTPException(status_code=400, detail="Session expired")

    user = get_user_by_username(db, username)

    if not user or not user.is_2fa_enabled:
        raise HTTPException(status_code=400, detail="2FA not enabled")

    # Verify TOTP
    if not verify_totp(user.totp_secret, totp_code):
        audit_2fa_failed(username)
        return templates.TemplateResponse(
            request, "auth/2fa.html", {"error": "Invalid 2FA code"}
        )

    # Create token and redirect
    access_token = create_access_token(data={"sub": user.username})
    update_last_login(db, user)
    audit_2fa_success(username)
    audit_login_success(username, _client_ip(request))

    # Redirect to change-password if flagged
    redirect_url = "/auth/change-password" if user.must_change_password else "/admin/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    response.delete_cookie(key="temp_username")
    return response


@router.get("/logout")
def logout(request: Request):
    """Logout user"""
    token = request.cookies.get("access_token")
    if token:
        try:
            from app.services.auth.token_service import verify_token
            payload = verify_token(token)
            if payload:
                audit_logout(payload.get("sub", "unknown"))
        except Exception:
            pass
    response = RedirectResponse(url="/auth/login", status_code=303)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="temp_username")
    return response


@router.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request):
    """Show change password page"""
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/auth/login", status_code=303)

    return templates.TemplateResponse(request, "auth/change_password.html")


@router.post("/change-password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Handle change password"""
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/auth/login", status_code=303)

    from app.services.auth.token_service import verify_token
    from app.services.auth.password_service import verify_password, get_password_hash

    payload = verify_token(token)
    if not payload:
        return RedirectResponse(url="/auth/login", status_code=303)

    username = payload.get("sub")
    user = get_user_by_username(db, username)

    if not user:
        return RedirectResponse(url="/auth/login", status_code=303)

    # Verify current password
    if not verify_password(current_password, user.hashed_password):
        return templates.TemplateResponse(
            request,
            "auth/change_password.html",
            {"error": "Current password is incorrect"},
        )

    # Validate new password
    if len(new_password) < 8:
        return templates.TemplateResponse(
            request,
            "auth/change_password.html",
            {"error": "Password must be at least 8 characters"},
        )

    if len(new_password.encode("utf-8")) > 72:
        return templates.TemplateResponse(
            request,
            "auth/change_password.html",
            {"error": "Password must not exceed 72 bytes (bcrypt limit)"},
        )

    # Check if passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse(
            request,
            "auth/change_password.html",
            {"error": "New passwords do not match"},
        )

    # Check if new password is same as old
    if verify_password(new_password, user.hashed_password):
        return templates.TemplateResponse(
            request,
            "auth/change_password.html",
            {
                "error": "New password must be different from current password",
            },
        )

    # Update password and clear force-change flag
    user.hashed_password = get_password_hash(new_password)
    user.must_change_password = False
    db.commit()
    audit_password_change(username)

    # Redirect to login with success message
    response = RedirectResponse(url="/auth/login?changed=1", status_code=303)
    response.delete_cookie(key="access_token")  # Force re-login
    return response
