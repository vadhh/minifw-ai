from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
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


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Show login page"""
    return templates.TemplateResponse("auth/login.html", {"request": request})


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Handle login"""
    user = authenticate_user(db, username, password)

    if not user:
        audit_login_failed(username, _client_ip(request))
        return templates.TemplateResponse(
            "auth/login.html",
            {"request": request, "error": "Invalid username or password"},
        )

    # If 2FA enabled, redirect to 2FA page
    if user.is_2fa_enabled:
        response = RedirectResponse(url="/auth/2fa", status_code=303)
        response.set_cookie(
            key="temp_username", value=username, httponly=True, max_age=300
        )
        return response

    # No 2FA, create token and redirect to dashboard
    access_token = create_access_token(data={"sub": user.username})
    update_last_login(db, user)
    audit_login_success(username, _client_ip(request))

    response = RedirectResponse(url="/admin/", status_code=303)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response


@router.get("/2fa", response_class=HTMLResponse)
def twofa_page(request: Request):
    """Show 2FA verification page"""
    return templates.TemplateResponse("auth/2fa.html", {"request": request})


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
            "auth/2fa.html", {"request": request, "error": "Invalid 2FA code"}
        )

    # Create token and redirect
    access_token = create_access_token(data={"sub": user.username})
    update_last_login(db, user)
    audit_2fa_success(username)
    audit_login_success(username, _client_ip(request))

    response = RedirectResponse(url="/admin/", status_code=303)
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

    return templates.TemplateResponse("auth/change_password.html", {"request": request})


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
            "auth/change_password.html",
            {"request": request, "error": "Current password is incorrect"},
        )

    # Validate new password
    if len(new_password) < 8:
        return templates.TemplateResponse(
            "auth/change_password.html",
            {"request": request, "error": "Password must be at least 8 characters"},
        )

    # Check if passwords match
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "auth/change_password.html",
            {"request": request, "error": "New passwords do not match"},
        )

    # Check if new password is same as old
    if verify_password(new_password, user.hashed_password):
        return templates.TemplateResponse(
            "auth/change_password.html",
            {
                "request": request,
                "error": "New password must be different from current password",
            },
        )

    # Update password
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    audit_password_change(username)

    # Redirect to login with success message
    response = RedirectResponse(url="/auth/login?changed=1", status_code=303)
    response.delete_cookie(key="access_token")  # Force re-login
    return response
