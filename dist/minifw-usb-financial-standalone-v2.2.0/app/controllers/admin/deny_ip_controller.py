from fastapi import Request, HTTPException
from sqlalchemy.orm import Session

from app.models.user import User, UserRole
from app.services.rbac_service import RBACService

from app.services.deny_ip.get_deny_ips_service import get_deny_ips
from app.services.deny_ip.add_deny_ip_service import add_deny_ip_service
from app.services.deny_ip.update_deny_ip_service import update_deny_ip_service
from app.services.deny_ip.delete_deny_ip_service import delete_deny_ip_service
from app.web.templates_config import templates


def deny_ip_controller(request: Request):
    ips = get_deny_ips()

    return templates.TemplateResponse(
        request,
        "admin/deny_ip.html",
        {
            "ips": ips,
            "user": {"name": "Fahrezi"},
        },
    )


def add_deny_ip(current_user: User, db: Session, ip: str):
    RBACService(db).check_permission(current_user, UserRole.ADMIN, "add deny-list IPs")
    try:
        add_deny_ip_service(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def update_deny_ip(current_user: User, db: Session, old_ip: str, new_ip: str):
    RBACService(db).check_permission(
        current_user, UserRole.ADMIN, "update deny-list IPs"
    )
    try:
        update_deny_ip_service(old_ip, new_ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def delete_deny_ip(current_user: User, db: Session, ip: str):
    RBACService(db).check_permission(
        current_user, UserRole.ADMIN, "delete deny-list IPs"
    )
    try:
        delete_deny_ip_service(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
