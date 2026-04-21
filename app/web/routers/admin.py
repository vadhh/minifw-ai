import re
import threading
import time as _time

from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel, field_validator
from app.middleware.auth_middleware import get_current_user
from app.models.user import User
from app.controllers.admin.dashboard_controller import dashboard_controller
from app.controllers.admin.allow_domain_controller import (
    allow_domain_controller,
    add_allow_domain,
    update_allow_domain,
    delete_allow_domain,
)
from app.controllers.admin.deny_ip_controller import (
    deny_ip_controller,
    add_deny_ip,
    update_deny_ip,
    delete_deny_ip,
)
from app.controllers.admin.deny_asn_controller import (
    deny_asn_controller,
    add_deny_asn,
    update_deny_asn,
    delete_deny_asn,
)
from app.controllers.admin.deny_domain_controller import (
    deny_domain_controller,
    add_deny_domain,
    update_deny_domain,
    delete_deny_domain,
)

from app.controllers.admin.events_controller import events_controller
from app.controllers.admin.events_api_controller import events_datatable_controller
from app.controllers.admin.download_events_controller import download_events_controller
from app.controllers.admin.policy_controller import (
    policy_controller,
    add_segment_controller,
    delete_segment_controller,
    update_segment_subnets_controller,
    update_features_controller,
    update_enforcement_controller,
    update_collectors_controller,
    update_burst_controller,
)
from app.controllers.admin.user_management_controller import (
    user_management_page_controller,
    get_all_users_controller,
    create_user_controller,
    update_user_controller,
    change_password_controller,
    delete_user_controller,
    get_current_user_info_controller,
)
from app.controllers.admin.audit_logs_controller import (
    audit_logs_page_controller,
    get_all_audit_logs_controller,
    get_audit_statistics_controller,
    export_audit_logs_controller,
)

from typing import Optional
from sqlalchemy.orm import Session
from app.database import get_db
from minifw_ai.audit import audit_policy_change, audit_user_mgmt

router = APIRouter(prefix="/admin", tags=["Admin"])
from app.web.templates_config import templates


# --- Input validation patterns ---
_RE_DOMAIN = re.compile(
    r"^(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_RE_IP_CIDR = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$"
)
_RE_ASN = re.compile(r"^AS\d{1,10}$", re.IGNORECASE)
_RE_SAFE_NAME = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
_RE_SAFE_PATH = re.compile(r"^[a-zA-Z0-9/_\-\.]{1,256}$")
_RE_USERNAME = re.compile(r"^[a-zA-Z0-9_\-\.@]{1,128}$")
_RE_SUBNET = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")

# SQL/command injection patterns to reject
_INJECTION_PATTERNS = re.compile(
    r"(?:--|;|'|\"|\\x|%27|%22|%3B|\bUNION\b|\bSELECT\b|\bINSERT\b"
    r"|\bDELETE\b|\bDROP\b|\bUPDATE\b|\bEXEC\b|\bORDER\s+BY\b"
    r"|\bOR\s+1\s*=\s*1\b|\bAND\s+1\s*=\s*1\b|`|\$\(|\$\{|&&|\|\|)",
    re.IGNORECASE,
)


def _validate_domain(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 253:
        raise ValueError("Domain name too long (max 253 chars)")
    if not _RE_DOMAIN.match(v):
        raise ValueError("Invalid domain format")
    if _INJECTION_PATTERNS.search(v):
        raise ValueError("Invalid characters in domain")
    return v


def _validate_ip(v: str) -> str:
    v = v.strip()
    if not _RE_IP_CIDR.match(v):
        raise ValueError("Invalid IP/CIDR format (e.g. 192.168.1.0/24)")
    # Validate octet ranges
    parts = v.split("/")[0].split(".")
    for octet in parts:
        if int(octet) > 255:
            raise ValueError("IP octet out of range (0-255)")
    if "/" in v:
        prefix = int(v.split("/")[1])
        if prefix > 32:
            raise ValueError("CIDR prefix out of range (0-32)")
    return v


def _validate_asn(v: str) -> str:
    v = v.strip().upper()
    if not _RE_ASN.match(v):
        raise ValueError("Invalid ASN format (e.g. AS12345)")
    return v


def _validate_safe_name(v: str) -> str:
    v = v.strip()
    if not _RE_SAFE_NAME.match(v):
        raise ValueError("Invalid name: only alphanumeric, underscore, hyphen allowed (max 64 chars)")
    return v


def _validate_safe_path(v: str) -> str:
    v = v.strip()
    if ".." in v:
        raise ValueError("Path traversal not allowed")
    if not _RE_SAFE_PATH.match(v):
        raise ValueError("Invalid path: only alphanumeric, slashes, underscores, hyphens, dots allowed")
    return v


def _validate_no_injection(v: str) -> str:
    if _INJECTION_PATTERNS.search(v):
        raise ValueError("Input contains disallowed characters or patterns")
    return v


# Pydantic models for request bodies
class AddDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


class UpdateDomainRequest(BaseModel):
    old: str
    new: str

    @field_validator("old", "new")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


class DeleteDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


class AddIpRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v: str) -> str:
        return _validate_ip(v)


class UpdateIpRequest(BaseModel):
    old: str
    new: str

    @field_validator("old", "new")
    @classmethod
    def check_ip(cls, v: str) -> str:
        return _validate_ip(v)


class DeleteIpRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def check_ip(cls, v: str) -> str:
        return _validate_ip(v)


class AddAsnRequest(BaseModel):
    asn: str

    @field_validator("asn")
    @classmethod
    def check_asn(cls, v: str) -> str:
        return _validate_asn(v)


class UpdateAsnRequest(BaseModel):
    old: str
    new: str

    @field_validator("old", "new")
    @classmethod
    def check_asn(cls, v: str) -> str:
        return _validate_asn(v)


class DeleteAsnRequest(BaseModel):
    asn: str

    @field_validator("asn")
    @classmethod
    def check_asn(cls, v: str) -> str:
        return _validate_asn(v)


class AddDenyDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


class UpdateDenyDomainRequest(BaseModel):
    old: str
    new: str

    @field_validator("old", "new")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


class DeleteDenyDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str) -> str:
        return _validate_domain(v)


# Policy requests
class AddSegmentRequest(BaseModel):
    segment_name: str
    block_threshold: int
    monitor_threshold: int

    @field_validator("segment_name")
    @classmethod
    def check_segment_name(cls, v: str) -> str:
        return _validate_safe_name(v)

    @field_validator("block_threshold", "monitor_threshold")
    @classmethod
    def check_threshold(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("Threshold must be 0-100")
        return v


class UpdateSubnetsRequest(BaseModel):
    segment_name: str
    subnets: list

    @field_validator("segment_name")
    @classmethod
    def check_segment_name(cls, v: str) -> str:
        return _validate_safe_name(v)

    @field_validator("subnets")
    @classmethod
    def check_subnets(cls, v: list) -> list:
        for subnet in v:
            if not isinstance(subnet, str) or not _RE_SUBNET.match(subnet.strip()):
                raise ValueError(f"Invalid subnet format: {subnet!r} (expected e.g. 192.168.1.0/24)")
        return [s.strip() for s in v]


class UpdateFeaturesRequest(BaseModel):
    dns_weight: int
    sni_weight: int
    asn_weight: int
    burst_weight: int

    @field_validator("dns_weight", "sni_weight", "asn_weight", "burst_weight")
    @classmethod
    def check_weight(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("Weight must be 0-100")
        return v


class UpdateEnforcementRequest(BaseModel):
    ipset_name_v4: str
    ip_timeout_seconds: int
    nft_table: str
    nft_chain: str

    @field_validator("ipset_name_v4", "nft_table", "nft_chain")
    @classmethod
    def check_nft_name(cls, v: str) -> str:
        return _validate_safe_name(v)

    @field_validator("ip_timeout_seconds")
    @classmethod
    def check_timeout(cls, v: int) -> int:
        if not (1 <= v <= 86400):
            raise ValueError("Timeout must be 1-86400 seconds")
        return v


class UpdateCollectorsRequest(BaseModel):
    dnsmasq_log_path: str
    zeek_ssl_log_path: str
    use_zeek_sni: bool

    @field_validator("dnsmasq_log_path", "zeek_ssl_log_path")
    @classmethod
    def check_path(cls, v: str) -> str:
        return _validate_safe_path(v)


class UpdateBurstRequest(BaseModel):
    dns_queries_per_minute_monitor: int
    dns_queries_per_minute_block: int

    @field_validator("dns_queries_per_minute_monitor", "dns_queries_per_minute_block")
    @classmethod
    def check_rate(cls, v: int) -> int:
        if not (1 <= v <= 10000):
            raise ValueError("Rate must be 1-10000")
        return v


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str
    sector: str
    full_name: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    must_change_password: bool = True

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str) -> str:
        v = v.strip()
        if not _RE_USERNAME.match(v):
            raise ValueError("Invalid username: alphanumeric, underscore, hyphen, dot, @ only (max 128)")
        return v

    @field_validator("role")
    @classmethod
    def check_role(cls, v: str) -> str:
        allowed = {"super_admin", "admin", "operator", "viewer"}
        if v.strip().lower() not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(sorted(allowed))}")
        return v.strip().lower()

    @field_validator("sector")
    @classmethod
    def check_sector(cls, v: str) -> str:
        allowed = {"education", "hospital", "government", "finance", "legal", "establishment", "gambling"}
        if v.strip().lower() not in allowed:
            raise ValueError(f"Sector must be one of: {', '.join(sorted(allowed))}")
        return v.strip().lower()

    @field_validator("full_name", "department")
    @classmethod
    def check_text_field(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if _INJECTION_PATTERNS.search(v):
                raise ValueError("Input contains disallowed characters")
        return v


class UpdateUserRequest(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    sector: Optional[str] = None
    full_name: Optional[str] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("role")
    @classmethod
    def check_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"super_admin", "admin", "operator", "viewer"}
            if v.strip().lower() not in allowed:
                raise ValueError(f"Role must be one of: {', '.join(sorted(allowed))}")
            return v.strip().lower()
        return v

    @field_validator("sector")
    @classmethod
    def check_sector(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed = {"education", "hospital", "government", "finance", "legal", "establishment", "gambling"}
            if v.strip().lower() not in allowed:
                raise ValueError(f"Sector must be one of: {', '.join(sorted(allowed))}")
            return v.strip().lower()
        return v

    @field_validator("full_name", "department")
    @classmethod
    def check_text_field(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if _INJECTION_PATTERNS.search(v):
                raise ValueError("Input contains disallowed characters")
        return v


class ChangePasswordRequest(BaseModel):
    new_password: str
    must_change_password: bool = True


@router.get("/")
def dashboard(request: Request, current_user: User = Depends(get_current_user)):
    return dashboard_controller(request)


@router.get("/allow-domain")
def get_allow_domain(request: Request, current_user: User = Depends(get_current_user)):
    return allow_domain_controller(request)


@router.post("/allow-domain")
def post_allow_domain(
    payload: AddDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    add_allow_domain(current_user, db, payload.domain)
    audit_policy_change("add_allow_domain", "allow_domain", payload.domain, current_user.username)
    return {"message": "Domain added successfully"}


@router.put("/allow-domain")
def put_allow_domain(
    payload: UpdateDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_allow_domain(current_user, db, payload.old, payload.new)
    audit_policy_change("update_allow_domain", "allow_domain", f"{payload.old} -> {payload.new}", current_user.username)
    return {"message": "Domain updated successfully"}


@router.delete("/allow-domain")
def del_allow_domain(
    payload: DeleteDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    delete_allow_domain(current_user, db, payload.domain)
    audit_policy_change("delete_allow_domain", "allow_domain", payload.domain, current_user.username)
    return {"message": "Domain deleted successfully"}


# Deny IP routes
@router.get("/deny-ip")
def get_deny_ip(request: Request, current_user: User = Depends(get_current_user)):
    return deny_ip_controller(request)


@router.post("/deny-ip")
def post_deny_ip(
    payload: AddIpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    add_deny_ip(current_user, db, payload.ip)
    audit_policy_change("add_deny_ip", "deny_ip", payload.ip, current_user.username)
    return {"message": "IP address added successfully"}


@router.put("/deny-ip")
def put_deny_ip(
    payload: UpdateIpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_deny_ip(current_user, db, payload.old, payload.new)
    audit_policy_change("update_deny_ip", "deny_ip", f"{payload.old} -> {payload.new}", current_user.username)
    return {"message": "IP address updated successfully"}


@router.delete("/deny-ip")
def del_deny_ip(
    payload: DeleteIpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    delete_deny_ip(current_user, db, payload.ip)
    audit_policy_change("delete_deny_ip", "deny_ip", payload.ip, current_user.username)
    return {"message": "IP address deleted successfully"}


# Deny ASN routes
@router.get("/deny-asn")
def get_deny_asn(request: Request, current_user: User = Depends(get_current_user)):
    return deny_asn_controller(request)


@router.post("/deny-asn")
def post_deny_asn(
    payload: AddAsnRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    add_deny_asn(current_user, db, payload.asn)
    audit_policy_change("add_deny_asn", "deny_asn", payload.asn, current_user.username)
    return {"message": "ASN added successfully"}


@router.put("/deny-asn")
def put_deny_asn(
    payload: UpdateAsnRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_deny_asn(current_user, db, payload.old, payload.new)
    audit_policy_change("update_deny_asn", "deny_asn", f"{payload.old} -> {payload.new}", current_user.username)
    return {"message": "ASN updated successfully"}


@router.delete("/deny-asn")
def del_deny_asn(
    payload: DeleteAsnRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    delete_deny_asn(current_user, db, payload.asn)
    audit_policy_change("delete_deny_asn", "deny_asn", payload.asn, current_user.username)
    return {"message": "ASN deleted successfully"}


# Deny Domain routes
@router.get("/deny-domain")
def get_deny_domain(request: Request, current_user: User = Depends(get_current_user)):
    return deny_domain_controller(request)


@router.post("/deny-domain")
def post_deny_domain(
    payload: AddDenyDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    add_deny_domain(current_user, db, payload.domain)
    audit_policy_change("add_deny_domain", "deny_domain", payload.domain, current_user.username)
    return {"message": "Domain added successfully"}


@router.put("/deny-domain")
def put_deny_domain(
    payload: UpdateDenyDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_deny_domain(current_user, db, payload.old, payload.new)
    audit_policy_change("update_deny_domain", "deny_domain", f"{payload.old} -> {payload.new}", current_user.username)
    return {"message": "Domain updated successfully"}


@router.delete("/deny-domain")
def del_deny_domain(
    payload: DeleteDenyDomainRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    delete_deny_domain(current_user, db, payload.domain)
    audit_policy_change("delete_deny_domain", "deny_domain", payload.domain, current_user.username)
    return {"message": "Domain deleted successfully"}


# Events page
@router.get("/events")
def get_events(request: Request, current_user: User = Depends(get_current_user)):
    return events_controller(request)


# Events DataTables API
@router.get("/api/events")
def api_get_events(
    current_user: User = Depends(get_current_user),
    draw: int = 1,
    start: int = 0,
    length: int = 10,
    search_value: str = "",
    order_column: int = 0,
    order_dir: str = "desc",
):
    """API endpoint for DataTables server-side processing"""
    # Sanitize search input
    if search_value and _INJECTION_PATTERNS.search(search_value):
        search_value = ""
    order_dir = order_dir if order_dir in ("asc", "desc") else "desc"
    length = max(1, min(length, 500))
    return events_datatable_controller(
        draw=draw,
        start=max(0, start),
        length=length,
        search_value=search_value,
        order_column=order_column,
        order_dir=order_dir,
    )


# Block Rate API (spike chart data)
@router.get("/api/block-rate")
def api_block_rate(current_user: User = Depends(get_current_user)):
    """
    Return blocks-per-5s buckets over the last 60 seconds.
    Used by the demo spike chart on the dashboard.
    """
    from app.services.events.get_events_service import get_recent_events
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=60)
    bucket_size = 5  # seconds
    num_buckets = 12  # 12 × 5 s = 60 s

    buckets_blocks = [0] * num_buckets
    buckets_total = [0] * num_buckets

    all_events = get_recent_events(limit=500)
    for ev in all_events:
        try:
            ts_str = ev.get("time", "")
            if not ts_str:
                continue
            normalized = ts_str.replace(" ", "T").replace("Z", "+00:00")
            if not normalized.endswith("+00:00") and "+" not in normalized[10:]:
                normalized += "+00:00"
            dt = datetime.fromisoformat(normalized)
        except Exception:
            continue
        if dt < cutoff:
            continue
        age = (now - dt).total_seconds()
        if age < 0:
            continue
        idx = min(int(age // bucket_size), num_buckets - 1)
        bucket_idx = num_buckets - 1 - idx  # newest → rightmost
        buckets_total[bucket_idx] += 1
        if ev.get("status") == "blocked":
            buckets_blocks[bucket_idx] += 1

    labels = []
    for i in range(num_buckets):
        t = now - timedelta(seconds=(num_buckets - 1 - i) * bucket_size)
        labels.append(t.strftime("%H:%M:%S"))

    return {"labels": labels, "blocks": buckets_blocks, "total": buckets_total}


# Events Download API
@router.get("/api/events/download")
def api_download_events(
    action_filter: str = "all",
    fmt: str = "xlsx",
    current_user: User = Depends(get_current_user),
):
    """API endpoint for downloading events as Excel, CSV, or PDF report"""
    if action_filter not in ("all", "block", "monitor", "allow"):
        action_filter = "all"
    if fmt not in ("xlsx", "csv", "pdf"):
        fmt = "xlsx"
    return download_events_controller(action_filter, fmt)


# IoMT Alerts (Hospital sector)
@router.get("/iomt-alerts")
def iomt_alerts_page(request: Request, current_user: User = Depends(get_current_user)):
    """IoMT device alert panel — filtered view of medical device anomalies."""
    from app.services.events.get_events_service import get_recent_events
    all_events = get_recent_events(limit=500)
    iomt_events = [e for e in all_events if "iomt_device_alert" in e.get("reason", "")]
    return templates.TemplateResponse(
        request,
        "admin/iomt_alerts.html",
        {"events": iomt_events, "total": len(iomt_events)},
    )


@router.get("/api/iomt-alerts")
def api_iomt_alerts(current_user: User = Depends(get_current_user)):
    """API: Get IoMT device alerts filtered from event stream."""
    from app.services.events.get_events_service import get_recent_events
    all_events = get_recent_events(limit=500)
    iomt_events = [e for e in all_events if "iomt_device_alert" in e.get("reason", "")]
    return {
        "success": True,
        "total": len(iomt_events),
        "alerts": iomt_events,
    }


# Policy Configuration routes
@router.get("/policy")
def get_policy(request: Request, current_user: User = Depends(get_current_user)):
    return policy_controller(request)


@router.post("/policy/segment")
def post_segment(
    payload: AddSegmentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    add_segment_controller(
        current_user,
        db,
        payload.segment_name,
        payload.block_threshold,
        payload.monitor_threshold,
    )
    audit_policy_change("add_segment", "segment", payload.segment_name, current_user.username)
    return {"message": "Segment saved successfully"}


@router.delete("/policy/segment/{segment_name}")
def delete_segment(
    segment_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    delete_segment_controller(current_user, db, segment_name)
    audit_policy_change("delete_segment", "segment", segment_name, current_user.username)
    return {"message": "Segment deleted successfully"}


@router.post("/policy/segment/subnets")
def post_segment_subnets(
    payload: UpdateSubnetsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_segment_subnets_controller(
        current_user, db, payload.segment_name, payload.subnets
    )
    return {"message": "Subnets updated successfully"}


@router.post("/policy/features")
def post_features(
    payload: UpdateFeaturesRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_features_controller(
        current_user,
        db,
        payload.dns_weight,
        payload.sni_weight,
        payload.asn_weight,
        payload.burst_weight,
    )
    audit_policy_change("update_features", "feature_weights",
                        f"dns={payload.dns_weight} sni={payload.sni_weight} asn={payload.asn_weight} burst={payload.burst_weight}",
                        current_user.username)
    return {"message": "Feature weights updated successfully"}


@router.post("/policy/enforcement")
def post_enforcement(
    payload: UpdateEnforcementRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_enforcement_controller(
        current_user,
        db,
        payload.ipset_name_v4,
        payload.ip_timeout_seconds,
        payload.nft_table,
        payload.nft_chain,
    )
    audit_policy_change("update_enforcement", "enforcement", f"set={payload.ipset_name_v4} timeout={payload.ip_timeout_seconds}s", current_user.username)
    return {"message": "Enforcement configuration updated successfully"}


@router.post("/policy/collectors")
def post_collectors(
    payload: UpdateCollectorsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_collectors_controller(
        current_user,
        db,
        payload.dnsmasq_log_path,
        payload.zeek_ssl_log_path,
        payload.use_zeek_sni,
    )
    audit_policy_change("update_collectors", "collectors", f"dns={payload.dnsmasq_log_path} zeek={payload.use_zeek_sni}", current_user.username)
    return {"message": "Collectors configuration updated successfully"}


@router.post("/policy/burst")
def post_burst(
    payload: UpdateBurstRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_burst_controller(
        current_user,
        db,
        payload.dns_queries_per_minute_monitor,
        payload.dns_queries_per_minute_block,
    )
    audit_policy_change("update_burst", "burst_detection",
                        f"monitor={payload.dns_queries_per_minute_monitor} block={payload.dns_queries_per_minute_block}",
                        current_user.username)
    return {"message": "Burst detection configuration updated successfully"}


# User Management Page
@router.get("/users")
def get_user_management_page(
    request: Request, current_user: User = Depends(get_current_user)
):
    """User management page (Super Admin only)"""
    return user_management_page_controller(request)


# Get Current User Info (for permission check)
@router.get("/api/auth/current-user")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return get_current_user_info_controller(current_user)


# Get All Users
@router.get("/api/users")
def get_all_users(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    """Get all users (Super Admin only)"""
    return get_all_users_controller(db, current_user)


# Create User
@router.post("/api/users")
def create_user(
    payload: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create new user (Super Admin only)"""
    result = create_user_controller(
        db=db,
        current_user=current_user,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        role=payload.role,
        sector=payload.sector,
        full_name=payload.full_name,
        department=payload.department,
        phone=payload.phone,
        must_change_password=payload.must_change_password,
    )
    audit_user_mgmt("create_user", payload.username, current_user.username, role=payload.role, sector=payload.sector)
    return result


# Update User
@router.put("/api/users/{user_id}")
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update user (Super Admin only)"""
    result = update_user_controller(
        db=db,
        current_user=current_user,
        user_id=user_id,
        email=payload.email,
        role=payload.role,
        sector=payload.sector,
        full_name=payload.full_name,
        department=payload.department,
        phone=payload.phone,
        is_active=payload.is_active,
    )
    audit_user_mgmt("update_user", f"user_id={user_id}", current_user.username)
    return result


# Change User Password
@router.put("/api/users/{user_id}/password")
def change_user_password(
    user_id: int,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change user password (Super Admin only)"""
    result = change_password_controller(
        db=db,
        current_user=current_user,
        user_id=user_id,
        new_password=payload.new_password,
        must_change_password=payload.must_change_password,
    )
    audit_user_mgmt("change_password", f"user_id={user_id}", current_user.username)
    return result


# Delete User
@router.delete("/api/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete user (Super Admin only)"""
    result = delete_user_controller(db, current_user, user_id)
    audit_user_mgmt("delete_user", f"user_id={user_id}", current_user.username)
    return result


# ============================================================
# AUDIT LOGS ROUTES
# ============================================================


@router.get("/audit-logs")
def get_audit_logs_page(
    request: Request, current_user: User = Depends(get_current_user)
):
    return audit_logs_page_controller(request)


@router.get("/api/audit/logs")
def get_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 100,
    offset: int = 0,
    action: Optional[str] = None,
    severity: Optional[str] = None,
    username: Optional[str] = None,
    resource_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    # Sanitize string filters
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    for param in (action, severity, username, resource_type, start_date, end_date):
        if param and _INJECTION_PATTERNS.search(param):
            raise HTTPException(status_code=400, detail="Invalid filter value")
    return get_all_audit_logs_controller(
        db=db,
        current_user=current_user,
        limit=limit,
        offset=offset,
        action=action,
        severity=severity,
        username=username,
        resource_type=resource_type,
        start_date=start_date,
        end_date=end_date,
    )


@router.get("/api/audit/statistics")
def get_audit_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    days: int = 7,
):
    return get_audit_statistics_controller(db, current_user, days)


@router.get("/api/audit/export")
def export_audit_logs(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    format: str = "json",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
):
    return export_audit_logs_controller(db, current_user, format, start_date, end_date)


# ============================================================
# LIVE BLOCK FEED (last 5 seconds of blocked events)
# ============================================================


@router.get("/api/live-blocks")
def api_live_blocks(current_user: User = Depends(get_current_user)):
    """
    Return events blocked within the last 5 seconds.
    Polled every 2 s by the dashboard Live Block Feed panel.
    """
    from app.services.events.get_events_service import get_recent_events
    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=5)
    all_events = get_recent_events(limit=200)
    live = []
    for ev in all_events:
        if ev.get("status") != "blocked":
            continue
        try:
            dt = datetime.fromisoformat(ev["time"].replace(" ", "T") + "+00:00")
        except Exception:
            continue
        if dt >= cutoff:
            live.append({
                "time": ev["time"],
                "source": ev.get("source", ""),
                "client_ip": ev.get("client_ip", ""),
                "domain": ev.get("domain", ""),
                "score": ev.get("score", 0),
                "reason": ev.get("reason", ""),
                "type": ev.get("type", ""),
                "ai_explanation": _build_ai_explanation(ev),
            })
    return {"count": len(live), "events": live}


def _build_ai_explanation(ev: dict) -> dict:
    """
    Categorise the raw reasons string into ASN / TLS / Behavior buckets
    and return a structured explanation dict for the AI Decision panel.
    """
    reason = ev.get("reason", "").lower()
    score = ev.get("score", 0)

    asn_signals = []
    tls_signals = []
    behavior_signals = []

    if "asn" in reason:
        asn_signals.append("ASN blocklist match")
    if "tor" in reason or "anonymizer" in reason:
        asn_signals.append("Tor / anonymizer network")
    if "tls" in reason or "sni" in reason:
        tls_signals.append("TLS/SNI policy violation")
    if "dns_tunnel" in reason:
        behavior_signals.append("DNS tunnelling detected")
    if "port_scan" in reason or "pps" in reason:
        behavior_signals.append("Port scan / high PPS")
    if "burst" in reason or "rate" in reason:
        behavior_signals.append("Burst / rate-limit breach")
    if "yara" in reason:
        behavior_signals.append("YARA pattern match")
    if "hard_threat_gate" in reason:
        behavior_signals.append("Hard threat gate triggered")
    if "mlp_threat_score" in reason or "mlp" in reason:
        behavior_signals.append(f"AI threat score: {score}")
    if "ip" in reason and not any(asn_signals + tls_signals + behavior_signals):
        asn_signals.append("IP blocklist match")

    # Determine dominant category
    category = "Behavior"
    if tls_signals and not asn_signals and not behavior_signals:
        category = "TLS/SNI"
    elif asn_signals and not behavior_signals:
        category = "ASN / Network"

    return {
        "score": score,
        "category": category,
        "asn": asn_signals,
        "tls": tls_signals,
        "behavior": behavior_signals,
    }


# ============================================================
# KERNEL PROOF INDICATOR (nftables enforcement check)
# ============================================================

_kernel_proof_lock = threading.Lock()
_kernel_proof_cache: dict = {}
_kernel_proof_expires: float = 0.0


@router.get("/api/kernel-proof")
def api_kernel_proof(current_user: User = Depends(get_current_user)):
    """
    Check whether the nftables minifw table/chain is active.
    Result is cached for 15 s (matching the JS poll interval) to avoid
    repeated subprocess + audit.jsonl reads across concurrent requests.

    Two-stage detection:
      Stage 1 — nft list (bare-metal, same network namespace)
      Stage 2 — audit.jsonl firewall_init sentinel (Docker shared volume)
    """
    global _kernel_proof_cache, _kernel_proof_expires

    now = _time.monotonic()
    with _kernel_proof_lock:
        if now < _kernel_proof_expires:
            return dict(_kernel_proof_cache)

    result = _compute_kernel_proof()

    with _kernel_proof_lock:
        _kernel_proof_cache = result
        _kernel_proof_expires = _time.monotonic() + 15.0

    return result


def _compute_kernel_proof() -> dict:
    import subprocess
    import json as _json
    from pathlib import Path as _Path

    result = {"active": False, "label": "Not active", "detail": "", "table": "minifw"}

    # Stage 1 — direct nft probe (same network namespace)
    try:
        out = subprocess.run(
            ["nft", "list", "table", "inet", "minifw"],
            capture_output=True, text=True, timeout=3
        )
        if out.returncode == 0 and "MiniFW-AI-Blocklist" in out.stdout:
            result.update(active=True, label="Blocked at kernel level (nftables)",
                          detail="inet/minifw table active with drop rule")
            return result
        if out.returncode == 0:
            result.update(active=True, label="nftables table active",
                          detail="inet/minifw table present (drop rule pending first block)")
            return result
    except (FileNotFoundError, Exception):
        pass  # not on same namespace — fall through to Stage 2

    # Stage 2 — audit.jsonl sentinel (Docker shared-volume)
    audit_log = os.environ.get("MINIFW_AUDIT_LOG", "/opt/minifw_ai/logs/audit.jsonl")
    try:
        audit_path = _Path(audit_log)
        if audit_path.exists():
            for _line in audit_path.open("r", encoding="utf-8"):
                _line = _line.strip()
                if not _line:
                    continue
                try:
                    if _json.loads(_line).get("action") == "firewall_init":
                        result.update(active=True,
                                      label="Blocked at kernel level (nftables)",
                                      detail="Confirmed via engine audit log (Docker deployment)")
                        return result
                except _json.JSONDecodeError:
                    continue
            result["detail"] = "Engine starting — nftables init pending"
        else:
            result["detail"] = "Engine not started (no audit log found)"
    except Exception as exc:
        result["detail"] = f"Audit log check failed: {exc}"

    return result


# ============================================================
# SECTOR LOCK ROUTES (Factory-Set Configuration)
# ============================================================


@router.get("/api/sector-lock")
def get_sector_lock_status(current_user: User = Depends(get_current_user)):
    """
    Get the factory-set sector lock status.

    This endpoint returns the immutable sector configuration.
    The sector CANNOT be changed via the Admin UI.

    Returns:
        - sector: Current sector (school, hospital, government, finance, legal, establishment)
        - locked: Always True (factory-set)
        - config: Sector-specific policy configuration
        - description: Human-readable sector description
    """
    try:
        from app.minifw_ai.sector_lock import get_sector_lock
        from minifw_ai.mode_context import get_mode_ui

        lock = get_sector_lock()
        config = lock.get_sector_config()
        mode_ui = get_mode_ui()

        return {
            "success": True,
            "sector": lock.get_sector(),
            "product_mode": mode_ui.product_mode or None,
            "mode_label": mode_ui.label,
            "mode_sublabel": mode_ui.sublabel,
            "mode_color": mode_ui.color,
            "locked": True,  # Always locked - factory-set
            "description": config.get("description", "Factory-set sector"),
            "config": {
                # Only expose safe-to-display config items
                "force_safesearch": config.get("force_safesearch", False),
                "block_vpns": config.get("block_vpns", False),
                "iomt_high_priority": config.get("iomt_high_priority", False),
                "block_tor": config.get("block_tor", False),
                "geo_ip_strict": config.get("geo_ip_strict", False),
                "data_exfiltration_watch": config.get("data_exfiltration_watch", False),
                "extra_feeds": config.get("extra_feeds", []),
            },
            "message": "Sector is factory-set and cannot be modified via UI",
        }
    except RuntimeError as e:
        return {
            "success": False,
            "sector": "unknown",
            "locked": False,
            "error": str(e),
            "message": "Sector not configured - device may be unprovisioned",
        }
    except ImportError:
        return {
            "success": False,
            "sector": "unknown",
            "locked": False,
            "error": "Sector lock module not available",
            "message": "Sector lock system not installed",
        }
