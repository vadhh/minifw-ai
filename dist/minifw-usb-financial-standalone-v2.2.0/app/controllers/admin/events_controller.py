from fastapi import Request
from app.services.events.get_events_service import get_recent_events
from app.web.templates_config import templates

_SSR_LIMIT = 500   # rows rendered into HTML; keeps page size reasonable


def events_controller(request: Request):
    """
    Events/Logs controller — server-side renders the initial events so the
    table is always populated on page load, independent of JS/fetch.
    Reads the most recent 500 events; renders them as HTML.
    """
    all_events = get_recent_events(limit=500)

    total = len(all_events)
    allowed  = sum(1 for e in all_events if e.get("status") == "allowed")
    blocked  = sum(1 for e in all_events if e.get("status") == "blocked")
    monitored = sum(1 for e in all_events if e.get("status") == "monitor")
    threats  = total - allowed

    return templates.TemplateResponse(
        request,
        "admin/events.html",
        {
            "user": {"name": "Fahrezi"},
            "events": all_events[:_SSR_LIMIT],   # rendered rows
            "total_events": total,
            "stat_allowed": allowed,
            "stat_blocked": blocked,
            "stat_monitored": monitored,
            "stat_threats": threats,
        },
    )
