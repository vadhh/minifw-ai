"""
Shared Jinja2Templates instance for all controllers and routers.

mode_ui is injected as a global once at startup so every template that
extends base.html gets it without each controller passing it explicitly.
"""
from fastapi.templating import Jinja2Templates
from minifw_ai.mode_context import get_mode_ui

templates = Jinja2Templates(directory="app/web/templates")
templates.env.globals["mode_ui"] = get_mode_ui()
