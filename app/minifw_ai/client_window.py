"""Per-client connection-rate AI (schema client-window-v1).

Feature: new connections from one client to one server:port within the last 60 s, counted once per
5-tuple when the flow tracker first sees it. Timestamps are FlowStats.first_seen, so a conntrack
deployment sees 5-second poll times; only counts are used because finer timing is not available there.

The model is a logistic regression stored as JSON (no pickle). It may isolate a client on its own only
when root-only config (MINIFW_AI_ENFORCE_MODEL_SHA256) names the SHA-256 of this exact file, the
client's segment is listed in policy ai_enforcement.segments, and the client is not exempt.
Scope is fast password guessing (roughly 30+ attempts/min to one server); slower guessing is not observable here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
from collections import OrderedDict, deque
from pathlib import Path

SCHEMA = "client-window-v1"
FEATURES = ("n60",)
WINDOW_SECONDS = 60.0
DEFAULT_MODEL_PATH = "/opt/minifw_ai/models/client_window_v1.json"
DEFAULT_BLOCK_TIMEOUT = 900


class ClientWindow:
    """Counts new connections per (client, server, port) in a sliding window of first-seen times."""

    def __init__(self, window: float = WINDOW_SECONDS, ignore_before: float = 0.0, max_keys: int = 20000):
        self.window = window
        # Flows first seen before this time are not counted: the first conntrack snapshot after an
        # engine (re)start reports every existing connection as new.
        self.ignore_before = ignore_before
        self.max_keys = max_keys
        self._starts: OrderedDict[tuple, deque] = OrderedDict()

    def add(self, client_ip: str, dst_ip: str, dst_port: int, first_seen: float) -> dict | None:
        if first_seen < self.ignore_before or not dst_ip:
            return None
        key = (client_ip, dst_ip, int(dst_port))
        starts = self._starts.get(key)
        if starts is None:
            if len(self._starts) >= self.max_keys:
                self._starts.popitem(last=False)
            starts = self._starts[key] = deque(maxlen=1000)  # ponytail: counts saturate at 1000/min
        else:
            self._starts.move_to_end(key)
        starts.append(first_seen)
        while starts and first_seen - starts[0] > self.window:
            starts.popleft()
        return {"n60": len(starts)}


class WindowModel:
    def __init__(self, raw: bytes):
        self.sha256 = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw)
        if data.get("schema") != SCHEMA or tuple(data.get("features", ())) != FEATURES:
            raise ValueError("not a client-window-v1 model")
        self.coef = [float(c) for c in data["coef"]]
        self.intercept = float(data["intercept"])
        self.block_probability = float(data["block_probability"])
        if len(self.coef) != len(FEATURES) or not all(map(math.isfinite, self.coef + [self.intercept])):
            raise ValueError("bad coefficients")
        if not 0.5 <= self.block_probability < 1:
            raise ValueError("block_probability must be in [0.5, 1)")

    def probability(self, features: dict) -> float:
        z = self.intercept + sum(c * float(features[name]) for c, name in zip(self.coef, FEATURES))
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


def load_model(path: str | None = None) -> WindowModel | None:
    """Missing or invalid model: None, and the engine keeps running on baseline rules."""
    path = path or os.environ.get("MINIFW_AI_WINDOW_MODEL", DEFAULT_MODEL_PATH)
    try:
        model = WindowModel(Path(path).read_bytes())
    except FileNotFoundError:
        logging.info("[AI_WINDOW] No model at %s; AI window scoring disabled", path)
        return None
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logging.warning("[AI_WINDOW] Model %s rejected (%s); AI window scoring disabled", path, exc)
        return None
    logging.info("[AI_WINDOW] Loaded %s sha256=%s", path, model.sha256)
    return model


def enforcement_approved(model: WindowModel | None) -> bool:
    approved = os.environ.get("MINIFW_AI_ENFORCE_MODEL_SHA256", "").strip().lower()
    return bool(model and approved and approved == model.sha256)


def may_isolate(model: WindowModel | None, probability: float, segment: str, client_ip: str, cfg: dict) -> bool:
    """True only for an approved model, high confidence, a listed segment and a non-exempt IPv4 client."""
    if not enforcement_approved(model) or probability < model.block_probability:
        return False
    if segment not in cfg.get("segments", ()):
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return not any(address in ipaddress.ip_network(cidr, strict=False) for cidr in cfg.get("exempt", ()))
