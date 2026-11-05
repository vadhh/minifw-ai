"""Fictional, ephemeral acceptance sandbox. Never deploy as a business service."""

import hashlib
import json
import secrets
import ssl
import threading
import time
import socket
import struct
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

SANDBOX_PASSWORD = "lab-only-do-not-deploy"
SERVER = "198.18.0.2"
USERS = {"alice": "finance", "bob": "finance", "student": "student", "staff": "staff"}


def dns_answer(query):
    if len(query) < 17:
        raise ValueError("truncated DNS query")
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:] + (
        b"\xc0\x0c\0\1\0\1\0\0\0\x1e\0\4" + socket.inet_aton(SERVER))


class SandboxState:
    def __init__(self):
        self.lock = threading.Lock()
        self.balances = {"alice": 100000, "bob": 50000, "merchant": 0}
        self.ledger = []
        self.sessions = {}


def handler_for(state, media):
    media = Path(media).read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, body, content_type="application/json", headers=None):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def principal(self, role=None):
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                token = cookie["sandbox_session"].value
            except (CookieError, KeyError):
                token = ""
            user = state.sessions.get(token)
            if not isinstance(self.connection, ssl.SSLSocket):
                self.respond(400, {"error": "TLS required for private sandbox operations"})
                return None
            if user is None:
                self.respond(401, {"error": "login required"})
                return None
            if role and USERS[user] != role:
                self.respond(403, {"error": "role denied"})
                return None
            return user

        def do_GET(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/":
                self.respond(200, "<h1>MiniFW acceptance sandbox</h1><p>Fictional credits and users; no real funds.</p>"
                             '<a href="/learning">Learning</a> · <a href="/login">Login</a>', "text/html")
            elif path == "/login":
                self.respond(200, {"endpoint": "POST /login", "users": list(USERS), "scope": "fictional lab accounts"})
            elif path == "/api/account":
                user = self.principal("finance")
                if user:
                    with state.lock:
                        self.respond(200, {"account": user, "credits": state.balances[user], "currency": "fictional credits"})
            elif path == "/documents/statement.csv":
                user = self.principal("finance")
                if user:
                    with state.lock:
                        body = f"account,credits,transactions\n{user},{state.balances[user]},{len(state.ledger)}\n"
                    self.respond(200, body, "text/csv", {"Content-Disposition": 'attachment; filename="sandbox-statement.csv"'})
            elif path == "/staff":
                if self.principal("staff"):
                    self.respond(200, {"service": "staff calendar", "items": [{"title": "Lesson planning", "room": "Lab 1"}]})
            elif path in {"/learning", "/lessons/intro"}:
                self.respond(200, '<h1>Fractions lesson</h1><video controls preload="auto" src="/media/lesson.webm"></video>'
                             '<form action="/search"><label>Search lessons <input name="q"></label><button>Search</button></form>', "text/html")
            elif path == "/search":
                query = parse_qs(parsed.query).get("q", [""])[0]
                self.respond(200, {"query": query, "results": [{"title": "Fractions", "path": "/lessons/intro"}]
                                  if "fraction" in query.lower() else []})
            elif path == "/media/lesson.webm":
                start, end, status = 0, len(media) - 1, 200
                headers = {"Accept-Ranges": "bytes", "X-Content-SHA256": hashlib.sha256(media).hexdigest()}
                requested = self.headers.get("Range")
                if requested:
                    try:
                        unit, extent = requested.split("=", 1)
                        first, last = extent.split("-", 1)
                        start, end = int(first), int(last) if last else len(media) - 1
                        if unit != "bytes" or not (0 <= start <= end < len(media)):
                            raise ValueError
                    except ValueError:
                        self.respond(416, {"error": "invalid range"})
                        return
                    status = 206
                    headers["Content-Range"] = f"bytes {start}-{end}/{len(media)}"
                self.respond(status, media[start:end + 1], "video/webm", headers)
            elif path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "32768")
                self.end_headers()
                try:
                    for _ in range(32):
                        self.wfile.write(b"x" * 1024)
                        self.wfile.flush()
                        time.sleep(0.25)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self.respond(404, {"error": "unknown sandbox endpoint"})

        def do_POST(self):
            path = urlsplit(self.path).path
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 65536:
                    raise ValueError
                raw = self.rfile.read(length)
                if path == "/dns-query":
                    # A real encrypted DNS fixture, intentionally outside DNS-log name coverage.
                    self.respond(200, dns_answer(raw), "application/dns-message")
                    return
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError
            except (ValueError, UnicodeError):
                self.respond(400, {"error": "invalid request"})
                return
            if path == "/login":
                if not isinstance(self.connection, ssl.SSLSocket):
                    self.respond(400, {"error": "TLS required"})
                elif not isinstance(data.get("username"), str) or data["username"] not in USERS or data.get("password") != SANDBOX_PASSWORD:
                    self.respond(401, {"error": "invalid sandbox credentials"})
                else:
                    user = data["username"]
                    token = secrets.token_urlsafe(24)
                    with state.lock:
                        state.sessions = {key: value for key, value in state.sessions.items() if value != user}
                        state.sessions[token] = user
                    self.respond(200, {"user": user, "role": USERS[user]},
                                 headers={"Set-Cookie": f"sandbox_session={token}; Secure; HttpOnly; SameSite=Strict; Path=/"})
            elif path in {"/payment", "/transfer"}:
                user = self.principal("finance")
                if not user:
                    return
                amount = data.get("amount")
                destination = "merchant" if path == "/payment" else data.get("to")
                if type(amount) is not int or amount <= 0 or not isinstance(destination, str) or destination not in state.balances or destination == user:
                    self.respond(400, {"error": "positive integer credits and a different known recipient required"})
                    return
                with state.lock:
                    if amount > state.balances[user]:
                        self.respond(409, {"error": "insufficient fictional credits"})
                        return
                    state.balances[user] -= amount
                    state.balances[destination] += amount
                    receipt = {"id": len(state.ledger) + 1, "from": user, "to": destination, "credits": amount}
                    state.ledger.append(receipt)
                self.respond(201, receipt)
            else:
                self.respond(404, {"error": "unknown sandbox endpoint"})

        def log_message(self, *_):
            pass

    return Handler
