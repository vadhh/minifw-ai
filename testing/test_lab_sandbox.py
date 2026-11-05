"""Sandbox state changes and authorization through its actual TLS HTTP interface."""

import http.client
import json
import ssl
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from lab_sandbox import SANDBOX_PASSWORD, SandboxState, handler_for


@pytest.fixture
def sandbox(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=lab.test", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    state = SandboxState()
    handler = handler_for(state, Path(__file__).parent / "fixtures/lesson.webm")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    def request(method, path, data=None, cookie="", headers=None):
        client = http.client.HTTPSConnection("127.0.0.1", server.server_port,
                                            context=ssl._create_unverified_context(), timeout=3)
        fields = dict(headers or {})
        if cookie:
            fields["Cookie"] = cookie
        client.request(method, path, json.dumps(data).encode() if data is not None else None, fields)
        response = client.getresponse()
        body = response.read()
        result = response.status, response.getheader("Set-Cookie", "").split(";", 1)[0], body
        client.close()
        return result

    yield request, state
    server.shutdown()
    server.server_close()
    worker.join(timeout=2)


def login(request, user):
    status, cookie, _ = request("POST", "/login", {"username": user, "password": SANDBOX_PASSWORD})
    assert status == 200 and cookie
    return cookie


def test_payments_transfers_and_rejected_overdraft_preserve_credits(sandbox):
    request, state = sandbox
    assert request("GET", "/api/account")[0] == 401
    alice = login(request, "alice")
    assert request("POST", "/payment", {"amount": 1250}, alice)[0] == 201
    assert request("POST", "/transfer", {"to": "bob", "amount": 2500}, alice)[0] == 201
    before = dict(state.balances)
    assert request("POST", "/transfer", {"to": "bob", "amount": 999999999}, alice)[0] == 409
    assert state.balances == before == {"alice": 96250, "bob": 52500, "merchant": 1250}
    assert sum(state.balances.values()) == 150000 and len(state.ledger) == 2
    assert b"alice,96250,2" in request("GET", "/documents/statement.csv", cookie=alice)[2]


@pytest.mark.parametrize("payload", [{"amount": -1}, {"amount": True}, {"amount": 1.5},
                                      {"amount": 100, "to": []}])
def test_invalid_transfer_inputs_do_not_change_balances(sandbox, payload):
    request, state = sandbox
    cookie = login(request, "alice")
    payload = {"to": "bob", **payload}
    assert request("POST", "/transfer", payload, cookie)[0] == 400
    assert state.balances["alice"] == 100000 and not state.ledger


def test_staff_role_and_learning_media_ranges(sandbox):
    request, _ = sandbox
    student = login(request, "student")
    assert request("GET", "/staff", cookie=student)[0] == 403
    staff = login(request, "staff")
    assert request("GET", "/staff", cookie=staff)[0] == 200
    assert b"<video" in request("GET", "/lessons/intro")[2]
    assert json.loads(request("GET", "/search?q=fractions")[2])["results"]
    part = request("GET", "/media/lesson.webm", headers={"Range": "bytes=0-1023"})
    assert part[0] == 206 and len(part[2]) == 1024 and part[2][:4] == bytes.fromhex("1a45dfa3")
    assert request("GET", "/media/lesson.webm", headers={"Range": "bytes=-100"})[0] == 416
