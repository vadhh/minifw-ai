"""Lab client: evenly spaced requests from one source address for a fixed time. Fictional sandbox traffic only.

new:       one new TCP (TLS) connection per tick to 198.18.0.2:443, GET /, close (attack-rate and poller cases).
keepalive: one TCP connection to 198.18.0.2:20000 for the whole run, one request line per tick. The sandbox
           HTTPS server speaks HTTP/1.0 and closes after each response, so 443 cannot carry a kept-alive session.
Usage: rate_client.py IP PERIOD_S DURATION_S OUT.jsonl new|keepalive [START_OFFSET_S]
"""
import http.client
import json
import socket
import ssl
import sys
import time

ip, period, duration, out, mode = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4], sys.argv[5]
assert mode in {'new', 'keepalive'}
context = ssl._create_unverified_context()  # Generated lab certificate only.
log = open(out, 'a', buffering=1)
held = None
time.sleep(float(sys.argv[6]) if len(sys.argv) > 6 else 0)  # Phase offset against the 5 s conntrack polls.
begin = time.time()
k = 0
while time.time() < begin + duration:
    row = dict(ip=ip, mode=mode, k=k, start=time.time(), port=None, status=None, error=None)
    try:
        if mode == 'keepalive':
            if held is None:
                held = socket.create_connection(('198.18.0.2', 20000), timeout=2, source_address=(ip, 0))
                row['new_connection'] = True
            held.sendall(b'GET /health HTTP/1.1\r\nHost: lab.test\r\n\r\n')
            row.update(port=held.getsockname()[1], status='sent')
        else:
            connection = http.client.HTTPSConnection('198.18.0.2', 443, context=context, timeout=2, source_address=(ip, 0))
            try:
                connection.connect()
                row['port'] = connection.sock.getsockname()[1]
                connection.request('GET', '/')
                response = connection.getresponse()
                response.read()
                row['status'] = response.status
            finally:
                connection.close()
    except OSError as error:
        row['error'] = type(error).__name__
        if held is not None:
            held.close()
            held = None
    row['end'] = time.time()
    log.write(json.dumps(row) + '\n')
    k += 1
    time.sleep(max(0, begin + k * period - time.time()))
