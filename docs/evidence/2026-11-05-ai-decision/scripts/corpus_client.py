"""Lab-only traffic client: logs every TLS connection it opens, so labels come from the actor itself.

human: paced page visits with think time, including typo and forgetful-user login failures (benign).
tool:  password guessing at tool speed, one new connection per guess (malicious).
slow:  password guessing at 4-8 s per guess, below simple rate limits (malicious).
"""
import http.client
import json
import math
import random
import ssl
import sys
import time

kind, ip, seed, count, offset, out, testing = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]), sys.argv[6], sys.argv[7]
sys.path.insert(0, testing)
from lab_sandbox import SANDBOX_PASSWORD  # Fictional sandbox credential only.

label = 'benign' if kind == 'human' else 'malicious'
rng = random.Random(seed)
context = ssl._create_unverified_context()  # Generated lab certificate only.
log = open(out, 'a', buffering=1)
GOOD = {'username': 'alice', 'password': SANDBOX_PASSWORD}


def call(method, path, body=None, attempt=None):
    connection = http.client.HTTPSConnection('198.18.0.2', 443, context=context, timeout=5, source_address=(ip, 0))
    row = dict(kind=kind, label=label, ip=ip, port=None, method=method, path=path.split('?')[0], status=None, bytes=None,
               guess=attempt, start=time.time(), end=None, error=None)
    try:
        connection.connect()
        row['port'] = connection.sock.getsockname()[1]
        connection.request(method, path, json.dumps(body) if body is not None else None,
                           {'Content-Type': 'application/json'} if body is not None else {})
        response = connection.getresponse()
        data = response.read()
        row.update(status=response.status, bytes=len(data))
    except OSError as error:
        row['error'] = type(error).__name__
    finally:
        connection.close()
        row['end'] = time.time()
        log.write(json.dumps(row) + '\n')


time.sleep(offset)
if kind == 'human':
    for _ in range(count):
        pick = rng.random()
        bad = {'username': 'alice', 'password': 'typo-' + str(rng.randrange(100))}
        if pick < .35:
            steps = [('GET', '/'), ('GET', '/lessons/intro')]
        elif pick < .6:
            steps = [('GET', '/search?q=' + rng.choice(['fractions', 'algebra', 'statement', 'transfer']))]
        elif pick < .8:
            steps = [('GET', '/lessons/intro'), ('GET', '/media/lesson.webm')]
        elif pick < .97:
            steps = [('POST', '/login', GOOD)] if rng.random() > .3 else [('POST', '/login', bad), 'pause', ('POST', '/login', GOOD)]
        else:
            steps = [('POST', '/login', bad), 'pause', ('POST', '/login', bad), 'pause', ('POST', '/login', bad), 'pause', ('POST', '/login', GOOD)]
        for step in steps:
            if step == 'pause':
                time.sleep(rng.uniform(3, 9))  # A person retyping a password.
            else:
                call(*step)
                time.sleep(rng.uniform(.05, .3))
        time.sleep(min(30, max(1, rng.lognormvariate(math.log(5), .8))))  # Reading time between visits.
else:
    for attempt in range(count):
        call('POST', '/login', {'username': 'alice', 'password': f'guess-{seed}-{attempt}'}, attempt)
        time.sleep(rng.uniform(.09, .16) if kind == 'tool' else rng.uniform(4, 8))
