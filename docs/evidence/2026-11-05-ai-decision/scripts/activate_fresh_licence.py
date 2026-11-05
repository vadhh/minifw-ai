"""Activate a vendor-signed lab licence on a fresh C19 guest through the dashboard (same checks as the C19 Monday run).

Licence file: /var/tmp/c19fresh-license.json. Admin password: the one set by verify_c19_fresh_install.py
(/var/tmp/fresh-admin-password, 0600). Neither is printed.
"""
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

edition = sys.argv[1]
assert socket.gethostname() == 'minifw-c19fresh-' + edition
mode = 'minifw_school' if edition == 'education' else 'minifw_financial'
licence = Path('/var/tmp/c19fresh-license.json').read_bytes()
payload = json.loads(licence)['payload']
assert payload['deployment_id'] == Path('/var/lib/minifw-ai/installation-id').read_text().strip()
assert payload['product_mode'] == mode
cookie = ''


def call(method, path, data=None, form=False, raw=None, content_type=None):
    connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=ssl._create_unverified_context(), timeout=10)
    headers = {'Origin': 'https://127.0.0.1:8443'}
    if cookie:
        headers['Cookie'] = cookie
    body = raw
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        body = urllib.parse.urlencode(data) if form else json.dumps(data)
    if content_type:
        headers['Content-Type'] = content_type
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, response.getheader('Set-Cookie'), response.read()
    connection.close()
    return result


def wait_web():
    for _ in range(100):
        try:
            if call('GET', '/auth/login')[0] in {200, 303}:
                return
        except OSError:
            pass
        time.sleep(.2)
    raise AssertionError('dashboard did not start')


def upload(raw):
    boundary = 'minifw-c19fresh-license-upload'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="license_file"; filename="license.json"\r\n'
            'Content-Type: application/json\r\n\r\n').encode() + raw + f'\r\n--{boundary}--\r\n'.encode()
    status, _, data = call('POST', '/admin/api/license', raw=body, content_type='multipart/form-data; boundary=' + boundary)
    return status, json.loads(data)


subprocess.run(['systemctl', 'start', 'minifw-ai-web'], check=True)
try:
    wait_web()
    password = Path('/var/tmp/fresh-admin-password').read_text().strip()
    status, token, _ = call('POST', '/auth/login', {'username': 'admin', 'password': password}, form=True)
    assert status == 303 and 'access_token=' in token, status
    cookie = token.split(';', 1)[0]
    before = call('GET', '/admin/license')
    status, activation = upload(licence)
    assert status == 200 and activation['license']['status'] == 'valid', (status, activation)
    installed = Path('/var/lib/minifw-ai/license.json').read_bytes()
    tampered = json.loads(licence)
    tampered['payload']['customer_id'] += '-tampered'
    rejected, _ = upload(json.dumps(tampered).encode())
    assert rejected == 400 and Path('/var/lib/minifw-ai/license.json').read_bytes() == installed
    subprocess.run(['systemctl', 'restart', 'minifw-ai-web'], check=True)
    wait_web()
    page = call('GET', '/admin/license')
    assert page[0] == 200 and b'<strong>Valid</strong>' in page[2], page[0]
    print(json.dumps(dict(edition=edition, candidate='C19', fresh_OS=True, licence=activation['license'],
                          licence_page_before_upload_http=before[0], tampered_upload_http=rejected,
                          persists_after_web_restart=True, scope='fresh lab guest, actual vendor signature'), indent=2))
finally:
    subprocess.run(['systemctl', 'stop', 'minifw-ai-web'])
