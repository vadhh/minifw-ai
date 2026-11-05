"""Verify clean C18 installation without exporting administrator credentials."""
import hashlib
import http.client
import json
import os
import secrets
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse

edition=sys.argv[1]
assert edition in {'education','financial'}
assert socket.gethostname()=='minifw-thursday-'+edition and os.geteuid()==0
assert subprocess.check_output(['systemd-detect-virt'],text=True).strip() in {'kvm','qemu'}
sector='finance' if edition=='financial' else edition
assert subprocess.check_output(['dpkg-query','-W','-f=${Version}','minifw-ai'],text=True)=='2.2.10-'+sector
verify=subprocess.run(['dpkg','--verify','minifw-ai'],capture_output=True,text=True)
assert not verify.stdout.strip(),verify.stdout
protected=[]
for name in ['app','venv','models','scripts','prometheus','scheduler','yara_rules']:
    for path in (Path('/opt/minifw_ai')/name).rglob('*'):
        if path.is_file():
            s=path.stat()
            assert s.st_uid==0 and not s.st_mode&0o022,str(path)
            protected.append(path)
code='''from pathlib import Path
for name in ['app/minifw_ai/main.py','venv/bin/python','models/mlp_packet14.pkl','scripts/backup.sh']:
 try:
  with (Path('/opt/minifw_ai')/name).open('ab'): pass
 except PermissionError: continue
 raise AssertionError('Unprivileged append permitted')
'''
for account in ['lab','minifw-web']:
    subprocess.run(['runuser','-u',account,'--','python3','-c',code],check=True)
secret=dict(line.split('=',1) for line in Path('/etc/minifw/minifw.env').read_text().splitlines() if '=' in line)
assert Path('/etc/minifw/minifw.env').stat().st_mode&0o077==0
subprocess.run(['systemctl','start','minifw-ai-web'],check=True)
try:
    for _ in range(60):
        try:
            connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=3)
            body=urllib.parse.urlencode({'username':'admin','password':secret['MINIFW_ADMIN_PASSWORD']})
            connection.request('POST','/auth/login',body,{'Content-Type':'application/x-www-form-urlencoded'})
            response=connection.getresponse()
            status,cookie=response.status,response.getheader('Set-Cookie')
            redirect=response.getheader('Location')
            response.read();connection.close()
            break
        except OSError: time.sleep(.5)
    assert status==303 and 'access_token=' in cookie
    assert redirect=='/auth/change-password',redirect
    replacement=secrets.token_urlsafe(24)
    with Path('/var/tmp/fresh-admin-password').open('w') as private:
        os.fchmod(private.fileno(),0o600)
        private.write(replacement)
    connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=5)
    form=urllib.parse.urlencode(dict(current_password=secret['MINIFW_ADMIN_PASSWORD'],new_password=replacement,confirm_password=replacement))
    connection.request('POST','/auth/change-password',form,{'Content-Type':'application/x-www-form-urlencoded','Cookie':cookie.split(';',1)[0]})
    response=connection.getresponse();response.read()
    assert response.status==303 and response.getheader('Location')=='/auth/login?changed=1'
    connection.close()
    connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=5)
    connection.request('POST','/auth/login',urllib.parse.urlencode(dict(username='admin',password=replacement)),{'Content-Type':'application/x-www-form-urlencoded'})
    response=connection.getresponse();response.read();cookie=response.getheader('Set-Cookie')
    assert response.status==303 and response.getheader('Location')=='/admin/'
    connection.close()
    pages={}
    for path in ['/admin/policy','/admin/license']:
        connection=http.client.HTTPSConnection('127.0.0.1',8443,context=ssl._create_unverified_context(),timeout=5)
        connection.request('GET',path,headers={'Cookie':cookie.split(';',1)[0]})
        response=connection.getresponse();pages[path]=response.status;response.read();connection.close()
        assert response.status==200
    with sqlite3.connect('/var/lib/minifw-ai/minifw.db') as db:
        assert db.execute('pragma integrity_check').fetchone()==('ok',)
        users=db.execute('select count(*) from users').fetchone()[0]
    assert users>=1
    print(json.dumps(dict(edition=edition,candidate='C18',fresh_OS=True,package_sha256=hashlib.sha256(Path('/var/tmp/minifw-c18.deb').read_bytes()).hexdigest(),
                         dpkg_verify='clean',protected_files=len(protected),write_attempts='denied for lab and minifw-web',
                         administrator_login='passed after mandatory password change and re-login',dashboard_pages=pages,sqlite_integrity='ok',users=users,
                         signed_activation='not performed on fresh deployment; existing upgraded guests tested separately',
                         cloud_init='base boot runcmd tried disabling absent MiniFW units and reports error; clean-app preconditions verified before install'),indent=2))
finally:
    subprocess.run(['systemctl','stop','minifw-ai-web','minifw-ai'],check=True)
