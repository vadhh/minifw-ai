"""Create two disposable clean Debian overlays for the C19 fresh-install check on the authorised Sydeco lab host."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess

assert socket.gethostname() == 'sydeco-desktop'
base = Path('/home/sydeco/vms/minifw-v229-installer-test/debian-12-genericcloud-amd64.qcow2')
root = Path('/home/sydeco/vms/minifw-c19fresh-20261105')
root.mkdir()  # Never overwrite an existing experiment.
original = Path('/home/sydeco/vms/minifw-monday-20261102/education/user-data').read_text()
manifest = dict(base=str(base), base_sha256=hashlib.sha256(base.read_bytes()).hexdigest(), guests=[])
for edition, port, suffix in [('education', 23222, '13'), ('financial', 23223, '14')]:
    folder = root/edition
    folder.mkdir()
    name = 'minifw-c19fresh-'+edition
    (folder/'user-data').write_text(original.replace('minifw-monday-education', name))
    (folder/'meta-data').write_text(f'instance-id: minifw-c19fresh-20261105-{edition}\nlocal-hostname: {name}\n')
    subprocess.run(['cloud-localds', str(folder/'seed.iso'), str(folder/'user-data'), str(folder/'meta-data')], check=True)
    subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(folder/'disk.qcow2')], check=True)
    subprocess.run(['qemu-img', 'resize', str(folder/'disk.qcow2'), '20G'], check=True)
    command = ['qemu-system-x86_64', '-name', name, '-enable-kvm', '-cpu', 'host', '-m', '2048', '-smp', '2',
               '-drive', f'file={folder}/disk.qcow2,if=virtio,format=qcow2',
               '-drive', f'file={folder}/seed.iso,media=cdrom,readonly=on',
               '-netdev', f'user,id=mgmt,net=10.231.0.0/24,hostfwd=tcp:127.0.0.1:{port}-:22',
               '-device', f'virtio-net-pci,netdev=mgmt,mac=52:54:00:22:20:{suffix}',
               '-display', 'none', '-serial', f'file:{folder}/serial.log',
               '-pidfile', str(folder/'qemu.pid'), '-daemonize']
    subprocess.run(command,check=True)
    manifest['guests'].append(dict(edition=edition,hostname=name,port=port,pid=int((folder/'qemu.pid').read_text())))
(root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
