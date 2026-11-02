import socket, subprocess
name = socket.gethostname()
assert name in {"minifw-monday-financial", "minifw-monday-education"}
print(name)
print(subprocess.check_output(["dpkg-query", "-W", "-f=${Package} ${Version}\\n", "minifw-ai"], text=True).strip())
for service in ["minifw-ai", "minifw-ai-web", "dnsmasq"]:
    result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
    state = result.stdout.strip()
    print(service, state)
    assert state in ({"inactive"} if service != "dnsmasq" else {"inactive", "failed"})
namespaces = subprocess.check_output(["ip", "netns", "list"], text=True).strip()
print("NAMESPACES", repr(namespaces))
assert not namespaces
print("LAB_CLEANUP_VERIFIED; dnsmasq failed state is not service readiness")
