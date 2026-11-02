"""Generate exact-host dnsmasq overrides using the providers' restricted endpoints."""
import argparse
import ipaddress
from pathlib import Path
import socket
import subprocess
import tempfile

TARGETS = {
    "forcesafesearch.google.com": ["google.com", "www.google.com", "google.co.id", "www.google.co.id"],
    "strict.bing.com": ["bing.com", "www.bing.com", "edgeservices.bing.com"],
    "restrict.youtube.com": ["www.youtube.com", "m.youtube.com",
                             "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"],
}


def render_safesearch():
    lines = ["# MiniFW v2.2.10: restricted Google/Bing/YouTube DNS; no TLS interception.",
             "# Re-generate when endpoint addresses change. Other domains are untouched.",
             "# Alternate/encrypted DNS, IPv6 and unlisted country domains need separate controls."]
    for target, aliases in TARGETS.items():
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)})
        if not addresses or any(not ipaddress.IPv4Address(address).is_global for address in addresses):
            raise ValueError(f"No public restricted endpoint addresses for {target}")
        for address in addresses:
            lines.append(f"host-record={target},{address}")
        for alias in aliases:
            lines.append(f"cname={alias},{target}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = render_safesearch()
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, prefix=".minifw-safesearch-", delete=False) as stream:
        stream.write(text)
        candidate = Path(stream.name)
    try:
        subprocess.run(["dnsmasq", "--test", "--conf-file=" + str(candidate)], check=True)
        candidate.replace(args.output)
    finally:
        candidate.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
