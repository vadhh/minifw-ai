# Annual deployment licenses

MiniFW verifies licenses offline with Ed25519. A license is bound to one
deployment UUID and one product mode. The web admin page at **Administration →
License** shows the deployment ID and accepts a renewal JSON file. Firewall
enforcement does not depend on license status and continues after expiry.

## Signing key setup

Generate the vendor keypair on a trusted issuing workstation:

```sh
python3 scripts/license_tool.py keygen \
  --key-id vendor-2026 \
  --private-key /secure/minifw-license-ed25519.pem \
  --keyring config/license_public_keys.json
```

Keep the private key offline and backed up securely. Only the public keyring is
included in the Debian package. Package builds copy it to
`/opt/minifw_ai/config/license_public_keys.json`; configure the vendor keyring
before building customer packages.

## Issue and install a license

Copy the deployment ID from the customer's License page, then issue a signed
file for the package product mode (for example `minifw_school` or
`minifw_financial`):

```sh
python3 scripts/license_tool.py issue \
  --private-key /secure/minifw-license-ed25519.pem \
  --key-id vendor-2026 \
  --customer-id customer-123 \
  --deployment-id 00000000-0000-0000-0000-000000000000 \
  --product-mode minifw_school \
  --output customer-123-license.json
```

The default term is one calendar year from the start time. Pass `--expires-at` only
when issuing a nonstandard term.

Upload the resulting JSON file from the License page. The verifier allows a
fixed 14-day renewal grace period and rejects malformed signatures, unknown
signing keys, mismatched deployments, and mismatched product modes. Keep the
deployment ID file at `/var/lib/minifw-ai/installation-id` when rehosting; this
MVP does not attempt to prevent a host administrator from copying or changing
local files or the system clock.

The current implementation covers issuance, offline verification, renewal,
and status display. Issue one signed license per deployment. It does not
provide billing or a customer portal.

## Client handoff

1. Install the sector package built with the vendor public keyring.
2. The client admin opens `/admin/license` and sends the deployment ID and
   product mode to the vendor.
3. The vendor issues a signed license JSON file and sends that file to the
   client. Never send the private signing key.
4. The client admin uploads the JSON file on the License page and confirms the
   status and expiry date.

The deployment ID survives restarts. Preserve
`/var/lib/minifw-ai/installation-id` when rehosting if the client should retain
the same license binding.
