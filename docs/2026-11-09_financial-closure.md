# MiniFW-AI Financial v2.2.13: closure statement

Monday 9 November 2026 · Afridho · status at 10:10 WIB

**The software handoff is complete. The package has been sent; delivery stays open until the signed receipt is returned.**

| Item | State |
| --- | --- |
| Delivery | Sent Friday 6 November, 16:43 WIB, within the end-of-day deadline, to Patrick; signed receipt outstanding |
| Customer installation | Not started |
| AI isolation | Off, as approved |
| Signing control | Applied 9 November |
| Credential containment | Complete. A GitHub cache purge is requested (optional) |

Every open item has one owner, Afridho. Ilham returns to RISKIPSO at 11:00.

## 1. Four separate states

| State | Status | Evidence | Next and owner |
| --- | --- | --- | --- |
| **Software handoff** | **Complete.** C22, v2.2.13, source `50058d10`, installer `6192bdd7…92c9`, model `d06ce40e…d6ee`. No code change since the freeze. | 6 Nov recommendation; reviewer's package check (zip hash, `SHA256SUMS`, installer version, model and policy match) | None |
| **Delivery** | **Sent, receipt outstanding.** Package `minifw-ai-financial-2.2.13-handoff.zip`, SHA-256 `9d14ffc34af95e09db95c7d680ddc54d6cd5686fea4ec2954a06b6974544900d`. Sent 6 November 2026, 16:43 WIB, to Patrick, through the vendor's private file share (sydecloud). The SHA-256 was **not** sent separately. The 6 November report was committed at 16:30, before the send, so it still recorded the package as unsent. | Afridho's sent record | Afridho: send the zip's SHA-256 to Patrick through a second channel, so the download can be checked (`SHA256SUMS` inside the zip cannot vouch for the zip itself). Then collect the signed receipt page. |
| **Customer installation** | **Not started.** It waits for the customer. | None yet | The customer installs and sends the deployment ID privately; Afridho signs the licence (section 4) |
| **AI activation** | **Off at handover, as approved.** Management approved handover with the connection-rate AI in shadow mode and rule blocks on (6 Nov, 14:37 WIB; confirmed 9 Nov). | Handover document, "State at handover" | After a shadow period of a few days, the customer's security owner approves isolation and records the approval (setup guide, sections 14–15). The first isolation is checked for its 15-minute expiry. |

## 2. Independent DNS-outage check: closed

- On 9 November, the original logs of the tester's final DNS-outage run were read from the tester's guest. Every step is confirmed:
  - candidate 2.2.13-finance, with the delivered model;
  - AI enforcement on throughout, in one engine process;
  - no DNS query for six minutes;
  - fallback to baseline 110 s after the last query;
  - in baseline, AI paused at up to 59 connections a minute while a port scan was still blocked;
  - return to AI-enhanced 61 s after DNS came back;
  - AI isolation again after that.
- One correction to the tester's report: the post-recovery AI block was at count 39, not 40.
- The release notes' summary stands. The package is unchanged.
- Evidence: `docs/evidence/2026-11-09-financial-closure/`.

## 3. Licence signing restricted

- **Decision (9 Nov):** Afridho is the only authorized signer.
- **Finding:** until now, signing needed only access to the host account that holds the vendor key. At least one other engineer had that access and used it for lab licences.
- **Control:** the vendor key is encrypted with a passphrase held only by the authorized signer. The signing tool now takes that passphrase (`scripts/license_tool.py`, with a test). The procedure was dry-run on 9 November with a throwaway key.
- **Status: applied 9 November.** The vendor key on the signing host is now passphrase-encrypted, and the plaintext copy is deleted. Before the deletion, the encrypted key signed a test licence that verified against the packaged public key. A search of the signing account found no other copy: its only other private keys are unrelated RSA keys.
- **No key rotation.** The delivered 2.2.13 trusts the current key, and rotating it would need a new build. The other engineer is asked to confirm holding no copy.

## 4. Customer licence: private procedure

1. The customer reads the deployment ID from the dashboard's License page and sends it privately. A deployment ID posted in a public ticket, chat channel or repository is not used.
2. The authorized signer issues a licence for that deployment ID and product mode `minifw_financial` only.
3. The licence is verified against the packaged public key before it is sent.
4. It is returned through the same private channel.
5. A private register records the licence ID, customer, deployment, dates and channel. Licences and IDs never go to GitHub.

## 5. Exposed lab credentials: contained by invalidation

- **What was exposed.** Two lab test guests' initial dashboard admin passwords. They were in independent-test evidence pushed to a public branch on 6 November.
- **Removal is not containment.** Both commits were removed from the branches, but GitHub still serves them by commit ID. Containment therefore rests on the passwords no longer working:

| Guest | Status (checked 9 Nov) |
| --- | --- |
| C21 test guest | Destroyed. Its directory and process are gone. |
| C22 test guest | Its admin password was changed nine minutes after installation, before the exposure (audit log). Its dashboard listened only inside the guest. Destroyed on 9 November, after its evidence was extracted; its process and directory are gone. |

- **Nothing else live was exposed.** A scan of everything still public in those commits found no application secret key, private key, licence signature or session token.
- **No reuse.** Each installation generates its own random initial password, so it cannot repeat across installs. The tester is asked to confirm that the passwords set on the guests are not used elsewhere.
- **Issue #8 history cleaned (9 November).** The original revisions of the three redacted comments held infrastructure details, not passwords. They are deleted, and no remaining revision holds those details.
- **GitHub cache purge requested** on 9 November (support ticket #4974713, open). GitHub removes data only when rotating the credentials cannot remove the risk. These credentials no longer work, so Support may decline. Containment does not depend on the purge.
- **Rule from 6 November, unchanged:** test evidence goes to the release owner privately, never to the repository.

## 6. Site inputs still needed

| # | Input | From | Needed for |
| --- | --- | --- | --- |
| 1 | Signed receipt page | Customer recipient | Delivery record |
| 2 | Deployment ID, sent privately | Customer gateway administrator | Licence |
| 3 | Network segments and subnets | Customer network team | Replace the example subnets (setup guide, section 11) |
| 4 | DNS on the gateway: dnsmasq resolves for the protected clients | Customer network team | AI-enhanced protection |
| 5 | Exempt list: servers, monitoring and polling systems, proxies, shared NAT addresses | Customer IT, from the shadow review | Before AI isolation is turned on |
| 6 | Approval to turn AI isolation on, with name and date | Customer security owner | AI activation |

The vendor contact for all six is Afridho.

## 7. Also recorded

- **Product naming.**
  - The 2.2.13 installer's package description still reads "MiniFW-AI gateway firewall engine (ARCHANGEL 2.0)". 2.2.13 is not rebuilt for this, since a rebuild would change the verified hashes and void the independent tests.
  - The build script is corrected in source (`scripts/build_deb.sh`). The fix takes effect in the next controlled build, which needs new checksums and verification.
- **Education must not be delivered unchanged.** Education v2.2.11 still has the packet-rate defect fixed in C22. It is rebuilt from the C22 source, which includes the naming fix, before its delivery.
- **Minor defect, not fixed today.** A user's own password change does not update the "last password change" date. The audit log records the change correctly.

## 8. Handback

**Financial blocker owner from 11:00:** Afridho. The items are:
- the SHA-256 to Patrick by a second channel;
- the signed receipt;
- Ilham's two confirmations;
- following up the GitHub ticket.

None of them blocks Ilham from RISKIPSO. Afridho and Ilham resume RISKIPSO at 11:00.
