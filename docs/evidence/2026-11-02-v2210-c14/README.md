# C14 v2.2.10 candidate evidence — superseded, retained as a failure

C14 = `885ccf43392270906565746253a5987ecb094bcc`: first build with the dashboard running as the unprivileged `minifw-web` user. **Do not use these packages.** After this build, automated security review found that root-run restore and postinst could follow symlinks the dashboard user can plant (fixed in `715114ab`, `532ecc21`), and the committed `build_deb.sh` had been mangled by partial staging (repaired in `cc51f0e9`). The source kit was built from the working tree, which was correct.

| Check | Education | Financial |
| --- | --- | --- |
| Package SHA256 | `f43f87c393c65a2eaabe08c37f831262ad425c6e069f4e74328719b5cd37754d` | `eac5a56af3ce1b0c0aecad52ac7e1465b418049dd8446d5143763592e0b7b53c` |
| Strict identity | [pass](education/identity.log) | [pass](financial/identity.log) |
| Debian suite | [613 passed](education/minifw-c14-tests.log) | (run once) |
| Feature and core runs | exit 0 | exit 0 |
| Extended run | **[failed](education/minifw-c14-extended.log)** | **[failed](financial/minifw-c14-extended.log)** |

What passed before the failure, in both editions: install with a non-root dashboard; readiness, including the three not-ready states; private backup/restore with the database at `/var/lib/minifw-ai/minifw.db`; and the web process at uid 105 with `CapBnd=0` and `CapEff=0`. The failure: the new smoke test expected `/admin/` to return 200, but a fresh admin is correctly redirected to `/auth/change-password` (303). The test was wrong, not the product; the C15 smoke test performs the password change.
