# Surge v19.4.1 — Release status

This archive is the cleaned Release Candidate source tree derived only from `Surge-v19.4.1-RELEASE-CANDIDATE.zip`.

## Completed in this cleanup
- Removed the user-facing implication that Sign Out releases a device or HWID.
- Reworked all Admin Panel DataGrid cell rendering to explicit `DataGridTemplateColumn` + `TextBlock` bindings.
- Kept DataGrid headers on the correct `DataGridColumnHeader` style.
- Locked production Windows binaries to `http://95.38.233.67/`; `SURGE_API_URL` is honored only in Debug builds.
- Removed the misleading “proxy-free” Admin Panel status text.
- Cleaned current-version documentation to 19.4.1 and retained only intentional legacy migration references.
- Added `RELEASE-VERIFICATION-CHECKLIST.md` for the Windows/VPS runtime checks.
- Added `deploy/preflight-production.sh` to validate Nginx config, secret-file permissions, shared control secret, systemd units, and loopback-only 5077/5078 listeners.
- Removed build artefact directories from the source archive.

## Not claimable from this environment
The source is not declared fully Release Ready until these are run on the real Windows PC/VPS:
- .NET 8 build and publish with zero errors.
- Client and Admin Panel startup.
- Admin Grid runtime verification with populated data and zero WPF binding errors.
- Real HTTPS certificate issuance/trust on `95.38.233.67`.
- Nginx reverse proxy and certificate renewal test.
- PC1/PC2 Account and License/HWID matrix.
- Authenticode signing.
