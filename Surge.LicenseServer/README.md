# Surge License Server v19.4.1

Security changes:
- Admin authentication uses signed bearer sessions from `/api/admin/login`; the legacy `X-Admin-Key` surface is removed.
- User accounts can be disabled and disabled accounts cannot login, refresh, or access license state.
- License lookup uses HMAC-SHA256 with `SURGE_LICENSE_SECRET`; legacy SHA-256 records can be migrated on first successful activation.
- One license binds to one account and one hardware fingerprint/device.
- Devices are blocked/released only by administrators.
- Admin mutations are audited with administrator, action, target, timestamp and source IP.
- Authentication, activation and admin endpoints are rate limited in-process.
- Store writes are atomic and timestamped backups are retained under `/opt/surge/backups` by default.
- Daily backup runs automatically.
- `/api/version/check` supports forced client updates.

Set all secrets before production. Put the service behind HTTPS/reverse proxy and restrict port 5077 to the intended network.
