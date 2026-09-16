# Surge.AdminPanel v19.4.1

WPF administrator console for the Surge License Server.

Environment variables on the server:
- `SURGE_ADMIN_USER`
- `SURGE_ADMIN_PASSWORD`
- `SURGE_LICENSE_SECRET`
- `SURGE_JWT_SECRET` (optional; generated and persisted when absent)
- `SURGE_BACKUP_PATH` (optional)

The panel authenticates with `/api/admin/login` and uses a short-lived signed administrator token. The old `X-Admin-Key` administration surface is no longer used.
