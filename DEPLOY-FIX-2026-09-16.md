# Deployment routing fix — 2026-09-16

## What was wrong

The License Server and Nginx were running, and `/api/license/api/health` returned `200 OK`.
However, the active VPS Nginx configuration did not route the root API namespace `/api/` to the
License Server, so `/api/health` returned `404 Not Found`. This broke components that use the
server-root API base (notably the Admin Panel health check).

## Correct routing

- `/api/license/*` -> `127.0.0.1:5077` with the `/api/license/` prefix stripped.
- `/api/admin/*` -> `127.0.0.1:5077` with the `/api/admin/` path preserved.
- `/api/*` -> `127.0.0.1:5077` with the `/api/` path preserved.
- `/api/control/*` -> `127.0.0.1:5078` with the `/api/control/` prefix stripped.

## Apply on VPS

From this project directory:

```bash
sudo ./deploy/apply-nginx-fix.sh
```

Then verify:

```bash
./deploy/verify-production-api.sh http://127.0.0.1
./deploy/verify-production-api.sh http://95.38.233.67
```
