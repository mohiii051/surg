# Surge v19.4.1 — Release & Deployment

**Status: NOT verified as Release Ready.** The code in this archive has been reviewed and fixed,
but it has never been compiled or executed — see [Verification status](#verification-status)
before shipping anything.

---

## 1. Architecture

```
                    Internet
                       │
                       ▼
          ┌─────────────────────────┐
          │  nginx   :80  :443      │   :80 = ACME http-01 only
          │  (only public listener) │   :443 = TLS, proxies /api/ →
          └─────────────────────────┘
                       │ 127.0.0.1
                       ▼
          ┌─────────────────────────┐
          │ Surge.LicenseServer     │  127.0.0.1:5077   user: surge
          │  · auth + refresh       │  SQLite @ /opt/surge/data/store.db
          │  · devices + licences   │
          │  · admin API            │
          │  · /api/admin/control/* ├──┐ proxies with X-Surge-Control-Secret
          └─────────────────────────┘  │
                                       ▼
                          ┌─────────────────────────┐
                          │ Surge.ServerControl     │ 127.0.0.1:5078
                          │  sudo systemctl {start,  │ user: surge-control
                          │  stop,restart} license   │
                          └─────────────────────────┘
```

| Component | Project | Runs on | Binding |
|---|---|---|---|
| Client | `SurgeApp.csproj` | Windows, net8.0-windows | — |
| Admin Panel | `Surge.AdminPanel` | Windows, net8.0-windows | — |
| License Server | `Surge.LicenseServer` | Linux, net8.0 | `127.0.0.1:5077` |
| Server Control | `Surge.ServerControl` | Linux, net8.0 | `127.0.0.1:5078` |

Public endpoint: **`http://95.38.233.67/`** — no domain name is used.
Ports `5077` and `5078` are never public. Each service refuses at startup to bind a
non-loopback address, so the firewall is a second control, not the only one.

---

## 2. Windows build & publish

Requires the .NET 8 SDK pinned by `global.json` (8.0.425 or a later 8.0.x feature band).

```bat
Publish-Surge-v19.4.1.cmd      REM Client + Admin Panel  -> publish\client, publish\admin
Publish-Server-Linux.cmd       REM Server + Control      -> publish\server, publish\control
```

Or by hand:

```bat
dotnet publish SurgeApp.csproj -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true -p:Deterministic=true ^
  -p:ContinuousIntegrationBuild=true -o publish\client

dotnet publish Surge.AdminPanel\Surge.AdminPanel.csproj -c Release -r win-x64 ^
  --self-contained true -p:PublishSingleFile=true -p:Deterministic=true ^
  -p:ContinuousIntegrationBuild=true -o publish\admin

dotnet publish Surge.LicenseServer\Surge.LicenseServer.csproj -c Release -r linux-x64 ^
  --self-contained false -p:Deterministic=true -o publish\server

dotnet publish Surge.ServerControl\Surge.ServerControl.csproj -c Release -r linux-x64 ^
  --self-contained false -p:Deterministic=true -o publish\control
```

### Code signing

The published EXEs are **unsigned**. Nothing in this repository signs them and nothing claims
they are signed. Sign these two, in this order, after publish:

- `publish\client\Surge.exe`
- `publish\admin\Surge.AdminPanel.exe`

The Linux DLLs are not Authenticode targets and are not signed.

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /f surge-codesign.pfx /p <password> publish\client\Surge.exe
signtool verify /pa /v publish\client\Surge.exe
```

Single-file publish embeds the payload inside the host EXE, so sign **after** publish, never
before. An OV or EV certificate from a CA in the Windows Trusted Root program is required;
without one, users will see a SmartScreen warning, and no amount of configuration removes it.

---

## 3. VPS deployment

### 3.1 Users, directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin surge
sudo useradd --system --no-create-home --shell /usr/sbin/nologin surge-control

sudo install -d -o surge -g surge -m 750 /opt/surge/server /opt/surge/data /opt/surge/backups
sudo install -d -o surge-control -g surge-control -m 750 /opt/surge/control
sudo install -d -o www-data -g www-data -m 755 /var/www/certbot

# The control service verifies admin tokens against token.secret, read-only.
sudo usermod -aG surge surge-control
sudo chmod 750 /opt/surge/data
```

Copy `publish/server/*` → `/opt/surge/server/`, `publish/control/*` → `/opt/surge/control/`.

### 3.2 Secrets

Nothing in this archive contains a real secret. Generate all five on the VPS:

```bash
umask 077
{
  echo "SURGE_ADMIN_USER=$(openssl rand -hex 8)"
  echo "SURGE_ADMIN_PASSWORD=$(openssl rand -base64 48)"
  echo "SURGE_JWT_SECRET=$(openssl rand -base64 48)"
  echo "SURGE_LICENSE_SECRET=$(openssl rand -base64 48)"
  echo "SURGE_CONTROL_SECRET=$(openssl rand -base64 48)"
} | sudo tee /opt/surge/server/surge.env >/dev/null
sudo chown surge:surge /opt/surge/server/surge.env && sudo chmod 600 /opt/surge/server/surge.env

# SURGE_CONTROL_SECRET and SURGE_ADMIN_USER must match on both sides.
sudo grep -E '^SURGE_CONTROL_SECRET=' /opt/surge/server/surge.env \
  | sudo tee /opt/surge/control/control.env >/dev/null
sudo grep -E '^SURGE_ADMIN_USER=' /opt/surge/server/surge.env \
  | sudo tee -a /opt/surge/control/control.env >/dev/null
sudo chown surge-control:surge-control /opt/surge/control/control.env
sudo chmod 600 /opt/surge/control/control.env
```

`SURGE_ADMIN_USER` is also hard-set in `surge-server-control.service` as `admin`; change that
line to match, or move it into `control.env` and delete it from the unit.

### 3.3 TLS certificate (Let's Encrypt, IP address)

Verified constraints, not guesses:

- IP-address certificates are issued **only** under the `shortlived` profile, valid ~160 hours
  (just over six days).
- **DNS-01 cannot be used.** Only `http-01` and `tls-alpn-01` validate an IP. nginx owns :443,
  so `http-01` over **:80 is mandatory** — port 80 is not optional here.
- Certbot **5.4 or later** is required for `--webroot` with `--ip-address`. (`--ip-address`
  arrived in 5.3 but only for `standalone`/`manual`; `--preferred-profile` exists since 4.0.)
- Certbot can obtain the certificate but **cannot install it into nginx** — the nginx installer
  plugin does not support IP addresses. Paths are set by hand once, and a deploy hook reloads
  nginx after each renewal.
- No purchased certificate is needed, and none is recommended. A publicly trusted IP certificate
  is available at no cost through the path below.

```bash
sudo snap install --classic certbot   # snap tracks current; apt is usually far behind
certbot --version                     # must be >= 5.4.0

# Staging first. Do not skip this: LE rate limits are unforgiving.
sudo certbot certonly --staging \
  --preferred-profile shortlived \
  --webroot --webroot-path /var/www/certbot \
  --ip-address 95.38.233.67 \
  --agree-tos -m you@example.com --non-interactive

# Once clean, reissue against production:
sudo certbot delete --cert-name 95.38.233.67
sudo certbot certonly \
  --preferred-profile shortlived \
  --webroot --webroot-path /var/www/certbot \
  --ip-address 95.38.233.67 \
  --agree-tos -m you@example.com --non-interactive
```

Renewal automation:

```bash
sudo install -m 0755 deploy/certbot-deploy-hook.sh \
  /etc/letsencrypt/renewal-hooks/deploy/surge-nginx.sh
sudo cp deploy/surge-cert-renew.service deploy/surge-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now surge-cert-renew.timer

# The distro certbot timer is sized for 90-day certs; ours must not fight it.
sudo systemctl disable --now certbot.timer snap.certbot.renew.timer 2>/dev/null || true

sudo systemctl list-timers surge-cert-renew.timer
sudo certbot renew --dry-run
```

The hook validates the certificate parses, that the key matches it, that the cert actually
covers `95.38.233.67`, and that `nginx -t` passes — and only then reloads. Any failure aborts
without touching the running server.

### 3.4 nginx

```bash
sudo cp deploy/nginx-surge.conf /etc/nginx/sites-available/surge
sudo ln -sf /etc/nginx/sites-available/surge /etc/nginx/sites-enabled/surge
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

### 3.5 Services

```bash
sudo cp surge-license.service surge-server-control.service /etc/systemd/system/
sudo install -m 0440 -o root -g root deploy/sudoers-surge-control /etc/sudoers.d/surge-control
sudo visudo -c                       # must report "parsed OK"
sudo systemctl daemon-reload
sudo systemctl enable --now surge-license.service surge-server-control.service
sudo systemctl status surge-license.service --no-pager
```

`surge-control` holds exactly three sudo rights — `start`, `stop`, `restart` on
`surge-license.service`. No wildcards, no `daemon-reload`, no other unit, no other binary.

### 3.6 Firewall

```bash
sudo bash deploy/ufw-surge.sh
```

Open: `22`, `80` (ACME, required), `443`. Closed: everything else, including `5077` and `5078`.

Verify from a **different** host:

```bash
curl -sS http://95.38.233.67/api/health          # {"ok":true,...}
nc -vz -w3 95.38.233.67 5077                      # must be refused/filtered
nc -vz -w3 95.38.233.67 5078                      # must be refused/filtered
```

### 3.7 Environment variable reference

| Variable | Where | Meaning |
|---|---|---|
| `SURGE_LICENSE_URL` | server unit | Must stay loopback (`http://127.0.0.1:5077`) |
| `SURGE_BEHIND_PROXY` | server unit | `true` — trust `X-Forwarded-*` from listed proxies |
| `SURGE_TRUSTED_PROXIES` | server unit | `127.0.0.1;::1` |
| `SURGE_DATA_PATH` | both units | `/opt/surge/data` |
| `SURGE_BACKUP_PATH` | server unit | `/opt/surge/backups` |
| `SURGE_CONTROL_INTERNAL_URL` | server unit | `http://127.0.0.1:5078/` |
| `SURGE_CONTROL_URL` | control unit | `http://127.0.0.1:5078` |
| `SURGE_ADMIN_USER` / `SURGE_ADMIN_PASSWORD` | `surge.env` | Admin credentials; no default exists |
| `SURGE_JWT_SECRET` | `surge.env` | Token signing key |
| `SURGE_LICENSE_SECRET` | `surge.env` | Licence-key HMAC key |
| `SURGE_CONTROL_SECRET` | both env files | ≥32 chars, identical on both sides |
| `SURGE_LATEST_VERSION` | optional | Defaults to the server assembly version |
| `SURGE_MINIMUM_VERSION` | optional | Client builds below this are refused at startup |
| `SURGE_FORCE_UPDATE` | optional | `true` blocks startup until the user updates |
| `SURGE_UPDATE_URL` | optional | Shown to the user; nothing is downloaded automatically |
| `SURGE_HWID_REBIND_UNTIL_UTC` | optional | Temporary HWID rebind window; see `HWID_MIGRATION.md` |
| `SURGE_API_URL` | Windows Debug builds | Optional staging/local override; ignored by Release builds |

Directories: data `/opt/surge/data` · backups `/opt/surge/backups` ·
certificates `/etc/letsencrypt/live/95.38.233.67/` ·
renewal hook `/etc/letsencrypt/renewal-hooks/deploy/surge-nginx.sh`.

---

## 4. Backup & restore

Daily automatic backups run in-process (`StoreService.RunDailyBackupAsync`) into
`SURGE_BACKUP_PATH`, using SQLite `VACUUM INTO` so the copy is consistent under concurrent
writes. Manual backups come from the Admin Panel → Backup tab.

Restore takes a **pre-restore snapshot first** (`store-pre-restore-<timestamp>.db`), so a
mistaken restore is itself reversible. Filenames are constrained to a bare filename inside the
backup directory — `Path.GetFileName(fileName) != fileName` rejects any traversal attempt.

```bash
sudo ls -lh /opt/surge/backups
sudo -u surge sqlite3 /opt/surge/backups/<file>.db "PRAGMA integrity_check;"
```

The database runs `journal_mode=WAL` with `synchronous=FULL`. FULL, not NORMAL: under
WAL+NORMAL a hard reset can discard recently committed transactions, which for this store means
a paid activation silently vanishing or a revoked licence returning to life.

---

## 5. PC1 / PC2 acceptance test

The business rule is **1 Account = 1 PC** and **1 Licence = 1 PC**, enforced server-side only.
Run this against a staging server with two genuinely different machines — a VM clone will share
hardware identifiers and will not exercise the rule honestly.

| # | Action | Expected |
|---|---|---|
| 1 | Register account A on PC1 | 200, session created |
| 2 | Activate licence L on PC1 | 200, licence locked to PC1 |
| 3 | Re-launch and sign in again on PC1 | 200 |
| 4 | Sign in as account A on PC2 | **409** `account_bound_other_device` |
| 5 | Register account B on PC1 | **409** `device_bound_other_account` |
| 6 | Sign in as account B on PC1 | **409** `device_bound_other_account` |
| 7 | Copy PC1's `device-identity` blob onto PC2, sign in as A | **409** `hardware_mismatch` |
| 8 | Activate licence L on PC2 | **409**/400, licence stays on PC1 |
| 9 | Sign out on PC1, sign in on PC2 | **409** — sign-out never unlocks |
| 10 | Uninstall on PC1, sign in on PC2 | **409** — uninstall never unlocks |
| 11 | Admin → Devices → Release HWID, then sign in on PC2 | 200 — only an admin can move a binding |
| 12 | Admin blocks PC1's device, sign in on PC1 | **403** `device_blocked` |

Steps 4–10 must **not** return an access token or create a refresh-token family. Check:

```bash
sudo -u surge sqlite3 /opt/surge/data/store.db \
  "SELECT user_id, device_id, revoked FROM refresh_tokens ORDER BY created_utc DESC LIMIT 5;"
```

---

## 6. Verification status

The following were checked by static analysis in this pass:

- All five Admin Panel DataGrids declare real columns (parsed from the XAML, not assumed).
- Every DataGrid column binding path resolves to a public property on its DTO record.
- All XAML files are well-formed.
- Modified C# files are brace/paren balanced.
- No hardcoded credentials, tokens, dev bypasses or `IsDevelopment` branches remain.
- No stale current-version references remain outside deliberately historical migration documentation; all current binaries/projects are `19.4.1`.

The following are **UNVERIFIED** — they could not be exercised in the environment this pass ran
in (no .NET SDK, no network, no Windows, no VPS):

- `dotnet build` / `dotnet publish` success
- Client, Admin Panel, Server or Control actually starting
- Any runtime behaviour, including the PC1/PC2 matrix in §5
- Certificate issuance, nginx reload, systemd startup, firewall state
- That the Admin grids render populated rows on screen

Do not treat any item in §5 as passing until it has been run.
