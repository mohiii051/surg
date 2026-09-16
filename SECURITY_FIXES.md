# Surge v19.4.1 — security and architecture fixes

Files below replace their equivalents in the existing tree. Paths are relative to the repo root.

> **Not compiled.** These were written without a .NET SDK available. Run
> `dotnet build` on all four projects and fix any signature drift before shipping. The logic and
> the reasoning are the deliverable; the compiler is still the authority on syntax.

---

## 1. Security and network

### `Surge.LicenseServer/Program.cs`
- **TLS is now enforced, not optional.** The old default binding was `http://0.0.0.0:5077` — every
  password, bearer token and licence key crossed the network in clear text. The server now supports
  Kestrel-terminated TLS (`SURGE_TLS_CERT_PATH` / PEM pair, `SslProtocols.Tls12 | Tls13`) or a
  reverse proxy (`SURGE_BEHIND_PROXY=true`), and **refuses to start** if asked to serve plain HTTP
  on a public interface. HSTS and HTTPS redirection are enabled when Kestrel owns the certificate.
- **`UseForwardedHeaders` with an explicit trusted-proxy list.** Without it, every request behind
  nginx is attributed to `127.0.0.1` and the per-IP rate limiter degenerates into one global bucket
  that any single client can exhaust for everyone.
- **Security headers** (`nosniff`, `DENY`, `no-referrer`, `no-store`) and request-size limits.

### `Services/AuthApiClient.cs` · `Surge.AdminPanel/MainWindow.xaml.cs`
- **Production API endpoint is HTTP deployment.** Windows clients default to `http://95.38.233.67/` and use `http://95.38.233.67/` in Release builds; `SURGE_API_URL` is honored only in Debug builds. A bare IP could never be
  covered by a certificate, so the connection was unauthenticatable in principle, and moving the
  VPS meant reshipping the binary.
- **Plain HTTP is permitted** unless the host is loopback, so an attacker who can set an environment
  variable cannot downgrade the client and harvest tokens. TLS 1.2 floor, strict chain/hostname validation, and no certificate-validation override anywhere. Revocation
  checking is disabled because the chosen short-lived IP certificate profile does not provide a useful
  online revocation path.

### `Surge.LicenseServer/Services/TokenRevocationService.cs` (new) + refresh endpoint
- **Refresh-token rotation with reuse detection.** Each token carries a public `Jti` prefix and a
  `FamilyId` shared across one login chain. Redeeming a token burns its JTI; presenting a burned
  JTI means the token exists in two places, so **the entire family is revoked** — logging out both
  the thief and the victim, which is the signal the victim needs.
- The in-memory list is a cache in front of the durable `Revoked` / `UsedUtc` columns, so a process
  restart cannot be used to slip a replayed token through. Entries expire automatically.
- **The reuse check and the rotation happen in one transaction.** Splitting them leaves a
  check-then-act race where two concurrent requests both observe a token as unused and both get a
  valid successor — defeating the whole mechanism.
- Tokens are bound to the device they were issued to, and families have a hard 60-day ceiling that
  rotation cannot extend.

### `Surge.LicenseServer/Services/SecurityService.cs`
- **Admin token lifetime 8 h → 1 h.** An admin token can create licences, ban users and restart the
  server; eight hours left a stolen one usable for most of a working day.
- Secret files are written `0600` on Unix.

### `Surge.ServerControl/Program.cs`
- **Loopback-only, enforced twice.** The old `http://0.0.0.0:5078` default exposed
  `systemctl start/stop/restart` to the internet. The service now refuses to start on a non-loopback
  binding *and* drops non-loopback connections at runtime.
- **Mandatory `X-Surge-Control-Secret`** (min 32 chars) on every request, constant-time compared, in
  addition to the admin bearer token. No insecure default — it will not start without one.
- `systemd` unit adds `IPAddressDeny=any` / `IPAddressAllow=localhost`.

---

## 2. Server architecture

### `Surge.LicenseServer/Services/StoreService.cs` — SQLite (WAL) replaces `store.json`
- Real schema with indexes on the columns actually queried (`users.email`, `devices.hw_hash`,
  `licenses.key_hash`, `refresh_tokens.family_id`, …).
- `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`, `foreign_keys=ON`.
- **Reads are lock-free and perform no I/O.** The service keeps one immutable snapshot, swapped
  atomically after each committed write. Every read previously took the global semaphore *and*
  re-read and re-parsed the entire JSON file.
- **Writes** apply to a private clone, diff against the snapshot fingerprint, and commit only the
  changed rows inside one `BEGIN IMMEDIATE` transaction. The old `Save()` rewrote the whole file and
  copied it — a crash mid-write could truncate the entire dataset.
- The semaphore that gated *I/O* is gone. A short write gate remains, held only for the duration of
  a transaction; SQLite permits exactly one writer regardless, and the diff needs a current
  snapshot at commit time. Calling that "removed" would be a lie — it is a different and much
  smaller thing than what was there.
- Automatic one-time import of an existing `store.json`, backups via `VACUUM INTO`, restore via
  `BackupDatabase` with a pre-restore safety copy, path-traversal guard on restore filenames.

### `Surge.LicenseServer/Services/RateLimitService.cs` · `ChallengeService.cs` (new)
- Both static dictionaries replaced with `IMemoryCache` entries carrying absolute expiration and a
  `SizeLimit`. The rate limiter previously allocated a counter per IP+path **forever**; the
  challenge dictionary only removed an entry if the matching attestation actually arrived, so every
  abandoned nonce leaked permanently. Either was a free remote memory-exhaustion primitive.
- Striped locking makes check-and-increment atomic; without it a burst slips past the limit.
- Nonces are now single-use and consumed even on a failed comparison, so a live nonce cannot be
  held open for signature brute-forcing.

---

## 3. Client logic and performance

### `Services/HardwareFingerprintService.cs` — rewritten, no `powershell.exe`
- Five PowerShell processes per call, each a 300–800 ms cold start, on the UI thread during login —
  and `ReadToEnd()` was called *before* `WaitForExit(2500)`, so the timeout never actually bounded
  anything. Now native WMI, single-digit milliseconds, cached per process.
- Also closes a spoofing hole: shelling out meant anyone who could shim `powershell.exe` on `PATH`
  controlled the fingerprint.
- **Canonical hash format deliberately preserved.** See **`HWID_MIGRATION.md`** — this is the one
  change that needs a rollout plan.

### `Services/TweakVerifiers.cs` — `ProcessRunner`
- Fixed the **pipe deadlock**: stdout was drained to completion before stderr was touched, so any
  child that filled the ~4 KB stderr buffer blocked forever, and `WaitForExit()` had no timeout at
  all. Both streams are now drained concurrently by the runtime's reader threads, every wait is
  bounded, and a timed-out process tree is killed.
- **Two timeouts, not one.** `ProbeTimeoutMs = 2500` for read-only verification (the UI-freeze
  path). `ApplyTimeoutMs = 30000` for writes. Capping `bcdedit /set`, `powercfg /hibernate off` or
  `sc stop` at 2.5 s would kill them mid-flight and leave the machine in neither the tweaked nor
  the original state, with a backup snapshot no longer matching reality. `TweakEngine.Execute` and
  `BackupEngine`'s restore paths use the longer budget.
- `MainWindow.CreateRestorePoint_Click` had the same deadlock; fixed with a 90 s budget, since VSS
  snapshots are legitimately slow.

### `Services/BackupEngine.cs` — DPAPI
- `MachineId` was `SHA256(MachineName + "|" + UserName)` and a mismatch threw. **Renaming the PC
  made every existing backup permanently unrestorable** — users could no longer revert tweaks
  already applied to their systems.
- Now derived from the registry `MachineGuid` (written once at Windows install) and the account
  **SID** (stable across account renames, unlike the display name). More importantly, **a mismatch
  is no longer fatal**: DPAPI `CurrentUser` has already proved ownership before the field is read.
  Mismatched snapshots are re-stamped and restored.
- Real DPAPI entropy added — a **fixed application constant**, deliberately *not* machine-derived.
  Entropy exists to stop another program running as the same user from reading these blobs; seeding
  it from anything mutable would reintroduce the exact bug being fixed. Old null-entropy files are
  detected, decrypted and transparently re-saved.

---

## 4. Error handling and deployment

- **`Services/ErrorReporter.cs` (new)** — one place where an exception becomes something a user
  sees. Release builds show `Message` (plus inner messages, which carry the useful part) and never
  `StackTrace`. Full detail still goes to the tamper-evident local log. Stack traces in a
  `MessageBox` handed anyone triggering an error a free map of the licensing and anti-tamper
  internals. `MainWindow`, `App`, `OperationLogWindow` and the Admin Panel all route through it.
- **Versions unified.** Current binaries report `19.4.1`; historical `v19.2` references remain only in migration documentation. Current runtime version values read
  `Assembly.GetExecutingAssembly().GetName().Version`; `.csproj` is the single source of truth
  (now `19.4.1`). Release builds keep a portable PDB, since support can no longer read a stack
  trace off the user's screen.
- **`GetAwaiter().GetResult()` removed from startup.** Blocking the WPF dispatcher on a task whose
  continuations post back to that same dispatcher is a textbook deadlock; even when it survived, it
  froze the app for the full HTTP timeout whenever the server was slow. The login window now shows
  first and the version check runs off-thread, marshalling back via `Dispatcher.InvokeAsync`.

---

## Explicitly unchanged

**The 30-second offline grace period is exactly as it was.** It is now the named constant
`MainWindow.OfflineGracePeriod` with a comment stating it must not be raised, so nobody
"tidies" it later. Anti-crack strictness is otherwise tightened, not relaxed: device-bound refresh
tokens, single-use nonces, shorter admin sessions, atomic reuse detection.

---

## Deployment checklist

1. `dotnet restore` — `Microsoft.Data.Sqlite` (server) and `System.Management` (client) are new.
2. Generate and set `SURGE_CONTROL_SECRET` (≥32 chars) in **both** service environments.
3. Set `SURGE_JWT_SECRET`, `SURGE_LICENSE_SECRET`, `SURGE_ADMIN_PASSWORD`. `chmod 600` the env files.
4. Provision TLS: reverse proxy (`SURGE_BEHIND_PROXY=true` + `SURGE_TRUSTED_PROXIES`) or a
   certificate. **The server will not start on public plain HTTP.**
5. Keep production clients pointed at `http://95.38.233.67/`; use `SURGE_API_URL` only for controlled staging/local development.
6. **Back up `store.json` before first start.** It is imported into `store.db` and renamed to
   `store.json.migrated`. Verify user, licence and device counts against the admin overview before
   deleting anything.
7. Set `SURGE_HWID_REBIND_UNTIL_UTC` per `HWID_MIGRATION.md`.
8. Verify: `/api/health` over TLS; port 5078 unreachable from outside the host; a stale refresh
   token returns 401 and writes `Refresh Token Reuse Detected` to the audit log.
