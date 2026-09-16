using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Surge.LicenseServer.Models;

namespace Surge.LicenseServer.Services;

public sealed record BackupInfo(string FileName, DateTime CreatedUtc, long SizeBytes);

/// <summary>
/// SQLite-backed store (WAL journal mode).
///
/// Concurrency model:
///  * READS are completely lock-free and never touch the disk. The service owns a single
///    immutable in-memory snapshot that is swapped atomically after every committed write,
///    so <see cref="ReadAsync{T}"/> never blocks and never contends with a writer.
///  * WRITES are applied to a private deep clone, diffed against the snapshot fingerprint,
///    and committed inside one BEGIN IMMEDIATE transaction. Only rows that actually changed
///    are written. The write gate is held for the duration of the transaction only; it is
///    NOT a file-I/O gate, and SQLite itself permits exactly one writer at a time anyway.
/// </summary>
public sealed class StoreService : IDisposable
{
    private const int MaxAuditRows = 5000;

    private readonly string _dbPath;
    private readonly string _backupDir;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);

    private volatile Snapshot _snapshot = Snapshot.Empty;
    private long _version;
    private bool _disposed;

    public StoreService(IWebHostEnvironment env)
    {
        var configured = Environment.GetEnvironmentVariable("SURGE_DATA_PATH");
        var dir = !string.IsNullOrWhiteSpace(configured)
            ? configured
            : OperatingSystem.IsLinux()
                ? "/opt/surge/data"
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Surge", "LicenseServer");

        Directory.CreateDirectory(dir);
        _dbPath = Path.Combine(dir, "store.db");
        _backupDir = Environment.GetEnvironmentVariable("SURGE_BACKUP_PATH")
                     ?? (OperatingSystem.IsLinux() ? "/opt/surge/backups" : Path.Combine(dir, "backups"));
        Directory.CreateDirectory(_backupDir);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Default,
            Pooling = true,
            ForeignKeys = true,
            DefaultTimeout = 30
        }.ToString();

        InitialiseSchema();
        ImportLegacyJsonIfNeeded(dir, env);
        ReloadSnapshot();
    }

    // ---------------------------------------------------------------- public API

    /// <summary>Lock-free read against the current committed snapshot. Never performs I/O.</summary>
    public Task<T> ReadAsync<T>(Func<StoreRoot, T> selector) => Task.FromResult(selector(_snapshot.Root));

    /// <summary>Synchronous variant of <see cref="ReadAsync{T}"/> for non-async call sites.</summary>
    public T Read<T>(Func<StoreRoot, T> selector) => selector(_snapshot.Root);

    /// <summary>
    /// Applies <paramref name="action"/> to a private copy of the store. If it returns true the
    /// changes are diffed and committed in a single transaction; otherwise nothing is written.
    /// </summary>
    public async Task WriteAsync(Func<StoreRoot, bool> action, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var current = _snapshot;
            var working = Clone(current.Root);
            if (!action(working)) return;

            TrimAuditLogs(working);

            var after = Fingerprint.Build(working, _json);
            var plan = ChangePlan.Diff(current.Fingerprints, after);
            if (plan.IsEmpty)
            {
                // Nothing observable changed; still publish the working copy so object
                // identity stays consistent for callers that captured references.
                _snapshot = new Snapshot(Interlocked.Increment(ref _version), working, after);
                return;
            }

            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable, deferred: false);
            Commit(connection, transaction, working, plan);
            transaction.Commit();

            _snapshot = new Snapshot(Interlocked.Increment(ref _version), working, after);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async Task<BackupInfo> CreateBackupAsync(string reason = "manual", CancellationToken ct = default)
    {
        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var name = $"store-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{Sanitize(reason)}.db";
            var file = Path.Combine(_backupDir, name);
            VacuumInto(file);
            var info = new FileInfo(file);
            return new BackupInfo(info.Name, DateTime.UtcNow, info.Length);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public Task<IReadOnlyList<BackupInfo>> ListBackupsAsync()
    {
        var files = Directory.EnumerateFiles(_backupDir, "store-*.db")
            .Concat(Directory.EnumerateFiles(_backupDir, "store-*.json"))
            .Select(p => new FileInfo(p))
            .OrderByDescending(x => x.LastWriteTimeUtc)
            .Select(x => new BackupInfo(x.Name, x.LastWriteTimeUtc, x.Length))
            .ToList();
        return Task.FromResult<IReadOnlyList<BackupInfo>>(files);
    }

    public async Task<bool> RestoreBackupAsync(string fileName, CancellationToken ct = default)
    {
        // Path-traversal guard: only a bare file name inside the backup directory is accepted.
        if (string.IsNullOrWhiteSpace(fileName) || Path.GetFileName(fileName) != fileName) return false;

        var source = Path.Combine(_backupDir, fileName);
        var fullSource = Path.GetFullPath(source);
        if (!fullSource.StartsWith(Path.GetFullPath(_backupDir) + Path.DirectorySeparatorChar, StringComparison.Ordinal)) return false;
        if (!File.Exists(fullSource)) return false;

        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Safety copy of the live database before anything is overwritten.
            VacuumInto(Path.Combine(_backupDir, $"store-pre-restore-{DateTime.UtcNow:yyyyMMdd-HHmmssfff}.db"));

            if (fullSource.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                StoreRoot? restored;
                try { restored = JsonSerializer.Deserialize<StoreRoot>(File.ReadAllText(fullSource), _json); }
                catch { return false; }
                if (restored is null) return false;
                ReplaceAll(restored);
            }
            else
            {
                using var sourceConnection = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = fullSource,
                    Mode = SqliteOpenMode.ReadOnly,
                    Pooling = false
                }.ToString());
                sourceConnection.Open();

                // Validate the backup really is a Surge store before clobbering live data.
                using (var probe = sourceConnection.CreateCommand())
                {
                    probe.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users','devices','licenses','refresh_tokens','audit_logs')";
                    if (Convert.ToInt32(probe.ExecuteScalar(), CultureInfo.InvariantCulture) != 5) return false;
                }

                using var destination = OpenConnection();
                sourceConnection.BackupDatabase(destination);
            }

            ReloadSnapshot();
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async Task RunDailyBackupAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.UtcNow;
                var next = now.Date.AddDays(1).AddMinutes(5);
                await Task.Delay(next - now, ct).ConfigureAwait(false);
                await CreateBackupAsync("daily", ct).ConfigureAwait(false);
                await PruneBackupsAsync(30).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch { /* a failed nightly backup must never take the server down */ }
        }
    }

    public Task PruneBackupsAsync(int keep)
    {
        foreach (var file in Directory.EnumerateFiles(_backupDir, "store-*.db")
                     .Select(p => new FileInfo(p))
                     .OrderByDescending(x => x.LastWriteTimeUtc)
                     .Skip(Math.Max(1, keep)))
        {
            try { file.Delete(); } catch { /* ignore */ }
        }
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _writeGate.Dispose();
        SqliteConnection.ClearAllPools();
    }

    // ---------------------------------------------------------------- connection / schema

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = """
            PRAGMA journal_mode=WAL;
            -- FULL, not NORMAL. Under WAL+NORMAL a host power loss or hard reset can discard
            -- the most recently committed transactions. For a licence store that is a user
            -- whose activation silently disappears, or a revoked licence that comes back to
            -- life. Write volume here is a handful of transactions per login, so the extra
            -- fsync per commit is not a meaningful cost. Override with SURGE_SQLITE_SYNC
            -- only if a measured workload justifies it.
            PRAGMA synchronous=FULL;
            PRAGMA busy_timeout=10000;
            PRAGMA foreign_keys=ON;
            PRAGMA temp_store=MEMORY;
            """;
        pragma.ExecuteNonQuery();
        return connection;
    }

    private void InitialiseSchema()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                email           TEXT NOT NULL,
                password_salt   TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                created_utc     TEXT NOT NULL,
                active          INTEGER NOT NULL,
                disabled_utc    TEXT NULL,
                disabled_reason TEXT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(email);

            CREATE TABLE IF NOT EXISTS devices (
                id               TEXT PRIMARY KEY,
                user_id          TEXT NOT NULL,
                account_user_ids TEXT NOT NULL,
                display_name     TEXT NOT NULL,
                public_key       TEXT NOT NULL,
                hw_hash          TEXT NOT NULL,
                first_seen_utc   TEXT NOT NULL,
                last_seen_utc    TEXT NOT NULL,
                active           INTEGER NOT NULL,
                blocked          INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_devices_user ON devices(user_id);
            CREATE INDEX IF NOT EXISTS ix_devices_hw   ON devices(hw_hash);

            CREATE TABLE IF NOT EXISTS licenses (
                id               TEXT PRIMARY KEY,
                key_hash         TEXT NOT NULL,
                legacy_hash      TEXT NULL,
                key_masked       TEXT NOT NULL,
                plan             TEXT NOT NULL,
                max_devices      INTEGER NOT NULL,
                owner_user_id    TEXT NULL,
                locked           INTEGER NOT NULL,
                locked_device_id TEXT NULL,
                hw_hash          TEXT NULL,
                locked_utc       TEXT NULL,
                banned           INTEGER NOT NULL,
                expires_utc      TEXT NULL,
                active_device_ids TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_licenses_keyhash ON licenses(key_hash);
            CREATE INDEX IF NOT EXISTS ix_licenses_owner   ON licenses(owner_user_id);

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                hash                 TEXT PRIMARY KEY,
                jti                  TEXT NOT NULL,
                family_id            TEXT NOT NULL,
                user_id              TEXT NOT NULL,
                device_id            TEXT NULL,
                created_utc          TEXT NOT NULL,
                expires_utc          TEXT NOT NULL,
                family_expires_utc   TEXT NOT NULL,
                revoked              INTEGER NOT NULL,
                used_utc             TEXT NULL,
                replaced_by_jti      TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_refresh_user   ON refresh_tokens(user_id);
            CREATE INDEX IF NOT EXISTS ix_refresh_family ON refresh_tokens(family_id);
            CREATE INDEX IF NOT EXISTS ix_refresh_jti    ON refresh_tokens(jti);

            CREATE TABLE IF NOT EXISTS audit_logs (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                id          TEXT NOT NULL UNIQUE,
                admin       TEXT NOT NULL,
                action      TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id   TEXT NOT NULL,
                ip          TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                metadata    TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs(created_utc);
            """;
        command.ExecuteNonQuery();
    }

    /// <summary>One-time migration from the legacy store.json layout.</summary>
    private void ImportLegacyJsonIfNeeded(string dir, IWebHostEnvironment env)
    {
        using (var connection = OpenConnection())
        using (var probe = connection.CreateCommand())
        {
            probe.CommandText = "SELECT (SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM licenses) + (SELECT COUNT(*) FROM devices)";
            if (Convert.ToInt64(probe.ExecuteScalar(), CultureInfo.InvariantCulture) > 0) return;
        }

        foreach (var candidate in new[]
                 {
                     Path.Combine(dir, "store.json"),
                     Path.Combine(dir, "store.backup.json"),
                     Path.Combine(env.ContentRootPath, "Data", "store.json")
                 })
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                var legacy = JsonSerializer.Deserialize<StoreRoot>(File.ReadAllText(candidate), _json);
                if (legacy is null) continue;

                // Legacy refresh records predate JTI/family tracking: synthesise identifiers so
                // reuse detection works for tokens issued before the upgrade.
                foreach (var token in legacy.RefreshTokens)
                {
                    if (string.IsNullOrWhiteSpace(token.Jti)) token.Jti = token.Hash;
                    if (string.IsNullOrWhiteSpace(token.FamilyId)) token.FamilyId = Guid.NewGuid().ToString("N");
                    if (token.CreatedUtc == default) token.CreatedUtc = DateTime.UtcNow;
                    if (token.FamilyExpiresUtc == default) token.FamilyExpiresUtc = token.ExpiresUtc;
                }

                ReplaceAll(legacy);
                try { File.Move(candidate, candidate + ".migrated", true); } catch { /* ignore */ }
                return;
            }
            catch { /* try the next candidate */ }
        }
    }

    private void ReplaceAll(StoreRoot root)
    {
        using var connection = OpenConnection();
        using var transaction = connection.BeginTransaction(System.Data.IsolationLevel.Serializable, deferred: false);

        foreach (var table in new[] { "users", "devices", "licenses", "refresh_tokens", "audit_logs" })
        {
            using var wipe = connection.CreateCommand();
            wipe.Transaction = transaction;
            wipe.CommandText = $"DELETE FROM {table}";
            wipe.ExecuteNonQuery();
        }

        TrimAuditLogs(root);
        foreach (var u in root.Users) UpsertUser(connection, transaction, u);
        foreach (var d in root.Devices) UpsertDevice(connection, transaction, d);
        foreach (var l in root.Licenses) UpsertLicense(connection, transaction, l);
        foreach (var r in root.RefreshTokens) UpsertRefresh(connection, transaction, r);
        foreach (var a in root.AuditLogs) UpsertAudit(connection, transaction, a);

        transaction.Commit();
    }

    private void VacuumInto(string destination)
    {
        if (File.Exists(destination)) File.Delete(destination);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "VACUUM INTO $target";
        command.Parameters.AddWithValue("$target", destination);
        command.ExecuteNonQuery();
    }

    // ---------------------------------------------------------------- snapshot loading

    private void ReloadSnapshot()
    {
        var root = LoadFromDatabase();
        _snapshot = new Snapshot(Interlocked.Increment(ref _version), root, Fingerprint.Build(root, _json));
    }

    private StoreRoot LoadFromDatabase()
    {
        var root = new StoreRoot();
        using var connection = OpenConnection();

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id, email, password_salt, password_hash, created_utc, active, disabled_utc, disabled_reason FROM users";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                root.Users.Add(new UserRecord
                {
                    Id = r.GetString(0),
                    Email = r.GetString(1),
                    PasswordSalt = r.GetString(2),
                    PasswordHash = r.GetString(3),
                    CreatedUtc = ReadDate(r.GetString(4)),
                    Active = r.GetInt64(5) != 0,
                    DisabledUtc = r.IsDBNull(6) ? null : ReadDate(r.GetString(6)),
                    DisabledReason = r.IsDBNull(7) ? null : r.GetString(7)
                });
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id, user_id, account_user_ids, display_name, public_key, hw_hash, first_seen_utc, last_seen_utc, active, blocked FROM devices";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                root.Devices.Add(new DeviceRecord
                {
                    Id = r.GetString(0),
                    UserId = r.GetString(1),
                    AccountUserIds = ReadList(r.GetString(2)),
                    DisplayName = r.GetString(3),
                    PublicKeyBase64 = r.GetString(4),
                    HardwareFingerprintHash = r.GetString(5),
                    FirstSeenUtc = ReadDate(r.GetString(6)),
                    LastSeenUtc = ReadDate(r.GetString(7)),
                    Active = r.GetInt64(8) != 0,
                    Blocked = r.GetInt64(9) != 0
                });
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id, key_hash, legacy_hash, key_masked, plan, max_devices, owner_user_id, locked, locked_device_id, hw_hash, locked_utc, banned, expires_utc, active_device_ids FROM licenses";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                root.Licenses.Add(new LicenseRecord
                {
                    Id = r.GetString(0),
                    KeyHash = r.GetString(1),
                    LegacySha256Hash = r.IsDBNull(2) ? null : r.GetString(2),
                    KeyMasked = r.GetString(3),
                    Plan = r.GetString(4),
                    MaxDevices = (int)r.GetInt64(5),
                    OwnerUserId = r.IsDBNull(6) ? null : r.GetString(6),
                    Locked = r.GetInt64(7) != 0,
                    LockedDeviceId = r.IsDBNull(8) ? null : r.GetString(8),
                    HardwareFingerprintHash = r.IsDBNull(9) ? null : r.GetString(9),
                    LockedUtc = r.IsDBNull(10) ? null : ReadDate(r.GetString(10)),
                    Banned = r.GetInt64(11) != 0,
                    ExpiresUtc = r.IsDBNull(12) ? null : ReadDate(r.GetString(12)),
                    ActiveDeviceIds = ReadList(r.GetString(13))
                });
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT hash, jti, family_id, user_id, device_id, created_utc, expires_utc, family_expires_utc, revoked, used_utc, replaced_by_jti FROM refresh_tokens";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                root.RefreshTokens.Add(new RefreshRecord
                {
                    Hash = r.GetString(0),
                    Jti = r.GetString(1),
                    FamilyId = r.GetString(2),
                    UserId = r.GetString(3),
                    DeviceId = r.IsDBNull(4) ? null : r.GetString(4),
                    CreatedUtc = ReadDate(r.GetString(5)),
                    ExpiresUtc = ReadDate(r.GetString(6)),
                    FamilyExpiresUtc = ReadDate(r.GetString(7)),
                    Revoked = r.GetInt64(8) != 0,
                    UsedUtc = r.IsDBNull(9) ? null : ReadDate(r.GetString(9)),
                    ReplacedByJti = r.IsDBNull(10) ? null : r.GetString(10)
                });
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = "SELECT id, admin, action, target_type, target_id, ip, created_utc, metadata FROM audit_logs ORDER BY seq";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                root.AuditLogs.Add(new AdminAuditRecord
                {
                    Id = r.GetString(0),
                    Admin = r.GetString(1),
                    Action = r.GetString(2),
                    TargetType = r.GetString(3),
                    TargetId = r.GetString(4),
                    IpAddress = r.GetString(5),
                    CreatedUtc = ReadDate(r.GetString(6)),
                    Metadata = r.IsDBNull(7) ? null : r.GetString(7)
                });
        }

        return root;
    }

    // ---------------------------------------------------------------- commit

    private void Commit(SqliteConnection connection, SqliteTransaction transaction, StoreRoot root, ChangePlan plan)
    {
        Delete(connection, transaction, "users", "id", plan.RemovedUsers);
        Delete(connection, transaction, "devices", "id", plan.RemovedDevices);
        Delete(connection, transaction, "licenses", "id", plan.RemovedLicenses);
        Delete(connection, transaction, "refresh_tokens", "hash", plan.RemovedRefreshTokens);
        Delete(connection, transaction, "audit_logs", "id", plan.RemovedAuditLogs);

        foreach (var u in root.Users.Where(x => plan.ChangedUsers.Contains(x.Id))) UpsertUser(connection, transaction, u);
        foreach (var d in root.Devices.Where(x => plan.ChangedDevices.Contains(x.Id))) UpsertDevice(connection, transaction, d);
        foreach (var l in root.Licenses.Where(x => plan.ChangedLicenses.Contains(x.Id))) UpsertLicense(connection, transaction, l);
        foreach (var t in root.RefreshTokens.Where(x => plan.ChangedRefreshTokens.Contains(x.Hash))) UpsertRefresh(connection, transaction, t);
        foreach (var a in root.AuditLogs.Where(x => plan.ChangedAuditLogs.Contains(x.Id))) UpsertAudit(connection, transaction, a);
    }

    private static void Delete(SqliteConnection connection, SqliteTransaction transaction, string table, string keyColumn, IReadOnlyCollection<string> keys)
    {
        if (keys.Count == 0) return;
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"DELETE FROM {table} WHERE {keyColumn} = $key";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$key";
        command.Parameters.Add(parameter);
        foreach (var key in keys)
        {
            parameter.Value = key;
            command.ExecuteNonQuery();
        }
    }

    private void UpsertUser(SqliteConnection c, SqliteTransaction t, UserRecord u)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = t;
        cmd.CommandText = """
            INSERT INTO users (id, email, password_salt, password_hash, created_utc, active, disabled_utc, disabled_reason)
            VALUES ($id, $email, $salt, $hash, $created, $active, $disabledUtc, $disabledReason)
            ON CONFLICT(id) DO UPDATE SET
                email=excluded.email, password_salt=excluded.password_salt, password_hash=excluded.password_hash,
                created_utc=excluded.created_utc, active=excluded.active,
                disabled_utc=excluded.disabled_utc, disabled_reason=excluded.disabled_reason
            """;
        cmd.Parameters.AddWithValue("$id", u.Id);
        cmd.Parameters.AddWithValue("$email", u.Email);
        cmd.Parameters.AddWithValue("$salt", u.PasswordSalt);
        cmd.Parameters.AddWithValue("$hash", u.PasswordHash);
        cmd.Parameters.AddWithValue("$created", WriteDate(u.CreatedUtc));
        cmd.Parameters.AddWithValue("$active", u.Active ? 1 : 0);
        cmd.Parameters.AddWithValue("$disabledUtc", WriteDate(u.DisabledUtc));
        cmd.Parameters.AddWithValue("$disabledReason", (object?)u.DisabledReason ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private void UpsertDevice(SqliteConnection c, SqliteTransaction t, DeviceRecord d)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = t;
        cmd.CommandText = """
            INSERT INTO devices (id, user_id, account_user_ids, display_name, public_key, hw_hash, first_seen_utc, last_seen_utc, active, blocked)
            VALUES ($id, $userId, $accounts, $name, $key, $hw, $first, $last, $active, $blocked)
            ON CONFLICT(id) DO UPDATE SET
                user_id=excluded.user_id, account_user_ids=excluded.account_user_ids, display_name=excluded.display_name,
                public_key=excluded.public_key, hw_hash=excluded.hw_hash, first_seen_utc=excluded.first_seen_utc,
                last_seen_utc=excluded.last_seen_utc, active=excluded.active, blocked=excluded.blocked
            """;
        cmd.Parameters.AddWithValue("$id", d.Id);
        cmd.Parameters.AddWithValue("$userId", d.UserId);
        cmd.Parameters.AddWithValue("$accounts", WriteList(d.AccountUserIds));
        cmd.Parameters.AddWithValue("$name", d.DisplayName);
        cmd.Parameters.AddWithValue("$key", d.PublicKeyBase64);
        cmd.Parameters.AddWithValue("$hw", d.HardwareFingerprintHash);
        cmd.Parameters.AddWithValue("$first", WriteDate(d.FirstSeenUtc));
        cmd.Parameters.AddWithValue("$last", WriteDate(d.LastSeenUtc));
        cmd.Parameters.AddWithValue("$active", d.Active ? 1 : 0);
        cmd.Parameters.AddWithValue("$blocked", d.Blocked ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    private void UpsertLicense(SqliteConnection c, SqliteTransaction t, LicenseRecord l)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = t;
        cmd.CommandText = """
            INSERT INTO licenses (id, key_hash, legacy_hash, key_masked, plan, max_devices, owner_user_id, locked,
                                  locked_device_id, hw_hash, locked_utc, banned, expires_utc, active_device_ids)
            VALUES ($id, $keyHash, $legacy, $masked, $plan, $max, $owner, $locked, $lockedDevice, $hw, $lockedUtc, $banned, $expires, $devices)
            ON CONFLICT(id) DO UPDATE SET
                key_hash=excluded.key_hash, legacy_hash=excluded.legacy_hash, key_masked=excluded.key_masked,
                plan=excluded.plan, max_devices=excluded.max_devices, owner_user_id=excluded.owner_user_id,
                locked=excluded.locked, locked_device_id=excluded.locked_device_id, hw_hash=excluded.hw_hash,
                locked_utc=excluded.locked_utc, banned=excluded.banned, expires_utc=excluded.expires_utc,
                active_device_ids=excluded.active_device_ids
            """;
        cmd.Parameters.AddWithValue("$id", l.Id);
        cmd.Parameters.AddWithValue("$keyHash", l.KeyHash);
        cmd.Parameters.AddWithValue("$legacy", (object?)l.LegacySha256Hash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$masked", l.KeyMasked);
        cmd.Parameters.AddWithValue("$plan", l.Plan);
        cmd.Parameters.AddWithValue("$max", l.MaxDevices);
        cmd.Parameters.AddWithValue("$owner", (object?)l.OwnerUserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$locked", l.Locked ? 1 : 0);
        cmd.Parameters.AddWithValue("$lockedDevice", (object?)l.LockedDeviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$hw", (object?)l.HardwareFingerprintHash ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$lockedUtc", WriteDate(l.LockedUtc));
        cmd.Parameters.AddWithValue("$banned", l.Banned ? 1 : 0);
        cmd.Parameters.AddWithValue("$expires", WriteDate(l.ExpiresUtc));
        cmd.Parameters.AddWithValue("$devices", WriteList(l.ActiveDeviceIds));
        cmd.ExecuteNonQuery();
    }

    private void UpsertRefresh(SqliteConnection c, SqliteTransaction t, RefreshRecord r)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = t;
        cmd.CommandText = """
            INSERT INTO refresh_tokens (hash, jti, family_id, user_id, device_id, created_utc, expires_utc, family_expires_utc, revoked, used_utc, replaced_by_jti)
            VALUES ($hash, $jti, $family, $user, $device, $created, $expires, $familyExpires, $revoked, $used, $replaced)
            ON CONFLICT(hash) DO UPDATE SET
                jti=excluded.jti, family_id=excluded.family_id, user_id=excluded.user_id, device_id=excluded.device_id,
                created_utc=excluded.created_utc, expires_utc=excluded.expires_utc, family_expires_utc=excluded.family_expires_utc,
                revoked=excluded.revoked, used_utc=excluded.used_utc, replaced_by_jti=excluded.replaced_by_jti
            """;
        cmd.Parameters.AddWithValue("$hash", r.Hash);
        cmd.Parameters.AddWithValue("$jti", r.Jti);
        cmd.Parameters.AddWithValue("$family", r.FamilyId);
        cmd.Parameters.AddWithValue("$user", r.UserId);
        cmd.Parameters.AddWithValue("$device", (object?)r.DeviceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", WriteDate(r.CreatedUtc));
        cmd.Parameters.AddWithValue("$expires", WriteDate(r.ExpiresUtc));
        cmd.Parameters.AddWithValue("$familyExpires", WriteDate(r.FamilyExpiresUtc));
        cmd.Parameters.AddWithValue("$revoked", r.Revoked ? 1 : 0);
        cmd.Parameters.AddWithValue("$used", WriteDate(r.UsedUtc));
        cmd.Parameters.AddWithValue("$replaced", (object?)r.ReplacedByJti ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private void UpsertAudit(SqliteConnection c, SqliteTransaction t, AdminAuditRecord a)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = t;
        cmd.CommandText = """
            INSERT INTO audit_logs (id, admin, action, target_type, target_id, ip, created_utc, metadata)
            VALUES ($id, $admin, $action, $targetType, $targetId, $ip, $created, $metadata)
            ON CONFLICT(id) DO UPDATE SET
                admin=excluded.admin, action=excluded.action, target_type=excluded.target_type,
                target_id=excluded.target_id, ip=excluded.ip, created_utc=excluded.created_utc, metadata=excluded.metadata
            """;
        cmd.Parameters.AddWithValue("$id", a.Id);
        cmd.Parameters.AddWithValue("$admin", a.Admin);
        cmd.Parameters.AddWithValue("$action", a.Action);
        cmd.Parameters.AddWithValue("$targetType", a.TargetType);
        cmd.Parameters.AddWithValue("$targetId", a.TargetId);
        cmd.Parameters.AddWithValue("$ip", a.IpAddress);
        cmd.Parameters.AddWithValue("$created", WriteDate(a.CreatedUtc));
        cmd.Parameters.AddWithValue("$metadata", (object?)a.Metadata ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    // ---------------------------------------------------------------- helpers

    private static void TrimAuditLogs(StoreRoot root)
    {
        if (root.AuditLogs.Count > MaxAuditRows)
            root.AuditLogs.RemoveRange(0, root.AuditLogs.Count - MaxAuditRows);
    }

    private StoreRoot Clone(StoreRoot source) =>
        JsonSerializer.Deserialize<StoreRoot>(JsonSerializer.SerializeToUtf8Bytes(source, _json), _json) ?? new StoreRoot();

    private static string WriteDate(DateTime value) =>
        DateTime.SpecifyKind(value, value.Kind == DateTimeKind.Unspecified ? DateTimeKind.Utc : value.Kind)
            .ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    private static object WriteDate(DateTime? value) => value is null ? DBNull.Value : WriteDate(value.Value);

    private static DateTime ReadDate(string value) =>
        DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();

    private static string WriteList(List<string> values) => JsonSerializer.Serialize(values);

    private static List<string> ReadList(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<string>();
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>(); }
        catch { return new List<string>(); }
    }

    private static string Sanitize(string value)
    {
        var clean = new string(value.Where(c => char.IsLetterOrDigit(c) || c == '-' || c == '_').ToArray());
        if (string.IsNullOrWhiteSpace(clean)) clean = "manual";
        return clean[..Math.Min(24, clean.Length)];
    }

    // ---------------------------------------------------------------- snapshot / diff types

    private sealed class Snapshot
    {
        public static readonly Snapshot Empty = new(0, new StoreRoot(), Fingerprint.Empty);

        public Snapshot(long version, StoreRoot root, Fingerprint fingerprints)
        {
            Version = version;
            Root = root;
            Fingerprints = fingerprints;
        }

        public long Version { get; }
        public StoreRoot Root { get; }
        public Fingerprint Fingerprints { get; }
    }

    /// <summary>Per-record serialized state, used to detect exactly which rows changed.</summary>
    private sealed class Fingerprint
    {
        public static readonly Fingerprint Empty = new(new(), new(), new(), new(), new());

        private Fingerprint(
            Dictionary<string, string> users,
            Dictionary<string, string> devices,
            Dictionary<string, string> licenses,
            Dictionary<string, string> refreshTokens,
            Dictionary<string, string> auditLogs)
        {
            Users = users; Devices = devices; Licenses = licenses; RefreshTokens = refreshTokens; AuditLogs = auditLogs;
        }

        public Dictionary<string, string> Users { get; }
        public Dictionary<string, string> Devices { get; }
        public Dictionary<string, string> Licenses { get; }
        public Dictionary<string, string> RefreshTokens { get; }
        public Dictionary<string, string> AuditLogs { get; }

        public static Fingerprint Build(StoreRoot root, JsonSerializerOptions json) => new(
            Index(root.Users, x => x.Id, json),
            Index(root.Devices, x => x.Id, json),
            Index(root.Licenses, x => x.Id, json),
            Index(root.RefreshTokens, x => x.Hash, json),
            Index(root.AuditLogs, x => x.Id, json));

        /// <summary>
        /// Last-write-wins indexing. ToDictionary would throw on a duplicate key, and a legacy
        /// store.json is not guaranteed to be free of them — a startup crash on import would be a
        /// far worse outcome than collapsing a duplicate, which the primary key would collapse
        /// anyway on the way into SQLite.
        /// </summary>
        private static Dictionary<string, string> Index<T>(IEnumerable<T> items, Func<T, string> key, JsonSerializerOptions json)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var item in items) result[key(item)] = JsonSerializer.Serialize(item, json);
            return result;
        }
    }

    private sealed class ChangePlan
    {
        public required HashSet<string> ChangedUsers { get; init; }
        public required HashSet<string> ChangedDevices { get; init; }
        public required HashSet<string> ChangedLicenses { get; init; }
        public required HashSet<string> ChangedRefreshTokens { get; init; }
        public required HashSet<string> ChangedAuditLogs { get; init; }
        public required List<string> RemovedUsers { get; init; }
        public required List<string> RemovedDevices { get; init; }
        public required List<string> RemovedLicenses { get; init; }
        public required List<string> RemovedRefreshTokens { get; init; }
        public required List<string> RemovedAuditLogs { get; init; }

        public bool IsEmpty =>
            ChangedUsers.Count == 0 && ChangedDevices.Count == 0 && ChangedLicenses.Count == 0 &&
            ChangedRefreshTokens.Count == 0 && ChangedAuditLogs.Count == 0 &&
            RemovedUsers.Count == 0 && RemovedDevices.Count == 0 && RemovedLicenses.Count == 0 &&
            RemovedRefreshTokens.Count == 0 && RemovedAuditLogs.Count == 0;

        public static ChangePlan Diff(Fingerprint before, Fingerprint after) => new()
        {
            ChangedUsers = Changed(before.Users, after.Users),
            ChangedDevices = Changed(before.Devices, after.Devices),
            ChangedLicenses = Changed(before.Licenses, after.Licenses),
            ChangedRefreshTokens = Changed(before.RefreshTokens, after.RefreshTokens),
            ChangedAuditLogs = Changed(before.AuditLogs, after.AuditLogs),
            RemovedUsers = Removed(before.Users, after.Users),
            RemovedDevices = Removed(before.Devices, after.Devices),
            RemovedLicenses = Removed(before.Licenses, after.Licenses),
            RemovedRefreshTokens = Removed(before.RefreshTokens, after.RefreshTokens),
            RemovedAuditLogs = Removed(before.AuditLogs, after.AuditLogs)
        };

        private static HashSet<string> Changed(Dictionary<string, string> before, Dictionary<string, string> after)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (key, value) in after)
                if (!before.TryGetValue(key, out var old) || !string.Equals(old, value, StringComparison.Ordinal))
                    result.Add(key);
            return result;
        }

        private static List<string> Removed(Dictionary<string, string> before, Dictionary<string, string> after)
        {
            var result = new List<string>();
            foreach (var key in before.Keys)
                if (!after.ContainsKey(key)) result.Add(key);
            return result;
        }
    }
}
