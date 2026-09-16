using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Surge.LicenseServer.Models;
using Surge.LicenseServer.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Transport security
// ---------------------------------------------------------------------------
// Three supported deployments, in order of preference:
//   1. TLS terminated by Kestrel        -> SURGE_TLS_CERT_PATH (+ password) or SURGE_TLS_CERT_PEM/KEY_PEM
//   2. TLS terminated by a reverse proxy -> SURGE_BEHIND_PROXY=true, bind loopback only
//   3. Local development                 -> loopback binding, plain HTTP
// Anything else (plain HTTP on a public interface) is refused at startup rather than
// silently shipping credentials and licence keys in clear text, which is what the old
// unconditional "http://0.0.0.0:5077" default did.

var behindProxy = IsTrue(Environment.GetEnvironmentVariable("SURGE_BEHIND_PROXY"));
var certificate = LoadServerCertificate();
var defaultUrl = certificate is not null ? "https://0.0.0.0:5077" : "http://127.0.0.1:5077";
var urls = (Environment.GetEnvironmentVariable("SURGE_LICENSE_URL") ?? defaultUrl)
    .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

ValidateBindings(urls, certificate is not null, behindProxy);
builder.WebHost.UseUrls(urls);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 256 * 1024;
    options.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(60);
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(20);

    options.ConfigureHttpsDefaults(https =>
    {
        // TLS 1.2 floor. SSL 3.0 / TLS 1.0 / TLS 1.1 are never negotiated.
        https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        https.ClientCertificateMode = ClientCertificateMode.NoCertificate;
        if (certificate is not null) https.ServerCertificate = certificate;
    });
});

builder.Services.AddSingleton<StoreService>();
builder.Services.AddSingleton<SecurityService>();
builder.Services.AddSingleton<RateLimitService>();
builder.Services.AddSingleton<ChallengeService>();
builder.Services.AddSingleton<TokenRevocationService>();
builder.Services.AddSingleton<AuditService>();
builder.Services.AddMemoryCache();

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    // Without this, every request behind nginx/Caddy is attributed to the proxy's IP and the
    // per-IP rate limiter collapses into a single global bucket.
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 2;
    options.KnownProxies.Clear();
    options.KnownNetworks.Clear();
    foreach (var entry in (Environment.GetEnvironmentVariable("SURGE_TRUSTED_PROXIES") ?? "127.0.0.1;::1")
             .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        if (IPAddress.TryParse(entry, out var ip)) options.KnownProxies.Add(ip);
    }
});

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

var serverVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Surge");

var backupTask = Task.Run(() => app.Services.GetRequiredService<StoreService>().RunDailyBackupAsync(app.Lifetime.ApplicationStopping));

// ---------------------------------------------------------------------------
// Server-control channel (Surge.ServerControl, loopback only)
// ---------------------------------------------------------------------------
var controlSecret = Environment.GetEnvironmentVariable("SURGE_CONTROL_SECRET");
var controlBaseUrl = Environment.GetEnvironmentVariable("SURGE_CONTROL_INTERNAL_URL") ?? "http://127.0.0.1:5078/";
if (!IsLoopbackUrl(controlBaseUrl))
    throw new InvalidOperationException($"SURGE_CONTROL_INTERNAL_URL must target loopback. Refusing to start with '{controlBaseUrl}'.");

var controlHttp = new HttpClient(new SocketsHttpHandler
{
    UseProxy = false,
    AllowAutoRedirect = false,
    ConnectTimeout = TimeSpan.FromSeconds(3)
})
{
    BaseAddress = new Uri(controlBaseUrl),
    Timeout = TimeSpan.FromSeconds(5)
};

async Task<IResult> ProxyControl(HttpRequest request, string path, HttpMethod method, SecurityService security)
{
    var (admin, err) = Admin(request, security);
    if (err is not null) return err;

    if (string.IsNullOrWhiteSpace(controlSecret))
        return Results.Json(new { message = "Server control is not configured. Set SURGE_CONTROL_SECRET on both services." }, statusCode: 503);

    using var req = new HttpRequestMessage(method, path);
    // The control service authenticates on the shared secret; the admin's bearer token is
    // forwarded only so the control service can re-verify the subject independently.
    req.Headers.TryAddWithoutValidation("X-Surge-Control-Secret", controlSecret);
    req.Headers.TryAddWithoutValidation("Authorization", request.Headers.Authorization.ToString());

    try
    {
        using var resp = await controlHttp.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();
        return Results.Content(body, resp.Content.Headers.ContentType?.ToString() ?? "application/json", Encoding.UTF8, (int)resp.StatusCode);
    }
    catch (Exception ex)
    {
        // Do not leak the internal exception text to an HTTP client.
        logger.LogWarning(ex, "Server control call failed for {Path}", path);
        return Results.Json(new { message = "Server control service unavailable." }, statusCode: 503);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static bool ValidEmail(string? email) => !string.IsNullOrWhiteSpace(email) && email.Length <= 254 && Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.None, TimeSpan.FromMilliseconds(250));
static bool ValidPassword(string? password) => password is { Length: >= 8 and <= 256 };
static IResult Unauthorized() => Results.Json(new { message = "Unauthorized." }, statusCode: 401);
static IResult Forbidden() => Results.Json(new { message = "Forbidden." }, statusCode: 403);
static IResult Bad(string message) => Results.Json(new { message }, statusCode: 400);
static string Ip(HttpRequest r) => r.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
static string NormalizeKey(string key) => key.Trim().ToUpperInvariant();

static bool SecureEquals(string? a, string? b)
{
    var left = Encoding.UTF8.GetBytes(a ?? "");
    var right = Encoding.UTF8.GetBytes(b ?? "");
    return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

static string Status(LicenseRecord l)
{
    if (l.Banned) return "Revoked";
    if (l.ExpiresUtc is not null && l.ExpiresUtc <= DateTime.UtcNow) return "Expired";
    return l.OwnerUserId is null ? "Available" : "Active";
}

static LicenseView LicenseDto(LicenseRecord l, string? deviceId = null) => new(
    l.Id, l.KeyMasked, l.Plan, 1, l.ActiveDeviceIds.Count,
    deviceId is not null && l.ActiveDeviceIds.Contains(deviceId),
    l.ExpiresUtc, l.OwnerUserId, Status(l));

string? CurrentUser(HttpRequest request, SecurityService security)
{
    var header = request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
    return security.TryValidateAccessToken(header[7..].Trim(), out var userId) ? userId : null;
}

async Task<string?> ActiveUser(HttpRequest request, StoreService store, SecurityService security)
{
    var id = CurrentUser(request, security);
    if (id is null) return null;
    return await store.ReadAsync(s => s.Users.FirstOrDefault(u => u.Id == id && u.Active)?.Id);
}

static (string? Admin, IResult? Error) Admin(HttpRequest request, SecurityService security)
{
    var header = request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || !security.TryValidateAdminToken(header[7..].Trim(), out var admin))
        return (null, Forbidden());
    var configured = Environment.GetEnvironmentVariable("SURGE_ADMIN_USER");
    if (string.IsNullOrWhiteSpace(configured) || !string.Equals(configured, admin, StringComparison.Ordinal)) return (null, Forbidden());
    return (admin, null);
}


// ---------------------------------------------------------------------------
// Account <-> device binding (1 Account = 1 PC), enforced BEFORE any token is issued
// ---------------------------------------------------------------------------
//
// Previously /api/auth/login verified the password and immediately minted an access token and a
// refresh-token family. Device identity travelled in the request (LoginRequest already carried
// DeviceId / DevicePublicKey / HardwareFingerprintHash) but was never checked: the only binding
// enforcement lived in /api/devices/register, which runs AFTER login has already succeeded.
//
// Two consequences:
//   * Account A could sign in from PC2, PC3, ... without limit. /api/devices/register only
//     rejects a PC owned by a DIFFERENT user, never a second PC for the same user.
//   * A rejected machine still received a valid access token and a live refresh family, which is
//     exactly what the rule is supposed to prevent.
//
// Both login and register now route through this one function so the two entry points cannot
// drift apart.
static (bool Ok, int Status, string Code, string Message) EvaluateBinding(
    StoreRoot store, string? userId, string? deviceId, string? publicKey, string? fingerprint)
{
    if (string.IsNullOrWhiteSpace(deviceId) || string.IsNullOrWhiteSpace(publicKey) || string.IsNullOrWhiteSpace(fingerprint))
        return (false, 400, "device_identity_required", "Device identity is required.");

    // 1. This physical PC already belongs to a different account.
    var byHardware = store.Devices.FirstOrDefault(d =>
        d.HardwareFingerprintHash == fingerprint && d.Active && !d.Blocked &&
        !string.IsNullOrWhiteSpace(d.UserId) && d.UserId != userId);
    if (byHardware is not null)
        return (false, 409, "device_bound_other_account", "This PC is already registered to another Surge account.");

    var byId = store.Devices.FirstOrDefault(d => d.Id == deviceId);
    if (byId is not null)
    {
        if (byId.Blocked)
            return (false, 403, "device_blocked", "This device has been blocked by an administrator.");

        // 2. A copied DeviceId presented from different hardware. The DeviceId is client-supplied
        //    and therefore never authoritative on its own.
        if (!string.IsNullOrWhiteSpace(byId.HardwareFingerprintHash) && byId.HardwareFingerprintHash != fingerprint)
            return (false, 409, "hardware_mismatch", "Device identity does not match this hardware.");

        // 3. A copied DeviceId presented with a different key pair.
        if (!string.IsNullOrWhiteSpace(byId.PublicKeyBase64) && byId.PublicKeyBase64 != publicKey)
            return (false, 409, "device_key_mismatch", "Device identity does not match this installation.");

        if (!string.IsNullOrWhiteSpace(byId.UserId) && byId.UserId != userId)
            return (false, 409, "device_bound_other_account", "This PC is already registered to another Surge account.");
    }

    // 4. 1 Account = 1 PC. An existing account may only sign in from the machine it is bound to.
    //    Released/blocked devices are excluded so an admin release genuinely frees the account.
    if (!string.IsNullOrWhiteSpace(userId))
    {
        var otherOwned = store.Devices.FirstOrDefault(d =>
            d.UserId == userId && d.Active && !d.Blocked && d.HardwareFingerprintHash != fingerprint);
        if (otherOwned is not null)
            return (false, 409, "account_bound_other_device", "This account is already activated on another PC. Contact support to move it.");
    }

    return (true, 200, "ok", "");
}

static IResult BindingRejection(int status, string code, string message) =>
    Results.Json(new { message, code }, statusCode: status);

/// <summary>
/// Issues the first refresh token of a new rotation family (login / register).
/// Rotation of an existing family happens inside the /api/auth/refresh transaction so that the
/// reuse check and the rotation cannot be separated by a concurrent request.
/// </summary>
async Task<string> IssueRefreshTokenAsync(StoreService store, SecurityService security, string userId, string? deviceId)
{
    var (token, jti) = security.NewRefreshToken();
    var now = DateTime.UtcNow;
    var familyEnd = now.Add(SecurityService.RefreshFamilyLifetime);
    var expires = now.Add(SecurityService.RefreshTokenLifetime);
    if (expires > familyEnd) expires = familyEnd;

    await store.WriteAsync(s =>
    {
        s.RefreshTokens.Add(new RefreshRecord
        {
            Hash = security.Hash(token),
            Jti = jti,
            FamilyId = Guid.NewGuid().ToString("N"),
            UserId = userId,
            DeviceId = string.IsNullOrWhiteSpace(deviceId) ? null : deviceId,
            CreatedUtc = now,
            ExpiresUtc = expires,
            FamilyExpiresUtc = familyEnd,
            Revoked = false
        });

        PruneRefreshTokens(s, now);
        return true;
    });

    return token;
}

/// <summary>
/// Drops rows that expired more than a day ago. They can never be redeemed, and the in-memory
/// revocation list already covers the reuse-detection window, so keeping them only grows the
/// table and the per-write snapshot diff.
/// </summary>
static void PruneRefreshTokens(StoreRoot store, DateTime now)
{
    var cutoff = now.AddDays(-1);
    store.RefreshTokens.RemoveAll(r => r.ExpiresUtc < cutoff);
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------
app.UseForwardedHeaders();

if (!behindProxy && certificate is not null)
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Reject public plain-HTTP access to the Kestrel listener itself. The current deployment uses
// Nginx on port 80 in front, while Kestrel remains on loopback; loopback requests are allowed.
app.Use(async (ctx, next) =>
{
    var remote = ctx.Connection.RemoteIpAddress;
    var loopback = remote is not null && IPAddress.IsLoopback(remote);
    if (!ctx.Request.IsHttps && !loopback)
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsJsonAsync(new { message = "Direct public access to the Kestrel HTTP listener is not allowed." });
        return;
    }

    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    await next();
});

app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/api/auth/login") || ctx.Request.Path.StartsWithSegments("/api/auth/register") ||
        ctx.Request.Path.StartsWithSegments("/api/auth/refresh") || ctx.Request.Path.StartsWithSegments("/api/licenses/activate") ||
        ctx.Request.Path.StartsWithSegments("/api/admin"))
    {
        var limiter = ctx.RequestServices.GetRequiredService<RateLimitService>();
        var limit = ctx.Request.Path.StartsWithSegments("/api/admin") ? 30 : 20;
        if (!limiter.Allow($"{Ip(ctx.Request)}:{ctx.Request.Path}", limit, TimeSpan.FromMinutes(1)))
        {
            ctx.Response.StatusCode = 429;
            await ctx.Response.WriteAsJsonAsync(new { message = "Too many requests. Try again later." });
            return;
        }
    }
    await next();
});

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------
app.MapGet("/api/health", () => Results.Ok(new { ok = true, service = "Surge License Server", version = serverVersion }));

app.MapGet("/api/version/check", () => Results.Ok(new
{
    latest = Environment.GetEnvironmentVariable("SURGE_LATEST_VERSION") ?? serverVersion,
    minimum = Environment.GetEnvironmentVariable("SURGE_MINIMUM_VERSION") ?? "0.0.0",
    force = IsTrue(Environment.GetEnvironmentVariable("SURGE_FORCE_UPDATE")),
    // There is no in-product updater. Saying so explicitly stops a future client from
    // assuming one exists and silently doing nothing.
    updateUrl = Environment.GetEnvironmentVariable("SURGE_UPDATE_URL"),
    automatic = false
}));

app.MapPost("/api/auth/register", async (RegisterRequest req, HttpRequest http, StoreService store, SecurityService security) =>
{
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    if (!ValidEmail(email) || !ValidPassword(req.Password)) return Bad("Use a valid email and a password with at least 8 characters.");
    if (string.IsNullOrWhiteSpace(req.DeviceId) || string.IsNullOrWhiteSpace(req.DevicePublicKey) || string.IsNullOrWhiteSpace(req.HardwareFingerprintHash))
        return Bad("Device identity is required.");

    var existing = await store.ReadAsync(s => s.Users.FirstOrDefault(u => u.Email == email));
    if (existing is not null) return Results.Json(new { message = "Account already exists." }, statusCode: 409);

    // A new account may not be created on a PC that is already bound to someone else, otherwise
    // "1 Account = 1 PC" is trivially defeated by registering a second account on the same box.
    var regBinding = await store.ReadAsync(s => EvaluateBinding(s, null, req.DeviceId, req.DevicePublicKey, req.HardwareFingerprintHash));
    if (!regBinding.Ok) return BindingRejection(regBinding.Status, regBinding.Code, regBinding.Message);

    var (salt, hash) = security.HashPassword(req.Password);
    var user = new UserRecord
    {
        Id = Guid.NewGuid().ToString("N"), Email = email, PasswordSalt = salt, PasswordHash = hash,
        CreatedUtc = DateTime.UtcNow, Active = true
    };

    var created = false;
    await store.WriteAsync(s =>
    {
        // Re-check inside the write transaction: two concurrent registrations for the same
        // address would otherwise both pass the read above and violate the unique index.
        if (s.Users.Any(u => u.Email == email)) return false;
        s.Users.Add(user);
        created = true;
        return true;
    });
    if (!created) return Results.Json(new { message = "Account already exists." }, statusCode: 409);

    var refresh = await IssueRefreshTokenAsync(store, security, user.Id, req.DeviceId);
    return Results.Ok(new
    {
        accessToken = security.CreateAccessToken(user.Id),
        refreshToken = refresh,
        accessTokenExpiresUtc = DateTime.UtcNow.Add(SecurityService.AccessTokenLifetime),
        user = new { id = user.Id, email = user.Email, createdUtc = user.CreatedUtc, active = user.Active }
    });
});

app.MapPost("/api/auth/login", async (LoginRequest req, HttpRequest http, StoreService store, SecurityService security, AuditService audit) =>
{
    var email = (req.Email ?? "").Trim().ToLowerInvariant();
    var user = await store.ReadAsync(s => s.Users.FirstOrDefault(u => u.Email == email));
    if (user is null || !user.Active || !ValidPassword(req.Password) || !security.VerifyPassword(req.Password, user.PasswordSalt, user.PasswordHash))
        return Results.Json(new { message = "Invalid email or password." }, statusCode: 401);

    // Device binding is evaluated before any token exists. A rejected machine must not walk away
    // with an access token or a refresh family it can rotate.
    var binding = await store.ReadAsync(s => EvaluateBinding(s, user.Id, req.DeviceId, req.DevicePublicKey, req.HardwareFingerprintHash));
    if (!binding.Ok)
    {
        await audit.WriteAsync("system", "Login Rejected (Device Binding)", "User", user.Id, Ip(http),
            new { binding.Code, deviceId = req.DeviceId });
        return BindingRejection(binding.Status, binding.Code, binding.Message);
    }

    var refresh = await IssueRefreshTokenAsync(store, security, user.Id, req.DeviceId);
    return Results.Ok(new
    {
        accessToken = security.CreateAccessToken(user.Id),
        refreshToken = refresh,
        accessTokenExpiresUtc = DateTime.UtcNow.Add(SecurityService.AccessTokenLifetime),
        user = new { id = user.Id, email = user.Email, createdUtc = user.CreatedUtc, active = user.Active }
    });
});

// -------------------- refresh with rotation + reuse detection ----------------
//
// The reuse check and the rotation happen inside ONE StoreService transaction. Splitting them
// (read the record, decide, then write) leaves a check-then-act race: two requests presenting the
// same token concurrently can both observe it as un-redeemed and both receive a valid successor,
// which is exactly the situation reuse detection is supposed to make impossible.
app.MapPost("/api/auth/refresh", async (RefreshRequest req, HttpRequest http, StoreService store, SecurityService security,
                                        TokenRevocationService revocation, AuditService audit) =>
{
    if (string.IsNullOrWhiteSpace(req.RefreshToken)) return Unauthorized();

    var presentedJti = SecurityService.ReadRefreshJti(req.RefreshToken);
    var presentedHash = security.Hash(req.RefreshToken);
    var now = DateTime.UtcNow;

    var (nextToken, nextJti) = security.NewRefreshToken();
    var nextHash = security.Hash(nextToken);

    RefreshOutcome outcome = RefreshOutcome.NotFound;
    string? userId = null, userEmail = null, familyId = null, redeemedJti = null, boundDeviceId = null;
    DateTime familyExpiresUtc = default, redeemedExpiresUtc = default, userCreatedUtc = default;

    await store.WriteAsync(s =>
    {
        var record = s.RefreshTokens.FirstOrDefault(r => r.Hash == presentedHash);
        if (record is null) { outcome = RefreshOutcome.NotFound; return false; }

        familyId = record.FamilyId;
        familyExpiresUtc = record.FamilyExpiresUtc;
        redeemedJti = record.Jti;
        redeemedExpiresUtc = record.ExpiresUtc;
        userId = record.UserId;
        boundDeviceId = record.DeviceId;

        // Reuse: already burned in the database, or flagged in the in-memory list.
        if (record.Revoked || record.UsedUtc is not null ||
            revocation.IsRedeemed(record.Jti) || revocation.IsFamilyRevoked(record.FamilyId))
        {
            outcome = RefreshOutcome.Reused;
            var changed = false;
            foreach (var sibling in s.RefreshTokens.Where(r => r.FamilyId == record.FamilyId && !r.Revoked))
            {
                sibling.Revoked = true;
                sibling.UsedUtc ??= now;
                changed = true;
            }
            return changed;
        }

        if (record.ExpiresUtc <= now || record.FamilyExpiresUtc <= now)
        {
            outcome = RefreshOutcome.Expired;
            return false;
        }

        // A token minted for one device must not be redeemable from another.
        if (!string.IsNullOrWhiteSpace(record.DeviceId) && !string.IsNullOrWhiteSpace(req.DeviceId) &&
            !string.Equals(record.DeviceId, req.DeviceId, StringComparison.Ordinal))
        {
            outcome = RefreshOutcome.DeviceMismatch;
            foreach (var sibling in s.RefreshTokens.Where(r => r.FamilyId == record.FamilyId && !r.Revoked))
            {
                sibling.Revoked = true;
                sibling.UsedUtc ??= now;
            }
            return true;
        }

        var user = s.Users.FirstOrDefault(u => u.Id == record.UserId && u.Active);
        if (user is null) { outcome = RefreshOutcome.UserInactive; return false; }

        userEmail = user.Email;
        userCreatedUtc = user.CreatedUtc;

        // Burn the presented token and mint its successor atomically.
        record.Revoked = true;
        record.UsedUtc = now;
        record.ReplacedByJti = nextJti;

        var expires = now.Add(SecurityService.RefreshTokenLifetime);
        if (expires > record.FamilyExpiresUtc) expires = record.FamilyExpiresUtc;

        s.RefreshTokens.Add(new RefreshRecord
        {
            Hash = nextHash,
            Jti = nextJti,
            FamilyId = record.FamilyId,
            UserId = user.Id,
            DeviceId = record.DeviceId ?? (string.IsNullOrWhiteSpace(req.DeviceId) ? null : req.DeviceId),
            CreatedUtc = now,
            ExpiresUtc = expires,
            FamilyExpiresUtc = record.FamilyExpiresUtc,
            Revoked = false
        });

        PruneRefreshTokens(s, now);
        outcome = RefreshOutcome.Rotated;
        return true;
    });

    switch (outcome)
    {
        case RefreshOutcome.NotFound:
            return revocation.IsRedeemed(presentedJti)
                ? Results.Json(new { message = "Refresh token was already used. Please sign in again." }, statusCode: 401)
                : Results.Json(new { message = "Refresh token expired or revoked." }, statusCode: 401);

        case RefreshOutcome.Reused:
            revocation.RevokeFamily(familyId!, familyExpiresUtc);
            await audit.WriteAsync("system", "Refresh Token Reuse Detected", "User", userId ?? "unknown", Ip(http),
                new { familyId, jti = redeemedJti, deviceId = req.DeviceId });
            logger.LogWarning("Refresh token reuse detected for user {UserId}; family {FamilyId} revoked.", userId, familyId);
            return Results.Json(new { message = "Refresh token was already used. Please sign in again." }, statusCode: 401);

        case RefreshOutcome.DeviceMismatch:
            revocation.RevokeFamily(familyId!, familyExpiresUtc);
            await audit.WriteAsync("system", "Refresh Token Device Mismatch", "User", userId ?? "unknown", Ip(http),
                new { expected = boundDeviceId, presented = req.DeviceId });
            return Results.Json(new { message = "Refresh token does not belong to this device." }, statusCode: 401);

        case RefreshOutcome.Expired:
            return Results.Json(new { message = "Refresh token expired or revoked." }, statusCode: 401);

        case RefreshOutcome.UserInactive:
            return Results.Json(new { message = "Account is disabled or not found." }, statusCode: 401);

        default:
            // The database has durably burned the old token, so it is now safe to publish the JTI
            // on the fast-path list.
            revocation.MarkRedeemed(redeemedJti!, redeemedExpiresUtc);
            return Results.Ok(new
            {
                accessToken = security.CreateAccessToken(userId!),
                refreshToken = nextToken,
                accessTokenExpiresUtc = now.Add(SecurityService.AccessTokenLifetime),
                user = new { id = userId, email = userEmail, createdUtc = userCreatedUtc, active = true }
            });
    }
});

app.MapPost("/api/auth/logout", async (HttpRequest request, RefreshRequest req, StoreService store, SecurityService security,
                                       TokenRevocationService revocation) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();

    var hash = security.Hash(req.RefreshToken ?? "");
    var record = await store.ReadAsync(s => s.RefreshTokens.FirstOrDefault(x => x.Hash == hash && x.UserId == userId));
    if (record is not null)
    {
        // Burn the whole family, not just this token: signing out must invalidate every
        // rotation descendant, otherwise an earlier copy stays usable.
        revocation.MarkRedeemed(record.Jti, record.ExpiresUtc);
        revocation.RevokeFamily(record.FamilyId, record.FamilyExpiresUtc);
        await store.WriteAsync(s =>
        {
            var changed = false;
            foreach (var sibling in s.RefreshTokens.Where(r => r.FamilyId == record.FamilyId && !r.Revoked))
            {
                sibling.Revoked = true;
                sibling.UsedUtc ??= DateTime.UtcNow;
                changed = true;
            }
            return changed;
        });
    }
    return Results.Ok(new { ok = true });
});

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------
app.MapPost("/api/devices/register", async (HttpRequest request, DeviceRegisterRequest req, StoreService store,
                                            SecurityService security, AuditService audit) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();
    if (string.IsNullOrWhiteSpace(req.DeviceId) || string.IsNullOrWhiteSpace(req.PublicKeyBase64) || string.IsNullOrWhiteSpace(req.HardwareFingerprintHash))
        return Bad("Device identity is required.");

    // Optional, time-boxed hardware-fingerprint rebind window. See HWID_MIGRATION notes: the
    // v19.4 client computes its fingerprint natively instead of shelling out to PowerShell, and a
    // small number of machines produce a different hash as a result. A rebind is accepted ONLY if
    // the device's ECDSA public key still matches, which proves possession of the DPAPI-protected
    // private key on the same Windows account and machine. Unset the variable to disable.
    var rebindUntil = ParseUtc(Environment.GetEnvironmentVariable("SURGE_HWID_REBIND_UNTIL_UTC"));
    var rebindOpen = rebindUntil is not null && rebindUntil > DateTime.UtcNow;

    // Same rule as login/register, so the three device-creating paths cannot diverge. Repeated
    // inside the write transaction below, which is where it is authoritative; this copy only
    // avoids doing transaction work for a request that is already known to be rejected.
    var preCheck = await store.ReadAsync(s => EvaluateBinding(s, userId, req.DeviceId, req.PublicKeyBase64, req.HardwareFingerprintHash));
    if (!preCheck.Ok && !(rebindOpen && preCheck.Code == "hardware_mismatch"))
        return BindingRejection(preCheck.Status, preCheck.Code, preCheck.Message);

    string? error = null;
    var rebound = false;

    await store.WriteAsync(s =>
    {
        var authoritative = EvaluateBinding(s, userId, req.DeviceId, req.PublicKeyBase64, req.HardwareFingerprintHash);
        if (!authoritative.Ok && !(rebindOpen && authoritative.Code == "hardware_mismatch"))
        {
            error = authoritative.Message;
            return false;
        }

        var device = s.Devices.FirstOrDefault(d => d.Id == req.DeviceId);
        if (device is null)
        {
            s.Devices.Add(new DeviceRecord
            {
                Id = req.DeviceId, UserId = userId, AccountUserIds = new List<string> { userId },
                DisplayName = req.DisplayName ?? "device", PublicKeyBase64 = req.PublicKeyBase64,
                HardwareFingerprintHash = req.HardwareFingerprintHash,
                FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow, Active = true
            });
            return true;
        }

        if (device.Blocked) { error = "Device is blocked."; return false; }
        if (!string.IsNullOrWhiteSpace(device.PublicKeyBase64) && !string.Equals(device.PublicKeyBase64, req.PublicKeyBase64, StringComparison.Ordinal))
        { error = "Device public-key conflict."; return false; }

        if (!string.IsNullOrWhiteSpace(device.HardwareFingerprintHash) &&
            !string.Equals(device.HardwareFingerprintHash, req.HardwareFingerprintHash, StringComparison.Ordinal))
        {
            if (!rebindOpen) { error = "Hardware fingerprint conflict."; return false; }
            rebound = true;

            // Carry the licence lock across with the device so the user is not locked out.
            foreach (var licence in s.Licenses.Where(l => l.LockedDeviceId == device.Id))
                licence.HardwareFingerprintHash = req.HardwareFingerprintHash;
        }

        if (!string.IsNullOrWhiteSpace(device.UserId) && device.UserId != userId) { error = "Device is already bound to another account."; return false; }

        device.UserId = userId;
        device.AccountUserIds = new List<string> { userId };
        device.PublicKeyBase64 = req.PublicKeyBase64;
        device.HardwareFingerprintHash = req.HardwareFingerprintHash;
        device.DisplayName = req.DisplayName ?? device.DisplayName;
        device.LastSeenUtc = DateTime.UtcNow;
        device.Active = true;
        return true;
    });

    if (rebound)
        await audit.WriteAsync("system", "Hardware Fingerprint Rebound", "Device", req.DeviceId, Ip(request), new { userId });

    return error is null ? Results.Ok(new { ok = true }) : Results.Json(new { message = error }, statusCode: 409);
});

app.MapGet("/api/devices/challenge", async (HttpRequest request, string deviceId, StoreService store,
                                            SecurityService security, ChallengeService challenges) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();
    var device = await store.ReadAsync(s => s.Devices.FirstOrDefault(d => d.Id == deviceId && d.Active && !d.Blocked && d.UserId == userId));
    if (device is null) return Bad("Device is not registered.");
    return Results.Ok(new { nonce = challenges.Issue(userId, deviceId) });
});

app.MapPost("/api/devices/attest", async (HttpRequest request, DeviceAttestationRequest req, StoreService store,
                                          SecurityService security, ChallengeService challenges) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();
    var device = await store.ReadAsync(s => s.Devices.FirstOrDefault(d => d.Id == req.DeviceId && d.Active && !d.Blocked && d.UserId == userId));
    if (device is null) return Bad("Device is not registered.");
    if (!challenges.TryConsume(userId, req.DeviceId, req.Nonce)) return Bad("Device challenge expired.");
    if (!security.VerifySignature(device.PublicKeyBase64, req.Nonce, req.SignatureBase64))
        return Results.Json(new { message = "Device attestation failed." }, statusCode: 403);

    await store.WriteAsync(s =>
    {
        var d = s.Devices.FirstOrDefault(x => x.Id == req.DeviceId && x.UserId == userId);
        if (d is null) return false;
        d.LastSeenUtc = DateTime.UtcNow;
        return true;
    });
    return Results.Ok(new { ok = true });
});

// ---------------------------------------------------------------------------
// Licenses
// ---------------------------------------------------------------------------
app.MapGet("/api/licenses/state", async (HttpRequest request, string deviceId, StoreService store, SecurityService security) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();

    var data = await store.ReadAsync(s => (
        user: s.Users.FirstOrDefault(u => u.Id == userId),
        device: s.Devices.FirstOrDefault(d => d.Id == deviceId && d.UserId == userId),
        licenses: s.Licenses.Where(l => l.OwnerUserId == userId).ToList()));

    if (data.user is null || data.device is null || !data.device.Active || data.device.Blocked)
        return Bad("Device is not registered or is blocked.");

    var licenses = data.licenses.Select(l => LicenseDto(l, deviceId)).ToList();
    var active = licenses.FirstOrDefault(x => x.ActivatedOnThisDevice);

    return Results.Ok(new
    {
        user = new { id = data.user.Id, email = data.user.Email, createdUtc = data.user.CreatedUtc, active = data.user.Active },
        licenses,
        activeLicense = active,
        device = new { id = data.device.Id, displayName = data.device.DisplayName, firstSeenUtc = data.device.FirstSeenUtc, lastSeenUtc = data.device.LastSeenUtc, active = data.device.Active }
    });
});

app.MapPost("/api/licenses/activate", async (HttpRequest request, ActivateLicenseRequest req, StoreService store,
                                             SecurityService security, ChallengeService challenges) =>
{
    var userId = await ActiveUser(request, store, security);
    if (userId is null) return Unauthorized();
    var device = await store.ReadAsync(s => s.Devices.FirstOrDefault(d => d.Id == req.DeviceId && d.Active && !d.Blocked && d.UserId == userId));
    if (device is null) return Bad("Device is not registered.");
    if (!challenges.TryConsume(userId, req.DeviceId, req.Nonce)) return Bad("Device challenge expired.");
    if (!security.VerifySignature(device.PublicKeyBase64, req.Nonce, req.SignatureBase64))
        return Results.Json(new { message = "Device attestation failed." }, statusCode: 403);

    var normalized = NormalizeKey(req.LicenseKey ?? "");
    var keyHash = security.HashLicenseKey(normalized);
    var legacyHash = security.Hash(normalized);

    LicenseRecord? target = null;
    string? error = null;

    await store.WriteAsync(s =>
    {
        target = s.Licenses.FirstOrDefault(l => l.KeyHash == keyHash || l.LegacySha256Hash == legacyHash || l.KeyHash == legacyHash);
        if (target is null) { error = "License key not found."; return false; }
        if (target.ExpiresUtc is not null && target.ExpiresUtc <= DateTime.UtcNow) { error = "License expired."; return false; }
        if (target.Banned) { error = "License revoked."; return false; }
        if (target.OwnerUserId is not null && target.OwnerUserId != userId) { error = "License is already assigned to another account."; return false; }
        if (!string.IsNullOrWhiteSpace(target.HardwareFingerprintHash) && target.HardwareFingerprintHash != device.HardwareFingerprintHash)
        { error = "License is locked to another PC."; return false; }
        if (target.Locked && target.LockedDeviceId != req.DeviceId) { error = "License is locked to another device."; return false; }

        target.OwnerUserId ??= userId;
        target.MaxDevices = 1;
        target.Locked = true;
        target.LockedDeviceId = req.DeviceId;
        target.HardwareFingerprintHash = device.HardwareFingerprintHash;
        target.LockedUtc ??= DateTime.UtcNow;
        target.ActiveDeviceIds.Clear();
        target.ActiveDeviceIds.Add(req.DeviceId);
        target.KeyHash = keyHash;
        target.LegacySha256Hash = null;
        return true;
    });

    if (error is not null) return Bad(error);
    if (target is null) return Bad("License activation failed.");
    return Results.Ok(LicenseDto(target, req.DeviceId));
});

// User-side device/license release endpoints intentionally remain absent in production policy.

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------
app.MapPost("/api/admin/login", (AdminLoginRequest req, SecurityService security, RateLimitService limiter, HttpRequest request) =>
{
    if (!limiter.Allow($"admin-login:{Ip(request)}", 5, TimeSpan.FromMinutes(5)))
        return Results.Json(new { message = "Too many admin login attempts." }, statusCode: 429);

    var user = Environment.GetEnvironmentVariable("SURGE_ADMIN_USER");
    var password = Environment.GetEnvironmentVariable("SURGE_ADMIN_PASSWORD");
    if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password) ||
        !SecureEquals(user, req.Username) || !SecureEquals(password, req.Password))
        return Results.Json(new { message = "Invalid administrator credentials." }, statusCode: 401);

    return Results.Ok(new
    {
        accessToken = security.CreateAdminToken(user),
        expiresUtc = DateTime.UtcNow.Add(SecurityService.AdminTokenLifetime),
        admin = user
    });
});

app.MapGet("/api/admin/control/status", async (HttpRequest request, SecurityService security) =>
    await ProxyControl(request, "api/control/status", HttpMethod.Get, security));

app.MapPost("/api/admin/control/{action}", async (HttpRequest request, string action, SecurityService security) =>
{
    if (action is not ("start" or "stop" or "restart")) return Results.NotFound();
    return await ProxyControl(request, $"api/control/{action}", HttpMethod.Post, security);
});

app.MapGet("/api/admin/overview", async (HttpRequest request, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    return Results.Ok(await store.ReadAsync(s => new
    {
        totalUsers = s.Users.Count,
        totalLicenses = s.Licenses.Count,
        activeDevices = s.Devices.Count(d => d.Active && !d.Blocked),
        expiredLicenses = s.Licenses.Count(l => l.ExpiresUtc is not null && l.ExpiresUtc <= DateTime.UtcNow && !l.Banned),
        recentActivity = s.AuditLogs.OrderByDescending(x => x.CreatedUtc).Take(20).ToList()
    }));
});

app.MapGet("/api/admin/users", async (HttpRequest request, string? search, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    var q = search?.Trim();
    return Results.Ok(await store.ReadAsync(s => s.Users
        .Where(u => string.IsNullOrWhiteSpace(q) || u.Email.Contains(q!, StringComparison.OrdinalIgnoreCase) || u.Id.Contains(q!, StringComparison.OrdinalIgnoreCase))
        .Select(u => new
        {
            u.Id, u.Email, u.CreatedUtc, u.Active, u.DisabledUtc, u.DisabledReason,
            devices = s.Devices.Count(d => d.UserId == u.Id),
            licenses = s.Licenses.Count(l => l.OwnerUserId == u.Id)
        }).ToList()));
});

app.MapPost("/api/admin/users/status", async (HttpRequest request, AdminUserStatusRequest req, StoreService store,
                                              SecurityService security, AuditService audit, TokenRevocationService revocation) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (string.IsNullOrWhiteSpace(req.UserId)) return Bad("User ID is required.");

    var changed = false;
    var burnedFamilies = new List<(string FamilyId, DateTime Expires)>();

    await store.WriteAsync(s =>
    {
        var u = s.Users.FirstOrDefault(x => x.Id == req.UserId);
        if (u is null) return false;
        u.Active = req.Active;
        u.DisabledUtc = req.Active ? null : DateTime.UtcNow;
        u.DisabledReason = req.Active ? null : req.Reason;

        if (!req.Active)
        {
            foreach (var r in s.RefreshTokens.Where(r => r.UserId == u.Id))
            {
                if (!r.Revoked) burnedFamilies.Add((r.FamilyId, r.FamilyExpiresUtc));
                r.Revoked = true;
            }
        }
        changed = true;
        return true;
    });

    // Mirror the ban into the in-memory list so a token already in flight is rejected
    // without waiting for anything to be re-read.
    foreach (var (familyId, expires) in burnedFamilies) revocation.RevokeFamily(familyId, expires);

    if (changed) await audit.WriteAsync(admin!, req.Active ? "Restore User" : "Ban User", "User", req.UserId, Ip(request), new { req.Reason });
    return changed ? Results.Ok(new { ok = true }) : Bad("User not found.");
});

app.MapPost("/api/admin/users/reset-password", async (HttpRequest request, AdminUserPasswordResetRequest req, StoreService store,
                                                     SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (string.IsNullOrWhiteSpace(req.UserId)) return Bad("User ID is required.");

    string? temporaryPassword = null;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var u = s.Users.FirstOrDefault(x => x.Id == req.UserId);
        if (u is null) return false;

        temporaryPassword = security.NewTemporaryPassword();
        var (salt, hash) = security.HashPassword(temporaryPassword);
        u.PasswordSalt = salt;
        u.PasswordHash = hash;

        foreach (var r in s.RefreshTokens.Where(r => r.UserId == u.Id && !r.Revoked))
        {
            r.Revoked = true;
            r.UsedUtc ??= DateTime.UtcNow;
        }

        changed = true;
        return true;
    });

    if (!changed || string.IsNullOrWhiteSpace(temporaryPassword)) return Bad("User not found.");

    await audit.WriteAsync(admin!, "Reset User Password", "User", req.UserId, Ip(request));
    return Results.Ok(new { ok = true, userId = req.UserId, temporaryPassword });
});

app.MapGet("/api/admin/devices", async (HttpRequest request, string? search, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    var q = search?.Trim();
    return Results.Ok(await store.ReadAsync(s => s.Devices
        .Where(d => string.IsNullOrWhiteSpace(q) || d.Id.Contains(q!, StringComparison.OrdinalIgnoreCase) ||
                    d.DisplayName.Contains(q!, StringComparison.OrdinalIgnoreCase) || d.UserId.Contains(q!, StringComparison.OrdinalIgnoreCase) ||
                    (s.Users.FirstOrDefault(u => u.Id == d.UserId)?.Email?.Contains(q!, StringComparison.OrdinalIgnoreCase) ?? false))
        .Select(d => new
        {
            d.Id, d.DisplayName, d.UserId, hardwareId = d.HardwareFingerprintHash,
            d.FirstSeenUtc, d.LastSeenUtc, d.Active, d.Blocked,
            email = s.Users.FirstOrDefault(u => u.Id == d.UserId)?.Email
        }).ToList()));
});

app.MapPost("/api/admin/devices/block", async (HttpRequest request, AdminDeviceStatusRequest req, StoreService store,
                                               SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var d = s.Devices.FirstOrDefault(x => x.Id == req.DeviceId);
        if (d is null) return false;
        d.Blocked = req.Blocked;
        d.Active = !req.Blocked;
        if (req.Blocked) foreach (var l in s.Licenses) l.ActiveDeviceIds.Remove(d.Id);
        changed = true;
        return true;
    });
    if (changed) await audit.WriteAsync(admin!, req.Blocked ? "Block Device" : "Unblock Device", "Device", req.DeviceId, Ip(request));
    return changed ? Results.Ok(new { ok = true }) : Bad("Device not found.");
});

app.MapPost("/api/admin/devices/release", async (HttpRequest request, DeviceReleaseRequest req, StoreService store,
                                                 SecurityService security, AuditService audit, TokenRevocationService revocation) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (string.IsNullOrWhiteSpace(req.DeviceId)) return Bad("Device ID is required.");

    var changed = false;
    var burnedFamilies = new List<(string FamilyId, DateTime Expires)>();
    await store.WriteAsync(s =>
    {
        var d = s.Devices.FirstOrDefault(x => x.Id == req.DeviceId);
        if (d is null) return false;

        var oldUserId = d.UserId;
        foreach (var r in s.RefreshTokens.Where(r => r.DeviceId == req.DeviceId && !r.Revoked))
        {
            burnedFamilies.Add((r.FamilyId, r.FamilyExpiresUtc));
            r.Revoked = true;
            r.UsedUtc ??= DateTime.UtcNow;
        }

        foreach (var l in s.Licenses.Where(l => l.LockedDeviceId == req.DeviceId || l.ActiveDeviceIds.Contains(req.DeviceId)))
        {
            l.ActiveDeviceIds.RemoveAll(id => id == req.DeviceId);
            if (l.LockedDeviceId == req.DeviceId)
            {
                l.Locked = false;
                l.LockedDeviceId = null;
                l.HardwareFingerprintHash = null;
                l.LockedUtc = null;
            }
        }

        // An administrator release must genuinely free the installation for a future
        // account/device registration. Keeping the historical Device row is useful for
        // auditability, but its ownership and cryptographic identity are reset.
        d.UserId = string.Empty;
        d.AccountUserIds.Clear();
        d.PublicKeyBase64 = string.Empty;
        d.HardwareFingerprintHash = string.Empty;
        d.Active = false;
        d.LastSeenUtc = DateTime.UtcNow;
        changed = true;
        return true;
    });

    foreach (var (familyId, expires) in burnedFamilies) revocation.RevokeFamily(familyId, expires);

    if (changed)
        await audit.WriteAsync(admin!, "Release HWID", "Device", req.DeviceId, Ip(request));

    return changed ? Results.Ok(new { ok = true }) : Bad("Device not found.");
});

app.MapGet("/api/admin/licenses", async (HttpRequest request, string? search, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    var q = search?.Trim();
    return Results.Ok(await store.ReadAsync(s => s.Licenses
        .Where(l => string.IsNullOrWhiteSpace(q) || l.Id.Contains(q!, StringComparison.OrdinalIgnoreCase) ||
                    l.KeyMasked.Contains(q!, StringComparison.OrdinalIgnoreCase) ||
                    (s.Users.FirstOrDefault(u => u.Id == l.OwnerUserId)?.Email?.Contains(q!, StringComparison.OrdinalIgnoreCase) ?? false))
        .Select(l => new
        {
            l.Id, l.KeyMasked, l.Plan, l.OwnerUserId,
            owner = s.Users.FirstOrDefault(u => u.Id == l.OwnerUserId)?.Email,
            devices = l.ActiveDeviceIds, l.ExpiresUtc, status = Status(l), l.Banned, l.Locked, hardwareFingerprintHash = l.HardwareFingerprintHash
        }).ToList()));
});

app.MapPost("/api/admin/licenses", async (HttpRequest request, AdminLicenseRequest req, StoreService store,
                                          SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (req.MaxDevices != 1) return Bad("Surge licenses support exactly one device.");

    var key = string.IsNullOrWhiteSpace(req.LicenseKey) ? security.NewLicenseKey() : NormalizeKey(req.LicenseKey);
    var record = new LicenseRecord
    {
        Id = Guid.NewGuid().ToString("N"),
        KeyHash = security.HashLicenseKey(key),
        KeyMasked = security.MaskLicenseKey(key),
        Plan = string.IsNullOrWhiteSpace(req.Plan) ? "PRO" : req.Plan.Trim().ToUpperInvariant(),
        MaxDevices = 1,
        ExpiresUtc = req.ExpiresUtc
    };

    var created = false;
    await store.WriteAsync(s =>
    {
        if (s.Licenses.Any(l => l.KeyHash == record.KeyHash)) return false;
        s.Licenses.Add(record);
        created = true;
        return true;
    });
    if (!created) return Results.Json(new { message = "That license key already exists." }, statusCode: 409);

    await audit.WriteAsync(admin!, "Create License", "License", record.Id, Ip(request), new { record.Plan });
    return Results.Ok(new { id = record.Id, licenseKey = key, licenseKeyMasked = record.KeyMasked, plan = record.Plan, expiresUtc = record.ExpiresUtc });
});

app.MapPost("/api/admin/licenses/rotate-key", async (HttpRequest request, RevokeLicenseRequest req, StoreService store,
                                                       SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    string? newKey = null; var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        newKey = security.NewLicenseKey();
        l.KeyHash = security.HashLicenseKey(newKey);
        l.KeyMasked = security.MaskLicenseKey(newKey);
        changed = true;
        return true;
    });
    if (!changed || string.IsNullOrWhiteSpace(newKey)) return Bad("License not found.");
    await audit.WriteAsync(admin!, "Rotate License Key", "License", req.LicenseId, Ip(request));
    return Results.Ok(new { id = req.LicenseId, licenseKey = newKey, licenseKeyMasked = security.MaskLicenseKey(newKey) });
});

app.MapPost("/api/admin/licenses/revoke", async (HttpRequest request, RevokeLicenseRequest req, StoreService store,
                                                 SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        l.Banned = true; l.ActiveDeviceIds.Clear(); changed = true; return true;
    });
    if (changed) await audit.WriteAsync(admin!, "Revoke License", "License", req.LicenseId, Ip(request));
    return changed ? Results.Ok(new { ok = true }) : Bad("License not found.");
});

app.MapPost("/api/admin/licenses/restore", async (HttpRequest request, RevokeLicenseRequest req, StoreService store,
                                                  SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        l.Banned = false; changed = true; return true;
    });
    if (changed) await audit.WriteAsync(admin!, "Restore License", "License", req.LicenseId, Ip(request));
    return changed ? Results.Ok(new { ok = true }) : Bad("License not found.");
});

app.MapPost("/api/admin/licenses/expire", async (HttpRequest request, RevokeLicenseRequest req, StoreService store,
                                                 SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        l.ExpiresUtc = DateTime.UtcNow.AddSeconds(-1); changed = true; return true;
    });
    if (changed) await audit.WriteAsync(admin!, "Expire License", "License", req.LicenseId, Ip(request));
    return changed ? Results.Ok(new { ok = true }) : Bad("License not found.");
});

app.MapPost("/api/admin/licenses/extend", async (HttpRequest request, AdminExtendLicenseRequest req, StoreService store,
                                                 SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (req.Days <= 0 || req.Days > 3650) return Bad("Days must be between 1 and 3650.");
    var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        l.ExpiresUtc = (l.ExpiresUtc is null || l.ExpiresUtc <= DateTime.UtcNow ? DateTime.UtcNow : l.ExpiresUtc.Value).AddDays(req.Days);
        l.Banned = false; changed = true; return true;
    });
    if (changed) await audit.WriteAsync(admin!, "Extend License", "License", req.LicenseId, Ip(request), new { req.Days });
    return changed ? Results.Ok(new { ok = true }) : Bad("License not found.");
});

app.MapPost("/api/admin/licenses/release-device", async (HttpRequest request, RevokeLicenseRequest req, StoreService store,
                                                         SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var changed = false;
    await store.WriteAsync(s =>
    {
        var l = s.Licenses.FirstOrDefault(x => x.Id == req.LicenseId);
        if (l is null) return false;
        l.ActiveDeviceIds.Clear(); l.Locked = false; l.LockedDeviceId = null; l.HardwareFingerprintHash = null; l.LockedUtc = null;
        changed = true; return true;
    });
    if (changed) await audit.WriteAsync(admin!, "Release Device", "License", req.LicenseId, Ip(request));
    return changed ? Results.Ok(new { ok = true }) : Bad("License not found.");
});

app.MapGet("/api/admin/logs", async (HttpRequest request, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    return Results.Ok(await store.ReadAsync(s => s.AuditLogs.OrderByDescending(x => x.CreatedUtc).Take(500).ToList()));
});

app.MapPost("/api/admin/backup", async (HttpRequest request, StoreService store, SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    var info = await store.CreateBackupAsync("manual");
    await audit.WriteAsync(admin!, "Create Backup", "Backup", info.FileName, Ip(request));
    return Results.Ok(info);
});

app.MapGet("/api/admin/backups", async (HttpRequest request, StoreService store, SecurityService security) =>
{
    var (_, err) = Admin(request, security); if (err is not null) return err;
    return Results.Ok(await store.ListBackupsAsync());
});

app.MapPost("/api/admin/restore", async (HttpRequest request, AdminRestoreRequest req, StoreService store,
                                         SecurityService security, AuditService audit) =>
{
    var (admin, err) = Admin(request, security); if (err is not null) return err;
    if (!await store.RestoreBackupAsync(req.FileName)) return Bad("Backup not found or invalid.");
    await audit.WriteAsync(admin!, "Restore Backup", "Backup", req.FileName, Ip(request));
    return Results.Ok(new { ok = true });
});

app.Run();

// ---------------------------------------------------------------------------
// Startup helpers
// ---------------------------------------------------------------------------
static bool IsTrue(string? value) => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1";

static DateTime? ParseUtc(string? value) =>
    DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
        ? parsed
        : null;

static bool IsLoopbackUrl(string url) =>
    Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
    (uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase));

static void ValidateBindings(IReadOnlyCollection<string> urls, bool hasCertificate, bool behindProxy)
{
    foreach (var url in urls)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"SURGE_LICENSE_URL contains an invalid URL: '{url}'.");

        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            if (!hasCertificate)
                throw new InvalidOperationException(
                    "An https:// binding was requested but no certificate was supplied. Set SURGE_TLS_CERT_PATH " +
                    "(+ SURGE_TLS_CERT_PASSWORD) or SURGE_TLS_CERT_PEM and SURGE_TLS_KEY_PEM.");
            continue;
        }

        var loopbackOnly = IsLoopbackUrl(url);
        if (!loopbackOnly && !behindProxy)
            throw new InvalidOperationException(
                $"Refusing to serve plain HTTP on a public interface ('{url}'). Supply a TLS certificate, " +
                "bind to 127.0.0.1, or set SURGE_BEHIND_PROXY=true when a reverse proxy terminates TLS.");
    }
}

static X509Certificate2? LoadServerCertificate()
{
    var pfxPath = Environment.GetEnvironmentVariable("SURGE_TLS_CERT_PATH");
    if (!string.IsNullOrWhiteSpace(pfxPath))
    {
        if (!File.Exists(pfxPath)) throw new FileNotFoundException($"SURGE_TLS_CERT_PATH does not exist: {pfxPath}");
        var password = Environment.GetEnvironmentVariable("SURGE_TLS_CERT_PASSWORD");
        return new X509Certificate2(pfxPath, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    var certPem = Environment.GetEnvironmentVariable("SURGE_TLS_CERT_PEM");
    var keyPem = Environment.GetEnvironmentVariable("SURGE_TLS_KEY_PEM");
    if (string.IsNullOrWhiteSpace(certPem) || string.IsNullOrWhiteSpace(keyPem)) return null;
    if (!File.Exists(certPem) || !File.Exists(keyPem))
        throw new FileNotFoundException("SURGE_TLS_CERT_PEM / SURGE_TLS_KEY_PEM point at a missing file.");

    var pem = X509Certificate2.CreateFromPemFile(certPem, keyPem);
    if (!OperatingSystem.IsWindows()) return pem;

    // Windows/SChannel cannot use an ephemeral PEM key directly; round-trip through a PFX.
    using (pem)
    {
        return new X509Certificate2(pem.Export(X509ContentType.Pfx), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }
}

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------
internal enum RefreshOutcome { NotFound, Reused, Expired, DeviceMismatch, UserInactive, Rotated }

public sealed record LicenseView(
    string Id, string LicenseKeyMasked, string Plan, int MaxDevices, int ActiveDevices,
    bool ActivatedOnThisDevice, DateTime? ExpiresUtc, string? OwnerUserId, string Status);

public sealed record RegisterRequest(string Email, string Password, string DeviceId, string DevicePublicKey, string HardwareFingerprintHash);
public sealed record LoginRequest(string Email, string Password, string DeviceId, string DevicePublicKey, string HardwareFingerprintHash);
public sealed record RefreshRequest(string RefreshToken, string DeviceId);
public sealed record DeviceRegisterRequest(string DeviceId, string PublicKeyBase64, string? DisplayName, string HardwareFingerprintHash);
public sealed record DeviceAttestationRequest(string DeviceId, string Nonce, string SignatureBase64);
public sealed record ActivateLicenseRequest(string LicenseKey, string DeviceId, string SignatureBase64, string Nonce);
public sealed record DeviceReleaseRequest(string DeviceId);
public sealed record RevokeLicenseRequest(string LicenseId);
public sealed record AdminLicenseRequest(string? LicenseKey, string? Plan, int MaxDevices, DateTime? ExpiresUtc);
public sealed record AdminLoginRequest(string Username, string Password);
public sealed record AdminUserStatusRequest(string UserId, bool Active, string? Reason);
public sealed record AdminUserPasswordResetRequest(string UserId);
public sealed record AdminDeviceStatusRequest(string DeviceId, bool Blocked);
public sealed record AdminExtendLicenseRequest(string LicenseId, int Days);
public sealed record AdminRestoreRequest(string FileName);
