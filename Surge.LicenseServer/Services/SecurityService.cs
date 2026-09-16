using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Surge.LicenseServer.Services;

public sealed class SecurityService
{
    /// <summary>User access token lifetime. Short by design; the client silently refreshes.</summary>
    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(20);

    /// <summary>
    /// Administrator token lifetime. Reduced from 8 hours to 1: an admin token grants license
    /// creation, user bans and remote systemctl control, so an 8-hour window left a stolen token
    /// usable for most of a working day.
    /// </summary>
    public static readonly TimeSpan AdminTokenLifetime = TimeSpan.FromHours(1);

    /// <summary>Rolling refresh token lifetime.</summary>
    public static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);

    /// <summary>Absolute ceiling for one rotation chain; rotation can never extend past this.</summary>
    public static readonly TimeSpan RefreshFamilyLifetime = TimeSpan.FromDays(60);

    private readonly byte[] _secret;
    private readonly byte[] _licenseSecret;
    private readonly string _secretPath;

    public SecurityService(IWebHostEnvironment env, IConfiguration config)
    {
        var dataPath = Environment.GetEnvironmentVariable("SURGE_DATA_PATH");
        var dataDir = !string.IsNullOrWhiteSpace(dataPath)
            ? dataPath
            : OperatingSystem.IsLinux() ? "/opt/surge/data" : Path.Combine(env.ContentRootPath, "Data");

        _secretPath = Path.Combine(dataDir, "token.secret");
        Directory.CreateDirectory(Path.GetDirectoryName(_secretPath)!);

        var configured = config["SURGE_JWT_SECRET"] ?? Environment.GetEnvironmentVariable("SURGE_JWT_SECRET");
        if (!string.IsNullOrWhiteSpace(configured)) _secret = SHA256.HashData(Encoding.UTF8.GetBytes(configured));
        else if (File.Exists(_secretPath)) _secret = Convert.FromBase64String(File.ReadAllText(_secretPath).Trim());
        else
        {
            _secret = RandomNumberGenerator.GetBytes(64);
            WriteSecretFile(_secretPath, Convert.ToBase64String(_secret));
        }

        var licensePath = Path.Combine(dataDir, "license.secret");
        var licenseConfigured = config["SURGE_LICENSE_SECRET"] ?? Environment.GetEnvironmentVariable("SURGE_LICENSE_SECRET");
        if (string.IsNullOrWhiteSpace(licenseConfigured) && File.Exists(licensePath)) licenseConfigured = File.ReadAllText(licensePath).Trim();
        if (string.IsNullOrWhiteSpace(licenseConfigured))
        {
            licenseConfigured = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            WriteSecretFile(licensePath, licenseConfigured);
        }
        _licenseSecret = SHA256.HashData(Encoding.UTF8.GetBytes(licenseConfigured));
    }

    // ---------------------------------------------------------------- tokens

    public string CreateAccessToken(string userId) => CreateToken(userId, "access", AccessTokenLifetime);
    public string CreateAdminToken(string admin) => CreateToken(admin, "admin", AdminTokenLifetime);

    public bool TryValidateAccessToken(string token, out string userId) => TryValidateToken(token, "access", out userId);
    public bool TryValidateAdminToken(string token, out string admin) => TryValidateToken(token, "admin", out admin);

    /// <summary>
    /// Mints an opaque refresh token of the form <c>{jti}.{secret}</c>.
    /// The JTI prefix is deliberately public: it lets the revocation list be consulted before any
    /// database work, while the 48-byte secret suffix is what actually authenticates the token.
    /// </summary>
    public (string Token, string Jti) NewRefreshToken()
    {
        var jti = Base64Url(RandomNumberGenerator.GetBytes(16));
        var secret = Base64Url(RandomNumberGenerator.GetBytes(48));
        return (jti + "." + secret, jti);
    }

    /// <summary>
    /// Extracts the JTI prefix from a presented refresh token. Tokens issued before the rotation
    /// upgrade have no prefix; for those the stored hash doubles as the JTI (see the migration in
    /// <c>StoreService</c>), so an empty result simply falls through to the database lookup.
    /// </summary>
    public static string ReadRefreshJti(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return "";
        var dot = token.IndexOf('.');
        if (dot <= 0) return "";
        var jti = token[..dot];
        foreach (var c in jti)
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_') return "";
        return jti;
    }

    // ---------------------------------------------------------------- hashing / keys

    public string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public string HashLicenseKey(string normalizedKey) => Convert.ToHexString(HMACSHA256.HashData(_licenseSecret, Encoding.UTF8.GetBytes(normalizedKey)));
    public string NewOpaqueToken(int bytes = 48) => Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>Creates a one-time temporary user password for administrator resets. The raw value is returned only once.</summary>
    public string NewTemporaryPassword(int length = 18)
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-";
        var bytes = RandomNumberGenerator.GetBytes(length);
        var chars = new char[length];
        for (var i = 0; i < length; i++) chars[i] = alphabet[bytes[i] % alphabet.Length];
        return new string(chars);
    }

    public string NewLicenseKey()
    {
        static string Part() => Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
        return $"SURGE-{Part()}-{Part()}-{Part()}";
    }

    public string MaskLicenseKey(string key) => key.Length <= 8 ? "••••" : key[..5] + "••••" + key[^4..];

    public (string Salt, string Hash) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return (Convert.ToBase64String(salt), Convert.ToBase64String(hash));
    }

    public bool VerifyPassword(string password, string saltBase64, string hashBase64)
    {
        try
        {
            var salt = Convert.FromBase64String(saltBase64);
            var expected = Convert.FromBase64String(hashBase64);
            var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 120_000, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }

    public bool VerifySignature(string publicKeyBase64, string message, string signatureBase64)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);
            return key.VerifyData(Encoding.UTF8.GetBytes(message), Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256);
        }
        catch { return false; }
    }

    // ---------------------------------------------------------------- internals

    private string CreateToken(string subject, string type, TimeSpan lifetime)
    {
        var header = B64(JsonSerializer.Serialize(new { alg = "HS256", typ = "SURGE" }));
        var now = DateTimeOffset.UtcNow;
        var payload = B64(JsonSerializer.Serialize(new
        {
            sub = subject,
            exp = now.Add(lifetime).ToUnixTimeSeconds(),
            iat = now.ToUnixTimeSeconds(),
            jti = Base64Url(RandomNumberGenerator.GetBytes(12)),
            typ = type
        }));
        var body = header + "." + payload;
        return body + "." + B64(Sign(body));
    }

    private bool TryValidateToken(string token, string expectedType, out string subject)
    {
        subject = "";
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return false;
            var body = parts[0] + "." + parts[1];
            if (!CryptographicOperations.FixedTimeEquals(Sign(body), FromB64(parts[2]))) return false;

            var json = JsonSerializer.Deserialize<JsonElement>(FromB64(parts[1]));
            if (!json.TryGetProperty("typ", out var typ) || typ.GetString() != expectedType) return false;
            if (!json.TryGetProperty("exp", out var exp) || exp.GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return false;

            subject = json.TryGetProperty("sub", out var sub) ? sub.GetString() ?? "" : "";
            return !string.IsNullOrWhiteSpace(subject);
        }
        catch { return false; }
    }

    private static void WriteSecretFile(string path, string contents)
    {
        File.WriteAllText(path, contents);
        // Keep signing material out of reach of other local accounts.
        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { /* best effort */ }
        }
    }

    private byte[] Sign(string body) => HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(body));
    private static string B64(string s) => B64(Encoding.UTF8.GetBytes(s));
    private static string B64(byte[] bytes) => Base64Url(bytes);
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromB64(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        s += new string('=', (4 - s.Length % 4) % 4);
        return Convert.FromBase64String(s);
    }
}
