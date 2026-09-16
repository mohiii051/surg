using Microsoft.Extensions.Caching.Memory;

namespace Surge.LicenseServer.Services;

/// <summary>
/// In-memory revocation list for refresh tokens, keyed by JTI and by rotation family.
///
/// <para>Purpose: detect <b>token reuse</b>. Refresh tokens are single-use and rotate on every
/// redemption. Once a JTI has been redeemed it goes on this list. If the same JTI ever shows up
/// again, exactly one of two things happened — the token was stolen and the thief is replaying it,
/// or the legitimate client is replaying a token the thief already spent. Either way the correct
/// response is to kill the whole family, which is what <see cref="RevokeFamily"/> does.</para>
///
/// <para>This is a cache in front of the database, not the source of truth: the durable
/// <c>Revoked</c>/<c>UsedUtc</c> columns still gate every decision, so a process restart cannot be
/// used to slip a replayed token past the check. Entries carry an absolute expiration matching the
/// remaining token lifetime, so the list is self-pruning and cannot grow without bound.</para>
/// </summary>
public sealed class TokenRevocationService : IDisposable
{
    private static readonly TimeSpan MinimumRetention = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaximumRetention = TimeSpan.FromDays(90);

    private readonly IMemoryCache _cache;
    private bool _disposed;

    public TokenRevocationService()
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 500_000,
            CompactionPercentage = 0.20,
            ExpirationScanFrequency = TimeSpan.FromMinutes(1)
        });
    }

    /// <summary>Records that a refresh token JTI has been redeemed and must never be accepted again.</summary>
    public void MarkRedeemed(string jti, DateTime tokenExpiresUtc)
    {
        if (string.IsNullOrWhiteSpace(jti)) return;
        Set("jti:" + jti, tokenExpiresUtc);
    }

    public bool IsRedeemed(string jti) =>
        !string.IsNullOrWhiteSpace(jti) && _cache.TryGetValue("jti:" + jti, out _);

    /// <summary>Revokes an entire rotation family after a reuse event.</summary>
    public void RevokeFamily(string familyId, DateTime familyExpiresUtc)
    {
        if (string.IsNullOrWhiteSpace(familyId)) return;
        Set("fam:" + familyId, familyExpiresUtc);
    }

    public bool IsFamilyRevoked(string familyId) =>
        !string.IsNullOrWhiteSpace(familyId) && _cache.TryGetValue("fam:" + familyId, out _);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        (_cache as IDisposable)?.Dispose();
    }

    private void Set(string key, DateTime expiresUtc)
    {
        var ttl = expiresUtc.ToUniversalTime() - DateTime.UtcNow;
        if (ttl < MinimumRetention) ttl = MinimumRetention;
        if (ttl > MaximumRetention) ttl = MaximumRetention;

        using var entry = _cache.CreateEntry(key);
        entry.Value = true;
        entry.Size = 1;
        entry.AbsoluteExpirationRelativeToNow = ttl;
    }
}
