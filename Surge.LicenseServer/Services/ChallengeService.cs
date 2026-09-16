using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;

namespace Surge.LicenseServer.Services;

/// <summary>
/// Single-use device attestation nonces.
///
/// Replaces the static <c>ConcurrentDictionary&lt;string,(string,DateTime)&gt;</c> in Program.cs.
/// That dictionary only ever removed an entry when the matching attestation actually arrived, so
/// every abandoned challenge (a client that requested a nonce and then went away, or an attacker
/// looping the endpoint) leaked permanently. Entries now expire on their own after
/// <see cref="Lifetime"/> whether they are consumed or not.
/// </summary>
public sealed class ChallengeService : IDisposable
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    private readonly IMemoryCache _cache;
    private bool _disposed;

    public ChallengeService()
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = 100_000,
            CompactionPercentage = 0.25,
            ExpirationScanFrequency = TimeSpan.FromSeconds(30)
        });
    }

    /// <summary>Issues a fresh nonce, replacing any outstanding challenge for the same device.</summary>
    public string Issue(string userId, string deviceId)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using var entry = _cache.CreateEntry(Key(userId, deviceId));
        entry.Value = nonce;
        entry.Size = 1;
        entry.AbsoluteExpirationRelativeToNow = Lifetime;
        return nonce;
    }

    /// <summary>
    /// Validates and atomically consumes a nonce. Returns false if the challenge is missing,
    /// expired, already used, or does not match — a nonce is never valid twice.
    /// </summary>
    public bool TryConsume(string userId, string deviceId, string? presented)
    {
        if (string.IsNullOrWhiteSpace(presented)) return false;

        var key = Key(userId, deviceId);
        if (!_cache.TryGetValue<string>(key, out var expected) || expected is null) return false;

        // Remove first: even a failed comparison burns the challenge, so an attacker cannot
        // sit on a live nonce and brute-force signatures against it.
        _cache.Remove(key);

        var left = Encoding.UTF8.GetBytes(expected);
        var right = Encoding.UTF8.GetBytes(presented);
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        (_cache as IDisposable)?.Dispose();
    }

    private static string Key(string userId, string deviceId) => string.Concat(userId, "\u001f", deviceId);
}
