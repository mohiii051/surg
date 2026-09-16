using Microsoft.Extensions.Caching.Memory;

namespace Surge.LicenseServer.Services;

/// <summary>
/// Fixed-window rate limiter backed by <see cref="IMemoryCache"/>.
///
/// The previous implementation used a static <c>ConcurrentDictionary</c> that was never pruned:
/// every distinct IP+path pair allocated a counter that lived for the lifetime of the process,
/// so any scanner could grow the server's heap without bound. Entries now carry an absolute
/// expiration equal to the window they belong to, and the cache is size-capped so that even a
/// deliberate key-flooding attack cannot exhaust memory.
/// </summary>
public sealed class RateLimitService : IDisposable
{
    private const int StripeCount = 64;

    private readonly IMemoryCache _cache;
    private readonly object[] _stripes;
    private bool _disposed;

    public RateLimitService()
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            // Hard ceiling on tracked windows. Each entry declares Size = 1, so this is a
            // straight count of live counters (~200k * a few dozen bytes).
            SizeLimit = 200_000,
            CompactionPercentage = 0.25,
            ExpirationScanFrequency = TimeSpan.FromSeconds(30)
        });

        _stripes = new object[StripeCount];
        for (var i = 0; i < StripeCount; i++) _stripes[i] = new object();
    }

    /// <summary>
    /// Returns false once <paramref name="limit"/> requests have been seen for
    /// <paramref name="key"/> inside the current <paramref name="window"/>.
    /// </summary>
    public bool Allow(string key, int limit, TimeSpan window)
    {
        if (limit <= 0) return false;
        if (window <= TimeSpan.Zero) return true;

        var windowMs = (long)window.TotalMilliseconds;
        var bucket = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / windowMs;
        var cacheKey = string.Concat(key, "|", bucket.ToString(System.Globalization.CultureInfo.InvariantCulture));

        // Stripe the lock so GetOrCreate + increment is atomic per key without a global lock.
        // Without this, two concurrent requests can both create a fresh counter and a burst
        // briefly slips past the limit.
        var stripe = _stripes[(uint)cacheKey.GetHashCode(StringComparison.Ordinal) % StripeCount];
        lock (stripe)
        {
            if (!_cache.TryGetValue<Counter>(cacheKey, out var counter) || counter is null)
            {
                counter = new Counter();
                using var entry = _cache.CreateEntry(cacheKey);
                entry.Value = counter;
                entry.Size = 1;
                // The entry cannot outlive its own window, plus a small grace for clock skew.
                entry.AbsoluteExpirationRelativeToNow = window + TimeSpan.FromSeconds(5);
            }

            if (counter.Count >= limit) return false;
            counter.Count++;
            return true;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        (_cache as IDisposable)?.Dispose();
    }

    private sealed class Counter
    {
        public int Count;
    }
}
