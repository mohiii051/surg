using SurgeApp.Models;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SurgeApp.Services;

public sealed class AuthApiClient : IDisposable
{
    /// <summary>
    /// Fallback endpoint when SURGE_API_URL is not set.
    ///
    /// <para>The current deployment intentionally uses the public VPS IP over HTTP behind Nginx.
    /// This value is overrideable via SURGE_API_URL only in Debug builds.</para>
    /// </summary>
    private const string DefaultServerUrl = "http://95.38.233.67/api/license/";

    private readonly HttpClient _http;
    private readonly JsonSerializerOptions _json = new(JsonSerializerDefaults.Web);
    private bool _disposed;

    public string BaseUrl => _http.BaseAddress?.ToString() ?? string.Empty;

    public AuthApiClient() : this(
#if DEBUG
        Environment.GetEnvironmentVariable("SURGE_API_URL")
#else
        null
#endif
    ) { }

    public AuthApiClient(string? configuredUrl)
    {
        _http = CreateClient(NormalizeBaseUrl(configuredUrl));
    }

    /// <summary>
    /// Validates and canonicalises an endpoint. The current deployment intentionally supports
    /// plain HTTP because TLS is not being used on the public endpoint.
    /// </summary>
    public static string NormalizeBaseUrl(string? url)
    {
        var candidate = string.IsNullOrWhiteSpace(url) ? DefaultServerUrl : url.Trim();
        if (!candidate.EndsWith('/')) candidate += "/";

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"SURGE_API_URL is not a valid absolute URL: '{url}'.");

        if (uri.Scheme == Uri.UriSchemeHttps) return uri.ToString();

        // Public HTTP is intentionally supported by the current deployment.
        if (uri.Scheme == Uri.UriSchemeHttp) return uri.ToString();

        throw new InvalidOperationException(
            $"Unsupported API URL scheme '{uri.Scheme}'. Use http:// or https://.");
    }

    private static HttpClient CreateClient(string baseUrl)
    {
        var handler = new SocketsHttpHandler
        {
            // The server is reached directly; the Windows system proxy has previously produced
            // misleading 503s on reachable hosts.
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = new SslClientAuthenticationOptions
            {
                // TLS 1.2 floor. Never negotiate SSL 3.0 / TLS 1.0 / TLS 1.1, and never
                // install a callback that would accept an invalid chain.
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                // The production endpoint uses a Let's Encrypt IP-address certificate, which is
                // issued only under the 160-hour 'shortlived' profile. Such certificates qualify
                // as Short-Lived Subscriber Certificates and are not required to carry revocation
                // information; Let's Encrypt documents that the CRL URL they still include today
                // may be withdrawn. Demanding an online revocation answer therefore buys nothing
                // over a six-day window and risks hard-failing on a chain that is perfectly valid.
                // Chain and hostname validation are unchanged and still enforced.
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }
        };

        var client = new HttpClient(handler)
        {
            BaseAddress = new Uri(baseUrl),
            Timeout = TimeSpan.FromSeconds(15)
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd($"Surge/{ClientVersion}");
        return client;
    }

    /// <summary>Client version, read from the assembly rather than a hardcoded literal.</summary>
    public static string ClientVersion =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    public async Task<(string Latest, string Minimum, bool Force)> CheckVersionAsync(CancellationToken ct = default)
    {
        using var response = await _http.GetAsync("api/version/check", ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var value = await response.Content.ReadFromJsonAsync<VersionResult>(_json, ct).ConfigureAwait(false);
        return value is null
            ? (ClientVersion, "0.0.0", false)
            : (value.Latest, string.IsNullOrWhiteSpace(value.Minimum) ? "0.0.0" : value.Minimum, value.Force);
    }

    private sealed record VersionResult(string Latest, string? Minimum, bool Force);

    public Task<AuthResponse> LoginAsync(LoginRequest request, CancellationToken ct = default) =>
        PostAsync<LoginRequest, AuthResponse>("api/auth/login", request, ct);

    public Task<AuthResponse> RegisterAsync(RegisterRequest request, CancellationToken ct = default) =>
        PostAsync<RegisterRequest, AuthResponse>("api/auth/register", request, ct);

    public Task<AuthResponse> RefreshAsync(RefreshRequest request, CancellationToken ct = default) =>
        PostAsync<RefreshRequest, AuthResponse>("api/auth/refresh", request, ct);

    public Task LogoutAsync(string accessToken, string refreshToken, string deviceId, CancellationToken ct = default) =>
        SendAsync("api/auth/logout", HttpMethod.Post, new RefreshRequest(refreshToken, deviceId), accessToken, ct);

    public Task RegisterDeviceAsync(string accessToken, string deviceId, string publicKey, string fingerprint, CancellationToken ct = default) =>
        SendAsync("api/devices/register", HttpMethod.Post,
            new { deviceId, publicKeyBase64 = publicKey, hardwareFingerprintHash = fingerprint, displayName = Environment.MachineName },
            accessToken, ct);

    public Task<ChallengeDto> GetChallengeAsync(string accessToken, string deviceId, CancellationToken ct = default) =>
        GetAsync<ChallengeDto>("api/devices/challenge?deviceId=" + Uri.EscapeDataString(deviceId), accessToken, ct);

    public Task AttestAsync(string accessToken, DeviceAttestationRequest request, CancellationToken ct = default) =>
        SendAsync("api/devices/attest", HttpMethod.Post, request, accessToken, ct);

    public Task<LicenseState> GetLicenseStateAsync(string accessToken, string deviceId, CancellationToken ct = default) =>
        GetAsync<LicenseState>("api/licenses/state?deviceId=" + Uri.EscapeDataString(deviceId), accessToken, ct);

    public Task<LicenseDto> ActivateAsync(string accessToken, ActivateLicenseRequest request, CancellationToken ct = default) =>
        PostAsync<ActivateLicenseRequest, LicenseDto>("api/licenses/activate", request, ct, accessToken);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _http.Dispose();
    }

    // ------------------------------------------------------------------ transport

    private async Task<TResponse> PostAsync<TRequest, TResponse>(string path, TRequest body, CancellationToken ct, string? token = null)
    {
        using var response = await SendCoreAsync(path, HttpMethod.Post, body, token, ct).ConfigureAwait(false);
        var result = await response.Content.ReadFromJsonAsync<TResponse>(_json, ct).ConfigureAwait(false);
        if (result is null) throw new InvalidOperationException("Server returned an empty response.");
        return result;
    }

    private async Task<T> GetAsync<T>(string path, string token, CancellationToken ct)
    {
        using var response = await SendCoreAsync(path, HttpMethod.Get, null, token, ct).ConfigureAwait(false);
        var result = await response.Content.ReadFromJsonAsync<T>(_json, ct).ConfigureAwait(false);
        if (result is null) throw new InvalidOperationException("Server returned an empty response.");
        return result;
    }

    private async Task SendAsync(string path, HttpMethod method, object body, string token, CancellationToken ct)
    {
        using var response = await SendCoreAsync(path, method, body, token, ct).ConfigureAwait(false);
        await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendCoreAsync(string path, HttpMethod method, object? body, string? token, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = JsonContent.Create(body, options: _json);
        if (!string.IsNullOrWhiteSpace(token))
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (response.IsSuccessStatusCode) return response;

        // Read the status before disposing, then always release the failed response so the
        // connection returns to the pool instead of leaking.
        var statusCode = (int)response.StatusCode;
        var reason = response.ReasonPhrase;
        string friendly;
        try
        {
            var message = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            friendly = string.IsNullOrWhiteSpace(message) ? reason ?? "Request failed." : message;
            using var doc = JsonDocument.Parse(message);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                if (doc.RootElement.TryGetProperty("message", out var msg)) friendly = msg.GetString() ?? friendly;
                else if (doc.RootElement.TryGetProperty("title", out var title)) friendly = title.GetString() ?? friendly;
            }
        }
        catch
        {
            friendly = reason ?? "Request failed.";
        }
        finally
        {
            response.Dispose();
        }

        throw new HttpRequestException($"HTTP {statusCode}: {friendly}");
    }
}
