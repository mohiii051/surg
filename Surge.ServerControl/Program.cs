using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ---------------------------------------------------------------------------
// Surge.ServerControl
//
// This process can start, stop and restart the license server through sudo/systemctl.
// It is therefore the highest-value target in the whole deployment, and it must never be
// reachable from outside the machine. Two independent controls enforce that:
//
//   1. The listener is pinned to loopback. A SURGE_CONTROL_URL that resolves to anything
//      else is rejected at startup rather than silently honoured, which is what the old
//      "http://0.0.0.0:5078" default did — that exposed systemctl control to the internet
//      to anyone who could forge or replay an admin bearer token.
//   2. Every request must carry X-Surge-Control-Secret matching SURGE_CONTROL_SECRET, in
//      addition to a valid admin bearer token. The secret is mandatory: the service refuses
//      to start without one, so there is no insecure default to forget about.
// ---------------------------------------------------------------------------

const string SecretHeader = "X-Surge-Control-Secret";
const string ServiceUnit = "surge-license.service";

var controlSecret = Environment.GetEnvironmentVariable("SURGE_CONTROL_SECRET");
if (string.IsNullOrWhiteSpace(controlSecret) || controlSecret.Trim().Length < 32)
    throw new InvalidOperationException(
        "SURGE_CONTROL_SECRET must be set to at least 32 characters before Surge.ServerControl can start. " +
        "Generate one with: openssl rand -base64 48");

var controlSecretBytes = Encoding.UTF8.GetBytes(controlSecret.Trim());

var requestedUrl = Environment.GetEnvironmentVariable("SURGE_CONTROL_URL") ?? "http://127.0.0.1:5078";
foreach (var url in requestedUrl.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        throw new InvalidOperationException($"SURGE_CONTROL_URL is not a valid URL: '{url}'.");
    if (!uri.IsLoopback && !string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        throw new InvalidOperationException(
            $"Surge.ServerControl may only bind to loopback. Refusing to start on '{url}'. " +
            "Use http://127.0.0.1:5078 and reach it through the license server's admin proxy.");
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(requestedUrl);
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 16 * 1024;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
});

var app = builder.Build();
var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Surge.ServerControl");
var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

// Defence in depth: even if the binding were somehow widened, drop anything non-loopback.
app.Use(async (ctx, next) =>
{
    var remote = ctx.Connection.RemoteIpAddress;
    if (remote is null || !IPAddress.IsLoopback(remote))
    {
        logger.LogWarning("Rejected non-loopback control request from {Remote}.", remote);
        ctx.Response.StatusCode = 403;
        await ctx.Response.WriteAsJsonAsync(new { message = "Forbidden." });
        return;
    }

    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    await next();
});

// Mandatory shared secret on every route.
app.Use(async (ctx, next) =>
{
    if (!HasValidSecret(ctx.Request))
    {
        logger.LogWarning("Rejected control request with missing or invalid {Header}.", SecretHeader);
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { message = "Unauthorized." });
        return;
    }
    await next();
});

app.MapGet("/api/control/health", () => Results.Ok(new { ok = true, service = "Surge Server Control", version }));

app.MapGet("/api/control/status", async (HttpRequest request) =>
{
    if (ReadAdmin(request) is null) return Results.Json(new { message = "Forbidden." }, statusCode: 403);

    var (code, output) = await RunAsync("/usr/bin/systemctl", new[] { "is-active", ServiceUnit });
    var state = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? "unknown";
    // systemctl is-active exits non-zero for inactive units, which is not an error here.
    var running = code == 0 && string.Equals(state, "active", StringComparison.OrdinalIgnoreCase);
    return Results.Ok(new
    {
        running,
        detail = running ? "License server is accepting requests." : $"License server status: {state}."
    });
});

app.MapPost("/api/control/{action}", async (HttpRequest request, string action) =>
{
    if (ReadAdmin(request) is null) return Results.Json(new { message = "Forbidden." }, statusCode: 403);
    if (action is not ("start" or "stop" or "restart")) return Results.NotFound(new { message = "Unknown server control action." });

    var (code, output) = await RunAsync("/usr/bin/sudo", new[] { "/bin/systemctl", action, ServiceUnit });
    if (code != 0)
    {
        logger.LogError("systemctl {Action} failed with exit code {Code}: {Output}", action, code, output);
        return Results.Json(new { message = $"systemctl {action} failed.", detail = output }, statusCode: 500);
    }
    logger.LogInformation("systemctl {Action} completed.", action);
    return Results.Ok(new { ok = true, action, detail = output });
});

app.Run();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

bool HasValidSecret(HttpRequest request)
{
    if (!request.Headers.TryGetValue(SecretHeader, out var values)) return false;
    var presented = values.ToString();
    if (string.IsNullOrEmpty(presented)) return false;
    var presentedBytes = Encoding.UTF8.GetBytes(presented.Trim());
    return presentedBytes.Length == controlSecretBytes.Length &&
           CryptographicOperations.FixedTimeEquals(presentedBytes, controlSecretBytes);
}

static string? ReadAdmin(HttpRequest request)
{
    var header = request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
    var token = header[7..].Trim();

    var dataPath = Environment.GetEnvironmentVariable("SURGE_DATA_PATH") ?? "/opt/surge/data";
    var secretPath = Path.Combine(dataPath, "token.secret");
    var configuredUser = Environment.GetEnvironmentVariable("SURGE_ADMIN_USER") ?? "admin";

    try
    {
        if (!File.Exists(secretPath)) return null;
        var secret = Convert.FromBase64String(File.ReadAllText(secretPath).Trim());

        var parts = token.Split('.');
        if (parts.Length != 3) return null;

        var body = parts[0] + "." + parts[1];
        var signature = FromB64(parts[2]);
        if (!CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(body)), signature)) return null;

        using var doc = JsonDocument.Parse(FromB64(parts[1]));
        var root = doc.RootElement;
        if (!root.TryGetProperty("typ", out var typ) || !string.Equals(typ.GetString(), "admin", StringComparison.Ordinal)) return null;
        if (!root.TryGetProperty("exp", out var exp) || exp.GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;

        var subject = root.TryGetProperty("sub", out var sub) ? sub.GetString() : null;
        return string.Equals(subject, configuredUser, StringComparison.Ordinal) ? subject : null;
    }
    catch
    {
        return null;
    }
}

static byte[] FromB64(string text)
{
    var s = text.Replace('-', '+').Replace('_', '/');
    s += new string('=', (4 - s.Length % 4) % 4);
    return Convert.FromBase64String(s);
}

/// <summary>
/// Runs a process and collects both streams concurrently with a hard timeout.
///
/// The previous version called ReadToEnd() on stdout before WaitForExit(), which deadlocks the
/// moment a child writes more than one pipe buffer to stderr, and had no timeout at all — a
/// wedged systemctl would pin the request thread forever.
/// </summary>
static async Task<(int Code, string Output)> RunAsync(string fileName, string[] arguments, int timeoutMs = 15_000)
{
    var startInfo = new ProcessStartInfo(fileName)
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };
    foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

    using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start {fileName}.");
    using var cts = new CancellationTokenSource(timeoutMs);

    var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token).AsTask();
    var stderrTask = process.StandardError.ReadToEndAsync(cts.Token).AsTask();

    try
    {
        await process.WaitForExitAsync(cts.Token);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        return (process.ExitCode, (stdout + "\n" + stderr).Trim());
    }
    catch (OperationCanceledException)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { /* already gone */ }
        return (-1, $"Timed out after {timeoutMs} ms.");
    }
}
