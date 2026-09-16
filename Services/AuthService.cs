using SurgeApp.Models;
using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SurgeApp.Services;

public sealed class AuthService
{
    private const string SessionKey = "auth-session";
    public DeviceIdentityService Device { get; } = new();
    public AuthApiClient Api { get; } = new();
    public string ServerUrl => Api.BaseUrl;
    private readonly SecureStore _secure = new();
    private readonly HardwareFingerprintService _hardware = new();

    /// <summary>
    /// Hardware fingerprint for this machine. Cheap to call repeatedly: the underlying service
    /// computes it once per process. It used to spawn five PowerShell processes on every read,
    /// and this property is read on every login, refresh, register and attest call.
    /// </summary>
    public string HardwareFingerprintHash => _hardware.GetFingerprintHash();

    public async Task<(AuthSession? Session, string? Error)> TryRestoreAsync(CancellationToken ct = default)
    {
        // No offline mode: a stored refresh token is never trusted by itself.
        // Restore always requires a live server refresh + device attestation + license-state read.
        var raw = _secure.Load(SessionKey);
        if (string.IsNullOrWhiteSpace(raw)) return (null, null);
        try
        {
            var snapshot = JsonSerializer.Deserialize<StoredSession>(raw);
            if (snapshot is null) return (null, null);
            var auth = await Api.RefreshAsync(new RefreshRequest(snapshot.RefreshToken, Device.DeviceId), ct);
            await Api.RegisterDeviceAsync(auth.AccessToken, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash, ct);
            await AttestAsync(auth.AccessToken, ct);
            var state = await Api.GetLicenseStateAsync(auth.AccessToken, Device.DeviceId, ct);
            var session = AuthSession.From(auth, state, Device.DeviceId);
            Save(session);
            return (session, null);
        }
        catch (Exception ex)
        {
            _secure.Delete(SessionKey);
            return (null, ex.Message);
        }
    }

    public async Task<(AuthSession? Session, string? Error)> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            var auth = await Api.LoginAsync(new LoginRequest(email.Trim(), password, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash), ct);
            await Api.RegisterDeviceAsync(auth.AccessToken, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash, ct);
            await AttestAsync(auth.AccessToken, ct);
            var state = await Api.GetLicenseStateAsync(auth.AccessToken, Device.DeviceId, ct);
            return (AuthSession.From(auth, state, Device.DeviceId), null);
        }
        catch (Exception ex) { return (null, ex.Message); }
    }

    public async Task<(AuthSession? Session, string? Error)> RegisterAsync(string email, string password, CancellationToken ct = default)
    {
        try
        {
            var auth = await Api.RegisterAsync(new RegisterRequest(email.Trim(), password, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash), ct);
            await Api.RegisterDeviceAsync(auth.AccessToken, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash, ct);
            await AttestAsync(auth.AccessToken, ct);
            var state = await Api.GetLicenseStateAsync(auth.AccessToken, Device.DeviceId, ct);
            return (AuthSession.From(auth, state, Device.DeviceId), null);
        }
        catch (Exception ex) { return (null, ex.Message); }
    }

    public async Task<LicenseDto> ActivateAsync(AuthSession session, string licenseKey, CancellationToken ct = default)
    {
        var challenge = await Api.GetChallengeAsync(session.AccessToken, Device.DeviceId, ct);
        var sig = Device.Sign(challenge.Nonce);
        var license = await Api.ActivateAsync(session.AccessToken,
            new ActivateLicenseRequest(licenseKey.Trim(), Device.DeviceId, sig, challenge.Nonce), ct);
        session.SetActiveLicense(license);
        Save(session);
        return license;
    }

    public async Task<AuthSession> EnsureFreshAsync(AuthSession session, CancellationToken ct = default)
    {
        if (session.AccessTokenExpiresUtc > DateTime.UtcNow.AddMinutes(2))
            return session;

        var auth = await Api.RefreshAsync(new RefreshRequest(session.RefreshToken, Device.DeviceId), ct);
        await Api.RegisterDeviceAsync(auth.AccessToken, Device.DeviceId, Device.PublicKeyBase64, HardwareFingerprintHash, ct);
        await AttestAsync(auth.AccessToken, ct);
        var state = await Api.GetLicenseStateAsync(auth.AccessToken, Device.DeviceId, ct);
        session.Update(auth, state);
        Save(session);
        return session;
    }

    public async Task AttestAsync(string accessToken, CancellationToken ct = default)
    {
        var challenge = await Api.GetChallengeAsync(accessToken, Device.DeviceId, ct);
        var sig = Device.Sign(challenge.Nonce);
        await Api.AttestAsync(accessToken, new DeviceAttestationRequest(Device.DeviceId, challenge.Nonce, sig), ct);
    }

    public void Save(AuthSession session)
    {
        _secure.Save(SessionKey, JsonSerializer.Serialize(new StoredSession(session.RefreshToken)));
    }

    public async Task<LicenseState> ValidateOnlineAsync(AuthSession session, CancellationToken ct = default)
    {
        // Strict online policy: refresh/attest/state must all succeed immediately.
        var fresh = await EnsureFreshAsync(session, ct);
        await AttestAsync(fresh.AccessToken, ct);
        var state = await Api.GetLicenseStateAsync(fresh.AccessToken, fresh.DeviceId, ct);
        fresh.UpdateFromState(state);
        Save(fresh);
        return state;
    }

    public async Task SignOutAsync(AuthSession session, CancellationToken ct = default)
    {
        // Pass the device id so the server can verify the token belongs to this machine before
        // burning the whole rotation family.
        try { await Api.LogoutAsync(session.AccessToken, session.RefreshToken, Device.DeviceId, ct); } catch { }
        _secure.Delete(SessionKey);
    }

    public void ClearLocalSession() => _secure.Delete(SessionKey);

    private sealed record StoredSession(string RefreshToken);
}
