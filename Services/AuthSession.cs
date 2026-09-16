using SurgeApp.Models;
using System;
using System.Collections.Generic;

namespace SurgeApp.Services;

public sealed class AuthSession
{
    private AuthSession(AuthResponse auth, LicenseState state, string deviceId)
    {
        AccessToken = auth.AccessToken;
        RefreshToken = auth.RefreshToken;
        AccessTokenExpiresUtc = auth.AccessTokenExpiresUtc;
        User = state.User;
        Device = state.Device;
        Licenses = state.Licenses;
        ActiveLicense = state.ActiveLicense;
        DeviceId = deviceId;
    }

    public string AccessToken { get; private set; }
    public string RefreshToken { get; private set; }
    public DateTime AccessTokenExpiresUtc { get; private set; }
    public UserDto User { get; private set; }
    public DeviceDto Device { get; private set; }
    public IReadOnlyList<LicenseDto> Licenses { get; private set; }
    public LicenseDto? ActiveLicense { get; private set; }
    public string DeviceId { get; }

    public static AuthSession From(AuthResponse auth, LicenseState state, string deviceId) => new(auth, state, deviceId);

    public void Update(AuthResponse auth, LicenseState state)
    {
        AccessToken = auth.AccessToken;
        RefreshToken = auth.RefreshToken;
        AccessTokenExpiresUtc = auth.AccessTokenExpiresUtc;
        User = state.User;
        Device = state.Device;
        Licenses = state.Licenses;
        ActiveLicense = state.ActiveLicense;
    }

    public void SetActiveLicense(LicenseDto? license) => ActiveLicense = license;

    public void UpdateFromState(LicenseState state)
    {
        User = state.User;
        Device = state.Device;
        Licenses = state.Licenses;
        ActiveLicense = state.ActiveLicense;
    }
}
