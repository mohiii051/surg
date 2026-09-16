using System;
using System.Collections.Generic;

namespace SurgeApp.Models;

public sealed record LoginRequest(string Email, string Password, string DeviceId, string DevicePublicKey, string HardwareFingerprintHash);
public sealed record RegisterRequest(string Email, string Password, string DeviceId, string DevicePublicKey, string HardwareFingerprintHash);
public sealed record RefreshRequest(string RefreshToken, string DeviceId);
public sealed record AuthResponse(string AccessToken, string RefreshToken, DateTime AccessTokenExpiresUtc, UserDto User);
public sealed record UserDto(string Id, string Email, DateTime CreatedUtc);
public sealed record LicenseDto(string Id, string LicenseKeyMasked, string Plan, int MaxDevices, int ActiveDevices, bool ActivatedOnThisDevice, DateTime? ExpiresUtc);
public sealed record DeviceDto(string Id, string DisplayName, DateTime FirstSeenUtc, DateTime LastSeenUtc, bool Active);
public sealed record LicenseState(UserDto User, IReadOnlyList<LicenseDto> Licenses, LicenseDto? ActiveLicense, DeviceDto Device);
public sealed record ChallengeDto(string Nonce);
public sealed record DeviceAttestationRequest(string DeviceId, string Nonce, string SignatureBase64);
public sealed record ActivateLicenseRequest(string LicenseKey, string DeviceId, string SignatureBase64, string Nonce);
public sealed record MessageResponse(string Message);
