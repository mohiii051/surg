namespace Surge.LicenseServer.Models;

public sealed class StoreRoot
{
    public List<UserRecord> Users { get; set; } = new();
    public List<DeviceRecord> Devices { get; set; } = new();
    public List<LicenseRecord> Licenses { get; set; } = new();
    public List<RefreshRecord> RefreshTokens { get; set; } = new();
    public List<AdminAuditRecord> AuditLogs { get; set; } = new();
}

public sealed class UserRecord
{
    public string Id { get; set; } = "";
    public string Email { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public bool Active { get; set; } = true;
    public DateTime? DisabledUtc { get; set; }
    public string? DisabledReason { get; set; }
}

public sealed class DeviceRecord
{
    public string Id { get; set; } = "";
    public string UserId { get; set; } = "";
    public List<string> AccountUserIds { get; set; } = new();
    public string DisplayName { get; set; } = "";
    public string PublicKeyBase64 { get; set; } = "";
    public string HardwareFingerprintHash { get; set; } = "";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public bool Active { get; set; } = true;
    public bool Blocked { get; set; }
}

public sealed class LicenseRecord
{
    public string Id { get; set; } = "";
    public string KeyHash { get; set; } = "";
    public string? LegacySha256Hash { get; set; }
    public string KeyMasked { get; set; } = "";
    public string Plan { get; set; } = "PRO";
    public int MaxDevices { get; set; } = 1;
    public string? OwnerUserId { get; set; }
    public bool Locked { get; set; }
    public string? LockedDeviceId { get; set; }
    public string? HardwareFingerprintHash { get; set; }
    public DateTime? LockedUtc { get; set; }
    public bool Banned { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public List<string> ActiveDeviceIds { get; set; } = new();
}

/// <summary>
/// A single rotated refresh token.
///
/// <para><b>Jti</b> uniquely identifies this token and is the key used by the in-memory
/// revocation list. <b>FamilyId</b> is shared by every token descended from one login: if a
/// already-redeemed JTI is presented again (the classic stolen-token signature) the entire
/// family is revoked at once, which logs out both the attacker and the victim.</para>
/// </summary>
public sealed class RefreshRecord
{
    /// <summary>SHA-256 of the full opaque token. Primary key; the raw token is never stored.</summary>
    public string Hash { get; set; } = "";

    /// <summary>Public, non-secret identifier embedded in the token, used for revocation lookups.</summary>
    public string Jti { get; set; } = "";

    /// <summary>Rotation family. Constant for the lifetime of one login chain.</summary>
    public string FamilyId { get; set; } = "";

    public string UserId { get; set; } = "";

    /// <summary>Device the token was issued to, so a token cannot be replayed from another machine.</summary>
    public string? DeviceId { get; set; }

    public DateTime CreatedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }

    /// <summary>Hard ceiling for the whole rotation chain; rotation can never push past this.</summary>
    public DateTime FamilyExpiresUtc { get; set; }

    public bool Revoked { get; set; }

    /// <summary>Set the moment the token is redeemed. Any second redemption is reuse.</summary>
    public DateTime? UsedUtc { get; set; }

    public string? ReplacedByJti { get; set; }
}

public sealed class AdminAuditRecord
{
    public string Id { get; set; } = "";
    public string Admin { get; set; } = "";
    public string Action { get; set; } = "";
    public string TargetType { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public string? Metadata { get; set; }
}
