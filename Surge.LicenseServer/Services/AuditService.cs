using System.Text.Json;
using Surge.LicenseServer.Models;

namespace Surge.LicenseServer.Services;

public sealed class AuditService
{
    private readonly StoreService _store;
    public AuditService(StoreService store) => _store = store;

    public Task WriteAsync(string admin, string action, string targetType, string targetId, string ip, object? metadata = null) =>
        _store.WriteAsync(s =>
        {
            s.AuditLogs.Add(new AdminAuditRecord
            {
                Id = Guid.NewGuid().ToString("N"), Admin = admin, Action = action,
                TargetType = targetType, TargetId = targetId, IpAddress = ip,
                CreatedUtc = DateTime.UtcNow, Metadata = metadata is null ? null : JsonSerializer.Serialize(metadata)
            });
            if (s.AuditLogs.Count > 5000) s.AuditLogs.RemoveRange(0, s.AuditLogs.Count - 5000);
            return true;
        });
}
