using Microsoft.Win32;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SurgeApp.Services;

public sealed class DeviceIdentityService
{
    private sealed record StoredIdentity(string DeviceId, string PublicKeyBase64, string PrivateKeyBase64);

    private readonly SecureStore _store = new();
    private readonly ECDsa _key;

    public string DeviceId { get; }
    public string PublicKeyBase64 { get; }

    public DeviceIdentityService()
    {
        var saved = _store.Load("device-identity");
        if (!string.IsNullOrWhiteSpace(saved))
        {
            try
            {
                var identity = JsonSerializer.Deserialize<StoredIdentity>(saved);
                if (identity is not null)
                {
                    _key = ECDsa.Create();
                    _key.ImportPkcs8PrivateKey(Convert.FromBase64String(identity.PrivateKeyBase64), out _);
                    DeviceId = identity.DeviceId;
                    PublicKeyBase64 = identity.PublicKeyBase64;
                    return;
                }
            }
            catch { }
        }

        using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = Convert.ToBase64String(generated.ExportPkcs8PrivateKey());
        PublicKeyBase64 = Convert.ToBase64String(generated.ExportSubjectPublicKeyInfo());
        DeviceId = BuildDeviceId(PublicKeyBase64);

        _key = ECDsa.Create();
        _key.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
        _store.Save("device-identity", JsonSerializer.Serialize(
            new StoredIdentity(DeviceId, PublicKeyBase64, privateKey)));
    }

    public string Sign(string text)
    {
        return Convert.ToBase64String(
            _key.SignData(Encoding.UTF8.GetBytes(text), HashAlgorithmName.SHA256));
    }

    private static string BuildDeviceId(string publicKeyBase64)
    {
        var machineId = ReadMachineGuid();
        return Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(machineId + "|" + publicKeyBase64)))
            .ToLowerInvariant()[..32];
    }

    private static string ReadMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString() ?? Environment.MachineName;
        }
        catch { return Environment.MachineName; }
    }
}
