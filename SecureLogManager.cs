using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SurgeApp.Services;

namespace SurgeApp;

public static class SecureLogManager
{
    private static readonly string Folder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Microsoft", ".surge");
    private static readonly string FilePath = Path.Combine(Folder, "log.bin");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public static void Write<T>(T data)
    {
        try
        {
            Directory.CreateDirectory(Folder);
            var payload = JsonSerializer.Serialize(data, JsonOptions);
            var prevHash = ReadLastHash();
            var hashInput = Encoding.UTF8.GetBytes(prevHash + "|" + payload);
            var hash = Convert.ToHexString(SHA256.HashData(hashInput));
            var envelope = new LogEnvelope(DateTime.UtcNow, prevHash, hash, payload);
            var plain = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(envelope, JsonOptions));
            var cipher = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
            using var fs = new FileStream(FilePath, FileMode.Append, FileAccess.Write, FileShare.Read);
            var b64 = Convert.ToBase64String(cipher);
            using var writer = new StreamWriter(fs, new UTF8Encoding(false), 1024, true);
            writer.WriteLine(b64);
            writer.Flush();
            try { File.SetAttributes(Folder, FileAttributes.Hidden | FileAttributes.System); } catch { }
            try { File.SetAttributes(FilePath, FileAttributes.Hidden | FileAttributes.System); } catch { }
        }
        catch
        {
            // Logging must never break a tweak operation.
        }
    }

    public static List<T> ReadAllVerified<T>()
    {
        var result = new List<T>();
        if (!File.Exists(FilePath)) return result;
        var expectedPrev = GenesisHash();
        foreach (var line in File.ReadLines(FilePath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var cipher = Convert.FromBase64String(line);
            var plain = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
            var envelope = JsonSerializer.Deserialize<LogEnvelope>(Encoding.UTF8.GetString(plain))
                ?? throw new InvalidDataException("Corrupt secure log entry.");
            var recomputed = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(envelope.PrevHash + "|" + envelope.Payload)));
            if (!recomputed.Equals(envelope.Hash, StringComparison.OrdinalIgnoreCase) ||
                !envelope.PrevHash.Equals(expectedPrev, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Secure log integrity check FAILED.");
            expectedPrev = envelope.Hash;
            var entry = JsonSerializer.Deserialize<T>(envelope.Payload, JsonOptions);
            if (entry is not null) result.Add(entry);
        }
        return result;
    }

    public static string ExportCsv(string destination)
    {
        var entries = ReadAllVerified<TweakLogEntry>();
        var sb = new StringBuilder();
        sb.AppendLine("TimeUtc,User,MachineId,TweakNumber,TweakTitle,Action,Outcome,VerificationState,Message,Commands,Exception");
        foreach (var e in entries)
        {
            var fields = new[]
            {
                e.TimestampUtc.ToString("o"), Environment.UserName, BackupEngine.MachineId,
                e.TweakNumber.ToString(), e.TweakTitle, e.Action, e.Outcome,
                e.VerificationState, e.Message, string.Join(" || ", e.Commands ?? Array.Empty<string>()), e.Exception ?? ""
            };
            sb.AppendLine(string.Join(",", Array.ConvertAll(fields, Quote)));
        }
        File.WriteAllText(destination, sb.ToString(), new UTF8Encoding(false));
        return destination;
    }

    public static string LogFile => FilePath;

    private static string ReadLastHash()
    {
        if (!File.Exists(FilePath)) return GenesisHash();
        string? last = null;
        foreach (var line in File.ReadLines(FilePath)) if (!string.IsNullOrWhiteSpace(line)) last = line;
        if (string.IsNullOrWhiteSpace(last)) return GenesisHash();
        try
        {
            var cipher = Convert.FromBase64String(last);
            var plain = ProtectedData.Unprotect(cipher, null, DataProtectionScope.CurrentUser);
            var envelope = JsonSerializer.Deserialize<LogEnvelope>(Encoding.UTF8.GetString(plain));
            return envelope?.Hash ?? GenesisHash();
        }
        catch { return GenesisHash(); }
    }

    private static string GenesisHash() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("SURGE-LOG-GENESIS")));
    private static string Quote(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
    private sealed record LogEnvelope(DateTime TimestampUtc, string PrevHash, string Hash, string Payload);
}
