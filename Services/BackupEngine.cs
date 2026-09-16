using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32;
using SurgeApp.Models;

namespace SurgeApp.Services;

public sealed class RegistryValueBackup
{
    public string Hive { get; set; } = "";
    public string Path { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = "";
    public string? Value { get; set; }
    public bool Existed { get; set; }
}

public sealed class ServiceBackup
{
    public string Name { get; set; } = "";
    public bool Exists { get; set; }
    public int StartTypeCode { get; set; }
    public bool Running { get; set; }
}

public sealed class PowerSettingBackup
{
    public string SubGroup { get; set; } = "";
    public string Setting { get; set; } = "";
    public int? AcIndex { get; set; }
    public int? DcIndex { get; set; }
}

public sealed class BcdEntryBackup
{
    public string Key { get; set; } = "";
    public string? Value { get; set; }
    public bool Existed { get; set; }
}

public sealed class NetworkSettingBackup
{
    public string Key { get; set; } = "";
    public string? Value { get; set; }
    public bool Existed { get; set; }
}

public sealed class FsutilSettingBackup
{
    public string Key { get; set; } = "";
    public int? Value { get; set; }
}

public sealed class SurgeBackup
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public string MachineId { get; set; } = "";
    public string UserName { get; set; } = "";
    public string Kind { get; set; } = "Tweak";
    public string TweakKey { get; set; } = "";
    public List<RegistryValueBackup> Registry { get; set; } = new();
    public List<ServiceBackup> Services { get; set; } = new();
    public List<PowerSettingBackup> Power { get; set; } = new();
    public List<BcdEntryBackup> Bcd { get; set; } = new();
    public List<NetworkSettingBackup> Network { get; set; } = new();
    public List<FsutilSettingBackup> Fsutil { get; set; } = new();
    public bool? HibernationEnabled { get; set; }
}

/// <summary>
/// Exact per-tweak snapshots. Payload is encrypted with the current Windows user's DPAPI
/// key and includes a hash inside the protected payload, so copying or editing the file
/// does not yield a usable plaintext snapshot.
/// </summary>
public sealed class BackupEngine
{
    private static readonly string RootDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Microsoft", ".surge");
    private static readonly string TweakDir = Path.Combine(RootDir, "backups");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    /// <summary>
    /// Application-specific DPAPI entropy.
    ///
    /// <para>Deliberately a fixed constant and NOT derived from the machine. Entropy exists so that
    /// another program running as the same Windows user cannot decrypt these blobs; it is not a
    /// second machine binding, and DPAPI's CurrentUser scope already provides that. Seeding entropy
    /// from anything mutable (machine name, user name, hardware) would reintroduce exactly the class
    /// of bug being fixed here: a rename silently destroying the user's ability to restore.</para>
    /// </summary>
    private static readonly byte[] DpapiEntropy =
        SHA256.HashData(Encoding.UTF8.GetBytes("SURGE-BACKUP-ENTROPY-v1"));

    private static readonly Lazy<string> MachineIdLazy = new(ComputeMachineId, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Stable machine+user identity stamped into each snapshot.
    ///
    /// <para>Previously this was <c>SHA256(Environment.MachineName + "|" + Environment.UserName)</c>,
    /// and <see cref="Load"/> treated a mismatch as a hard failure. Renaming the PC (or renaming the
    /// Windows account) therefore made every existing backup permanently unrestorable — the user
    /// could no longer revert tweaks that were already applied to their system.</para>
    ///
    /// <para>It is now derived from the registry MachineGuid (written once at Windows install; it
    /// survives renames and domain joins) and the account SID (stable across account renames, unlike
    /// the display name). Just as importantly, a mismatch is now advisory rather than fatal: DPAPI's
    /// CurrentUser scope has already proved the blob belongs to this user on this machine before the
    /// field is ever read.</para>
    /// </summary>
    public static string MachineId => MachineIdLazy.Value;

    /// <summary>Pre-v19.4 identity, kept so old snapshots are recognised and silently migrated.</summary>
    public static string LegacyMachineId =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName + "|" + Environment.UserName)))[..16];

    private static string ComputeMachineId()
    {
        var seed = ReadMachineGuid() + "|" + CurrentUserSid();
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(seed)))[..16];
    }

    private static string ReadMachineGuid()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
            var value = key?.GetValue("MachineGuid")?.ToString();
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        catch { /* fall through */ }
        return "no-machine-guid";
    }

    private static string CurrentUserSid()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var sid = identity.User?.Value;
            if (!string.IsNullOrWhiteSpace(sid)) return sid;
        }
        catch { /* fall through */ }
        return "no-sid";
    }

    public SurgeBackup CaptureTweakSnapshot(TweakItem tweak, out string? summary)
    {
        var snapshot = new SurgeBackup
        {
            Kind = "Tweak",
            TweakKey = Sanitize(tweak),
            MachineId = MachineId,
            UserName = Environment.UserName
        };
        CaptureCommands(tweak.SourceCommands, snapshot);
        summary = $"registry:{snapshot.Registry.Count} service:{snapshot.Services.Count} power:{snapshot.Power.Count} bcd:{snapshot.Bcd.Count} network:{snapshot.Network.Count} fsutil:{snapshot.Fsutil.Count}";
        Save(snapshot);
        return snapshot;
    }

    public string CaptureGlobalSnapshot(IEnumerable<TweakItem> tweaks)
    {
        var snapshot = new SurgeBackup
        {
            Kind = "Global",
            MachineId = MachineId,
            UserName = Environment.UserName
        };
        foreach (var tweak in tweaks) CaptureCommands(tweak.SourceCommands, snapshot);
        Save(snapshot);
        return snapshot.Id;
    }

    private static void CaptureCommands(IEnumerable<string> commands, SurgeBackup snapshot)
    {
        foreach (var raw in commands)
        {
            var command = raw.Trim();
            switch (TweakClassifier.Classify(command))
            {
                case TweakVerifyKind.Registry when RegistryProbe.TryParseRegAdd(command, out var r):
                    if (snapshot.Registry.Any(x => Same(x.Hive, r.hive) && Same(x.Path, r.path) && Same(x.Name, r.name))) break;
                    var old = RegistryProbe.Read(r.hive, r.path, r.name);
                    snapshot.Registry.Add(new RegistryValueBackup
                    {
                        Hive = r.hive, Path = r.path, Name = r.name,
                        Kind = old switch
                        {
                            int or uint or long or ulong => "REG_DWORD",
                            byte[] => "REG_BINARY",
                            string => "REG_SZ",
                            _ => old is null ? r.type : r.type
                        },
                        Value = old switch
                        {
                            null => null,
                            byte[] b => Convert.ToHexString(b),
                            _ => Convert.ToString(old)
                        },
                        Existed = old is not null
                    });
                    break;

                case TweakVerifyKind.Service:
                    var sm = Regex.Match(command, "sc\\s+(?:config|stop|start)\\s+(?:\"(?<n>[^\"]+)\"|(?<n>\\S+))", RegexOptions.IgnoreCase);
                    if (!sm.Success) break;
                    var name = sm.Groups["n"].Value;
                    if (snapshot.Services.Any(x => Same(x.Name, name))) break;
                    var service = ServiceVerifier.Capture(name);
                    snapshot.Services.Add(new ServiceBackup { Name = name, Exists = service.Exists, StartTypeCode = service.StartTypeCode, Running = service.Running });
                    break;

                case TweakVerifyKind.Power:
                    if (command.Equals("powercfg /hibernate off", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Power", false);
                            var hibernationValue = key?.GetValue("HibernateEnabled", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                            snapshot.HibernationEnabled = hibernationValue is int i ? i != 0 : null;
                        }
                        catch { snapshot.HibernationEnabled = null; }
                        break;
                    }
                    if (PowerVerifier.TryParseIndexCommand(command, out _, out var sub, out var setting, out _))
                    {
                        if (snapshot.Power.Any(x => Same(x.SubGroup, sub) && Same(x.Setting, setting))) break;
                        var power = PowerVerifier.Capture(sub, setting);
                        if (power is not null) snapshot.Power.Add(new PowerSettingBackup { SubGroup = sub, Setting = setting, AcIndex = power.Value.Ac, DcIndex = power.Value.Dc });
                    }
                    break;

                case TweakVerifyKind.Bcd when BcdVerifier.TryParseSet(command, out var bcdKey, out _):
                    if (snapshot.Bcd.Any(x => Same(x.Key, bcdKey))) break;
                    var bcd = BcdVerifier.CaptureRelevant();
                    snapshot.Bcd.Add(new BcdEntryBackup { Key = bcdKey, Value = bcd.TryGetValue(bcdKey, out var v) ? v : null, Existed = bcd.ContainsKey(bcdKey) });
                    break;

                case TweakVerifyKind.Network when NetworkVerifier.TryParseSet(command, out var netKey, out _):
                    if (snapshot.Network.Any(x => Same(x.Key, netKey))) break;
                    var net = NetworkVerifier.Capture(netKey);
                    snapshot.Network.Add(new NetworkSettingBackup { Key = netKey, Value = net, Existed = net is not null });
                    break;

                case TweakVerifyKind.Fsutil when FsutilVerifier.TryParseSet(command, out var fsKey, out _):
                    if (snapshot.Fsutil.Any(x => Same(x.Key, fsKey))) break;
                    snapshot.Fsutil.Add(new FsutilSettingBackup { Key = fsKey, Value = FsutilVerifier.Capture(fsKey) });
                    break;
            }
        }
    }

    public void Save(SurgeBackup snapshot)
    {
        Directory.CreateDirectory(TweakDir);
        try { File.SetAttributes(RootDir, FileAttributes.Hidden | FileAttributes.System); } catch { }
        var payloadJson = JsonSerializer.Serialize(snapshot, JsonOptions);
        var plain = Encoding.UTF8.GetBytes(payloadJson);
        var hash = Convert.ToHexString(SHA256.HashData(plain));
        var envelopeJson = JsonSerializer.Serialize(new ProtectedBackup(hash, snapshot.Id, Convert.ToBase64String(plain)), JsonOptions);
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(envelopeJson), DpapiEntropy, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(FileFor(snapshot), protectedBytes);
        try { File.SetAttributes(FileFor(snapshot), FileAttributes.Hidden | FileAttributes.System); } catch { }
    }

    public SurgeBackup Load(string idOrTweakKey)
    {
        var key = Path.GetFileNameWithoutExtension(idOrTweakKey);
        var file = Path.Combine(TweakDir, key.EndsWith(".bin", StringComparison.OrdinalIgnoreCase) ? key : key + ".bin");
        if (!File.Exists(file)) throw new FileNotFoundException($"Backup snapshot not found: {key}");

        var protectedBytes = File.ReadAllBytes(file);
        var envelopeJson = Encoding.UTF8.GetString(Unprotect(protectedBytes, out var neededMigration));

        var envelope = JsonSerializer.Deserialize<ProtectedBackup>(envelopeJson)
                       ?? throw new InvalidDataException("Backup envelope is invalid.");

        var plain = Convert.FromBase64String(envelope.PayloadBase64);
        var actualHash = Convert.ToHexString(SHA256.HashData(plain));
        if (!actualHash.Equals(envelope.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Backup integrity check FAILED.");

        var snapshot = JsonSerializer.Deserialize<SurgeBackup>(Encoding.UTF8.GetString(plain))
                       ?? throw new InvalidDataException("Backup payload is empty.");

        // The identity stamp is advisory only. Decryption above already proved, via DPAPI's
        // CurrentUser scope, that this blob belongs to this Windows account on this machine —
        // which is a strictly stronger guarantee than a string comparison. Treating a mismatch as
        // fatal is what made a PC rename destroy the user's ability to restore their own tweaks.
        var identityChanged = !snapshot.MachineId.Equals(MachineId, StringComparison.OrdinalIgnoreCase);
        if (identityChanged)
        {
            snapshot.MachineId = MachineId;
            snapshot.UserName = Environment.UserName;
        }

        // Re-stamp on disk so subsequent loads take the fast path.
        if (neededMigration || identityChanged)
        {
            try { Save(snapshot); } catch { /* restoring matters more than re-stamping */ }
        }

        return snapshot;
    }

    /// <summary>
    /// Decrypts a snapshot, accepting both the current entropy-protected format and the older
    /// null-entropy format written by v19.2 and earlier.
    /// </summary>
    private static byte[] Unprotect(byte[] protectedBytes, out bool wasLegacyFormat)
    {
        try
        {
            wasLegacyFormat = false;
            return ProtectedData.Unprotect(protectedBytes, DpapiEntropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            wasLegacyFormat = true;
            return ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
        }
    }

    public SurgeBackup? FindTweakBackup(TweakItem tweak)
    {
        var key = Sanitize(tweak);

        // Current secure location (v18+).
        var current = Path.Combine(TweakDir, key + ".bin");
        if (File.Exists(current))
            return Load(key);

        // Backward compatibility: tweaks applied by older Surge builds may
        // still have their pre-change snapshot in the previous ProgramData
        // location. Try the known legacy layouts and migrate only after a
        // successful integrity/decryption/identity check.
        foreach (var legacy in GetLegacyBackupCandidates(key))
        {
            if (!File.Exists(legacy)) continue;
            var snapshot = TryLoadLegacy(legacy);
            if (snapshot is null) continue;

            // Preserve the snapshot under the current protected store so a
            // second revert does not depend on the legacy format/location.
            try
            {
                snapshot.Kind = "Tweak";
                snapshot.TweakKey = key;
                Save(snapshot);
            }
            catch { }
            return snapshot;
        }

        return null;
    }

    private static IEnumerable<string> GetLegacyBackupCandidates(string key)
    {
        var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var roots = new[]
        {
            Path.Combine(common, "Surge", "Backups", "tweaks"),
            Path.Combine(common, "Surge", "Backups"),
            Path.Combine(common, "Surge", "Backups", "snapshots")
        };

        foreach (var root in roots)
        {
            yield return Path.Combine(root, key + ".json");
            yield return Path.Combine(root, key + ".bin");
        }
    }

    private static SurgeBackup? TryLoadLegacy(string file)
    {
        try
        {
            var bytes = File.ReadAllBytes(file);
            string json;

            // Plain JSON legacy snapshot.
            if (Path.GetExtension(file).Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                json = Encoding.UTF8.GetString(bytes);
            }
            else
            {
                // Older encrypted builds may have used either CurrentUser or
                // LocalMachine DPAPI. Prefer CurrentUser, then LocalMachine.
                byte[] plain;
                try
                {
                    plain = ProtectedData.Unprotect(bytes, DpapiEntropy, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException)
                {
                    try
                    {
                        plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
                    }
                    catch (CryptographicException)
                    {
                        plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine);
                    }
                }
                json = Encoding.UTF8.GetString(plain);
            }

            var snapshot = JsonSerializer.Deserialize<SurgeBackup>(json, JsonOptions);
            if (snapshot is null) return null;

            // Accept the current identity, the pre-v19.4 MachineName|UserName identity, or a
            // stamp we no longer recognise because the PC or account was renamed. In every case
            // the decryption above already established ownership; re-stamp and carry on.
            snapshot.MachineId = MachineId;
            snapshot.UserName = Environment.UserName;
            return snapshot;
        }
        catch
        {
            return null;
        }
    }

    public IReadOnlyList<string> ListSnapshots()
    {
        Directory.CreateDirectory(TweakDir);
        return Directory.GetFiles(TweakDir, "*.bin").Select(Path.GetFileNameWithoutExtension).Where(x => x is not null).Cast<string>().ToList();
    }

    public void Restore(SurgeBackup snapshot)
    {
        foreach (var r in snapshot.Registry) RestoreRegistry(r);
        foreach (var s in snapshot.Services) RestoreService(s);
        if (snapshot.HibernationEnabled is true) TryRun("powercfg.exe", "/hibernate", "on");
        else if (snapshot.HibernationEnabled is false) TryRun("powercfg.exe", "/hibernate", "off");
        foreach (var p in snapshot.Power) RestorePower(p);
        if (snapshot.Power.Count > 0) TryRun("powercfg.exe", "/setactive", "SCHEME_CURRENT");
        foreach (var b in snapshot.Bcd) RestoreBcd(b);
        foreach (var n in snapshot.Network) RestoreNetwork(n);
        foreach (var f in snapshot.Fsutil) RestoreFsutil(f);
    }

    public bool VerifyRestore(SurgeBackup snapshot)
    {
        foreach (var r in snapshot.Registry) if (!VerifyRegistry(r)) return false;
        if (snapshot.HibernationEnabled is not null && !PowerVerifier.IsHibernationOff() != snapshot.HibernationEnabled.Value) return false;
        foreach (var s in snapshot.Services) { var now = ServiceVerifier.Capture(s.Name); if (now.Exists != s.Exists || now.StartTypeCode != s.StartTypeCode || now.Running != s.Running) return false; }
        foreach (var p in snapshot.Power)
        {
            var now = PowerVerifier.Capture(p.SubGroup, p.Setting); if (now is null) return false;
            if (p.AcIndex is not null && now.Value.Ac != p.AcIndex) return false;
            if (p.DcIndex is not null && now.Value.Dc != p.DcIndex) return false;
        }
        foreach (var b in snapshot.Bcd)
        {
            var current = BcdVerifier.CaptureRelevant();
            if (b.Existed && (!current.TryGetValue(b.Key, out var v) || !Equals(v, b.Value))) return false;
            if (!b.Existed && current.ContainsKey(b.Key)) return false;
        }
        foreach (var n in snapshot.Network)
        {
            var current = NetworkVerifier.Capture(n.Key);
            if (n.Existed && !Equals(current, n.Value)) return false;
            if (!n.Existed && current is not null) return false;
        }
        foreach (var f in snapshot.Fsutil)
        {
            if (f.Value is null) continue;
            if (FsutilVerifier.Capture(f.Key) != f.Value) return false;
        }
        return true;
    }

    public void DeleteTweakBackup(TweakItem tweak)
    {
        var file = Path.Combine(TweakDir, Sanitize(tweak) + ".bin");
        try { if (File.Exists(file)) File.Delete(file); } catch { }
    }

    private static void RestoreRegistry(RegistryValueBackup r)
    {
        var root = GetRoot(r.Hive);
        using var key = root.CreateSubKey(r.Path, true) ?? throw new InvalidOperationException($"Unable to open registry key: {r.Hive}\\{r.Path}");
        if (!r.Existed) { key.DeleteValue(r.Name, false); return; }
        if (r.Kind.Equals("REG_DWORD", StringComparison.OrdinalIgnoreCase) && RegistryProbe.TryParseInteger(r.Value ?? "0", out var dword)) key.SetValue(r.Name, dword, RegistryValueKind.DWord);
        else if (r.Kind.Equals("REG_BINARY", StringComparison.OrdinalIgnoreCase)) key.SetValue(r.Name, Convert.FromHexString(r.Value ?? ""), RegistryValueKind.Binary);
        else key.SetValue(r.Name, r.Value ?? "", RegistryValueKind.String);
    }

    private static bool VerifyRegistry(RegistryValueBackup r)
    {
        var actual = RegistryProbe.Read(r.Hive, r.Path, r.Name);
        return r.Existed ? RegistryProbe.Equals(actual, r.Kind, r.Value ?? "") : actual is null;
    }

    private static void RestoreService(ServiceBackup s)
    {
        if (!s.Exists) return;
        // Restore is a write path: use the longer budget so a slow service transition is not
        // killed half-way, which would leave the machine in neither the tweaked nor the original state.
        try { ProcessRunner.Run("sc.exe", ProcessRunner.ApplyTimeoutMs, "config", s.Name, $"start= {ServiceVerifier.StartToken(s.StartTypeCode)}"); } catch { }
        try { ProcessRunner.Run("sc.exe", ProcessRunner.ApplyTimeoutMs, s.Running ? "start" : "stop", s.Name); } catch { }
    }

    private static void RestorePower(PowerSettingBackup p)
    {
        if (p.AcIndex is not null) TryRun("powercfg.exe", "/setacvalueindex", "SCHEME_CURRENT", p.SubGroup, p.Setting, p.AcIndex.Value.ToString(CultureInfo.InvariantCulture));
        if (p.DcIndex is not null) TryRun("powercfg.exe", "/setdcvalueindex", "SCHEME_CURRENT", p.SubGroup, p.Setting, p.DcIndex.Value.ToString(CultureInfo.InvariantCulture));
    }

    private static void RestoreBcd(BcdEntryBackup b)
    {
        if (b.Existed) TryRun("bcdedit.exe", "/set", b.Key, b.Value ?? "");
        else TryRun("bcdedit.exe", "/deletevalue", b.Key);
    }

    private static void RestoreNetwork(NetworkSettingBackup n)
    {
        if (!n.Existed || string.IsNullOrWhiteSpace(n.Value)) return;
        TryRun("netsh.exe", "int", "tcp", "set", "global", n.Key == "autotuninglevel" ? $"autotuninglevel={n.Value}" : n.Key == "rss" ? $"rss={n.Value}" : $"blackhole={n.Value}");
    }

    private static void RestoreFsutil(FsutilSettingBackup f)
    {
        if (f.Value is null) return;
        TryRun("fsutil.exe", "behavior", "set", f.Key, f.Value.Value.ToString(CultureInfo.InvariantCulture));
    }

    private static RegistryKey GetRoot(string hive) => hive.ToUpperInvariant() switch
    {
        "HKLM" => Registry.LocalMachine,
        "HKCU" => Registry.CurrentUser,
        "HKCR" => Registry.ClassesRoot,
        "HKU" => Registry.Users,
        _ => throw new ArgumentOutOfRangeException(nameof(hive))
    };

    private static void TryRun(string file, params string[] args)
    {
        // Every TryRun caller here is a restore operation (powercfg, bcdedit, netsh, fsutil),
        // so these get the write-path timeout rather than the probe timeout.
        try { ProcessRunner.Run(file, ProcessRunner.ApplyTimeoutMs, args); } catch { }
    }
    private static string FileFor(SurgeBackup snapshot) => Path.Combine(TweakDir, snapshot.Kind == "Tweak" ? snapshot.TweakKey + ".bin" : snapshot.Id + ".bin");
    private static string Sanitize(TweakItem t) => Regex.Replace(t.Number + "_" + t.Title, @"[^A-Za-z0-9_-]+", "_");
    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool Equals(string? a, string? b) => string.Equals(a?.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);
    private sealed record ProtectedBackup(string Sha256, string SnapshotId, string PayloadBase64);
}
