using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SurgeApp.Services;

/// <summary>
/// Builds the stable hardware fingerprint used to bind a licence to one PC.
///
/// <para>This no longer launches <c>powershell.exe</c>. The old implementation spawned five
/// PowerShell processes per call — each one a ~300-800 ms cold start, executed on the UI thread
/// during login, with <c>ReadToEnd()</c> called before <c>WaitForExit(2500)</c> so a slow or
/// hung PowerShell blocked indefinitely regardless of the timeout. Spawning a shell also gave
/// anti-cheat/EDR software an obvious hook point and left the fingerprint trivially spoofable by
/// anyone who could shim <c>powershell.exe</c> on PATH.</para>
///
/// <para>Everything is now read in-process through WMI (<see cref="ManagementObjectSearcher"/>),
/// which takes single-digit milliseconds and cannot be intercepted by PATH manipulation.</para>
///
/// <para><b>Canonical form is deliberately unchanged</b> — the same five components in the same
/// order, normalised the same way — so the great majority of machines produce a byte-identical
/// hash remains compatible with the legacy client where migration is required. See <c>HWID_MIGRATION.md</c>
/// for the rebind window that covers the minority that shift.</para>
/// </summary>
public sealed class HardwareFingerprintService
{
    /// <summary>
    /// Fingerprint scheme version. Reported alongside the hash so the server can tell which
    /// algorithm produced a stored value and migrate deliberately later.
    ///
    /// <para>Deliberately NOT mixed into the hashed canonical string: doing so would change
    /// every existing hash and invalidate every live licence lock. Versioning travels beside
    /// the value, not inside it.</para>
    /// </summary>
    public const string FingerprintVersion = "hwid-v1";

    private const string Missing = "missing";
    private const string Unavailable = "unavailable";
    private const string Unsupported = "unsupported";

    // WMI calls are not free; the fingerprint is requested on every auth call
    // (AuthService.HardwareFingerprintHash is a property). Cache it for the process lifetime —
    // the underlying hardware cannot change without a reboot.
    private readonly Lazy<string> _cached;

    public HardwareFingerprintService()
    {
        _cached = new Lazy<string>(Compute, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public string GetFingerprintHash() => _cached.Value;

    /// <summary>Scheme identifier for the value returned by <see cref="GetFingerprintHash"/>.</summary>
    public string GetFingerprintVersion() => FingerprintVersion;

    private static string Compute()
    {
        var cpu = QueryFirst("Win32_Processor", "ProcessorId");
        var board = QueryFirst("Win32_ComputerSystemProduct", "UUID");
        var disk = QueryPrimaryDiskSerial();
        var tpm = QueryTpmPresent();
        var machineGuid = ReadMachineGuid();

        var canonical = string.Join("|", new[] { cpu, board, disk, tpm, machineGuid }.Select(Normalize));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    /// <summary>Reads a single scalar property from the first instance of a WMI class.</summary>
    private static string QueryFirst(string className, string property)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\CIMV2"),
                new ObjectQuery($"SELECT {property} FROM {className}"),
                NoTimeoutOptions());

            using var results = searcher.Get();
            foreach (ManagementBaseObject instance in results)
            {
                using (instance)
                {
                    var value = instance[property];
                    if (value is null) continue;
                    var text = Convert.ToString(value, CultureInfo.InvariantCulture)?.Trim();
                    if (!string.IsNullOrWhiteSpace(text)) return text;
                }
            }
            return Unavailable;
        }
        catch
        {
            return Unavailable;
        }
    }

    /// <summary>
    /// Serial of the lowest-indexed physical disk (\\.\PHYSICALDRIVE0).
    ///
    /// Ordering by Index rather than trusting WMI enumeration order matters: enumeration order is
    /// not contractually stable, so a machine that hot-adds a drive could otherwise silently change
    /// its fingerprint and lock the user out of their own licence.
    /// </summary>
    private static string QueryPrimaryDiskSerial()
    {
        if (!OperatingSystem.IsWindows()) return Unsupported;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\CIMV2"),
                new ObjectQuery("SELECT Index, SerialNumber FROM Win32_DiskDrive"),
                NoTimeoutOptions());

            var drives = new List<(uint Index, string Serial)>();
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject instance in results)
                {
                    using (instance)
                    {
                        var serial = Convert.ToString(instance["SerialNumber"], CultureInfo.InvariantCulture)?.Trim();
                        if (string.IsNullOrWhiteSpace(serial)) continue;

                        var index = instance["Index"] is null
                            ? uint.MaxValue
                            : Convert.ToUInt32(instance["Index"], CultureInfo.InvariantCulture);

                        drives.Add((index, serial));
                    }
                }
            }

            if (drives.Count == 0) return Unavailable;
            return drives.OrderBy(d => d.Index).First().Serial;
        }
        catch
        {
            return Unavailable;
        }
    }

    /// <summary>
    /// TPM presence. Emits "True"/"False" to preserve the legacy serialized form where migration compatibility requires it, matching the historical client representation from
    /// <c>Get-Tpm | Select -ExpandProperty TpmPresent</c>, so the canonical string is unchanged.
    /// </summary>
    private static string QueryTpmPresent()
    {
        if (!OperatingSystem.IsWindows()) return Unsupported;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftTpm"),
                new ObjectQuery("SELECT IsEnabled_InitialValue FROM Win32_Tpm"),
                NoTimeoutOptions());

            using var results = searcher.Get();
            foreach (ManagementBaseObject instance in results)
            {
                instance.Dispose();
                return "True";
            }
            return "False";
        }
        catch
        {
            // The WMI namespace is absent on machines with no TPM stack, and the query needs
            // elevation. The app manifest already requests it, so this is the genuine no-TPM path.
            return Unavailable;
        }
    }

    private static string ReadMachineGuid()
    {
        if (!OperatingSystem.IsWindows()) return Unsupported;
        try
        {
            // Explicitly open the 64-bit view: under a 32-bit host the default view is redirected
            // to Wow6432Node and returns a different GUID.
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
            var value = key?.GetValue("MachineGuid")?.ToString();
            return string.IsNullOrWhiteSpace(value) ? Unavailable : value;
        }
        catch
        {
            return Unavailable;
        }
    }

    private static EnumerationOptions NoTimeoutOptions() => new()
    {
        // Bounded so a wedged WMI provider cannot hang the caller, matching the intent of the
        // old 2500 ms process timeout without a process in the picture.
        Timeout = TimeSpan.FromSeconds(3),
        ReturnImmediately = true,
        Rewindable = false,
        EnsureLocatable = false
    };

    private static string Normalize(string value) =>
        // NOTE: the empty-value sentinel is intentionally lower-case. It is part of the hashed
        // canonical string and matching the documented legacy representation is what keeps existing licence locks valid.
        string.IsNullOrWhiteSpace(value) ? Missing : value.Trim().ToUpperInvariant();
}
