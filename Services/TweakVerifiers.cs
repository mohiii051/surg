using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace SurgeApp.Services;

public enum TweakVerifyKind { Registry, Service, Bcd, Power, Network, Fsutil, Unsupported }

/// <summary>
/// Runs short-lived console tools (sc.exe, powercfg.exe, netsh.exe, fsutil.exe, bcdedit.exe)
/// and returns their stdout.
///
/// <para>The previous implementation had two defects that together produced the reported UI
/// freezes:</para>
/// <list type="number">
/// <item><description><b>Classic pipe deadlock.</b> It called <c>StandardOutput.ReadToEnd()</c>
/// to completion and only then read stderr. A child that fills the ~4 KB stderr pipe buffer
/// blocks on write, never exits, and never closes stdout — so the parent blocks forever inside
/// the first read. <c>bcdedit /enum</c> and <c>netsh int tcp show global</c> both produce enough
/// output to hit this.</description></item>
/// <item><description><b>No timeout.</b> <c>WaitForExit()</c> was called with no argument, so any
/// wedged child (a hung service query is the usual culprit) pinned the calling thread
/// indefinitely. Scans run dozens of these per pass.</description></item>
/// </list>
///
/// <para>Both streams are now drained concurrently by the runtime's own reader threads via the
/// <c>OutputDataReceived</c>/<c>ErrorDataReceived</c> events, and every wait is bounded by
/// <see cref="DefaultTimeoutMs"/>. On timeout the whole process tree is killed so nothing is
/// left behind. This is deliberately synchronous — it is always invoked from a background
/// <c>Task.Run</c> in TweakEngine — so there is no sync-over-async and no deadlock risk.</para>
/// </summary>
internal static class ProcessRunner
{
    /// <summary>
    /// Ceiling for read-only probes (sc qc, powercfg /query, netsh show, fsutil query, bcdedit /enum).
    /// These run dozens of times per scan pass and must never stall the pipeline.
    /// </summary>
    public const int ProbeTimeoutMs = 2500;

    /// <summary>
    /// Ceiling for state-changing invocations (applying a tweak, restoring a backup).
    ///
    /// <para>Deliberately much larger than <see cref="ProbeTimeoutMs"/>. <c>bcdedit /set</c>,
    /// <c>powercfg /hibernate off</c> and <c>sc stop</c> on a busy service routinely exceed 2.5 s;
    /// killing them mid-flight would leave the system half-modified and the backup snapshot no
    /// longer matching reality. A 2.5 s cap belongs on probes, not on writes.</para>
    /// </summary>
    public const int ApplyTimeoutMs = 30_000;

    public static string Run(string file, params string[] args) => Run(file, ProbeTimeoutMs, args);

    public static string Run(string file, int timeoutMs, params string[] args)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = file,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8
            }
        };
        foreach (var arg in args) process.StartInfo.ArgumentList.Add(arg);

        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        // Signalled when each stream reaches EOF, so we know the buffers are complete
        // before inspecting them.
        using var stdoutDone = new ManualResetEventSlim(false);
        using var stderrDone = new ManualResetEventSlim(false);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is null) { stdoutDone.Set(); return; }
            lock (stdout) stdout.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) { stderrDone.Set(); return; }
            lock (stderr) stderr.AppendLine(e.Data);
        };

        if (!process.Start()) throw new InvalidOperationException($"Failed to start {file}.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        // Some console tools block waiting on stdin if it is redirected; close it immediately
        // so they see EOF and proceed.
        try { process.StandardInput.Close(); } catch { /* the child may have closed it already */ }

        var deadline = Environment.TickCount64 + timeoutMs;

        if (!process.WaitForExit(timeoutMs))
        {
            KillTree(process);
            throw new TimeoutException($"{file} did not exit within {timeoutMs} ms and was terminated.");
        }

        // WaitForExit(int) does not guarantee the async readers have flushed. Wait for both
        // EOF signals with whatever budget is left rather than the unbounded WaitForExit().
        stdoutDone.Wait(Math.Max(0, (int)(deadline - Environment.TickCount64)));
        stderrDone.Wait(Math.Max(0, (int)(deadline - Environment.TickCount64)));

        if (process.ExitCode != 0)
        {
            string error;
            lock (stderr) error = stderr.ToString().Trim();
            throw new InvalidOperationException($"{file} exited with code {process.ExitCode}: {error}");
        }

        lock (stdout) return stdout.ToString().Trim();
    }

    private static void KillTree(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch
        {
            // Already exited, or we lost the race with the OS. Nothing useful to do.
        }
    }
}

public static class TweakClassifier
{
    public static TweakVerifyKind Classify(string command)
    {
        var c = command.Trim();
        if (c.Length == 0) return TweakVerifyKind.Unsupported;
        if (c.StartsWith("reg add ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Registry;
        if (c.StartsWith("sc ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Service;
        if (c.StartsWith("bcdedit ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Bcd;
        if (c.StartsWith("powercfg ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Power;
        if (c.StartsWith("netsh ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Network;
        if (c.StartsWith("fsutil ", StringComparison.OrdinalIgnoreCase)) return TweakVerifyKind.Fsutil;
        return TweakVerifyKind.Unsupported;
    }
}

public static class RegistryProbe
{
    public static bool TryParseRegAdd(string command, out (string hive, string path, string name, string type, string expected) result)
    {
        result = default;
        var m = Regex.Match(command,
            "^reg\\s+add\\s+\"(?<key>HKLM|HKCU|HKCR|HKU)(?<path>[^\"]*)\"\\s+/v\\s+\"?(?<name>[^\"\\s]+)\"?\\s+/t\\s+(?<type>REG_DWORD|REG_SZ|REG_BINARY)\\s+/f\\s+/d\\s+\"?(?<data>[^\"]+)\"?$",
            RegexOptions.IgnoreCase);
        if (!m.Success) return false;
        result = (
            m.Groups["key"].Value,
            m.Groups["path"].Value.TrimStart('\\'),
            m.Groups["name"].Value,
            m.Groups["type"].Value.ToUpperInvariant(),
            m.Groups["data"].Value.Trim().Trim('"')
        );
        return true;
    }

    public static object? Read(string hive, string path, string name)
    {
        var root = hive.ToUpperInvariant() switch
        {
            "HKLM" => Registry.LocalMachine,
            "HKCU" => Registry.CurrentUser,
            "HKCR" => Registry.ClassesRoot,
            "HKU" => Registry.Users,
            _ => throw new ArgumentOutOfRangeException(nameof(hive))
        };
        using var key = root.OpenSubKey(path, false);
        return key?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    }

    public static RegistryValueKind KindOf(object? value, string declaredType)
        => value switch
        {
            int or uint or long or ulong => RegistryValueKind.DWord,
            byte[] => RegistryValueKind.Binary,
            _ => string.Equals(declaredType, "REG_SZ", StringComparison.OrdinalIgnoreCase) ? RegistryValueKind.String : RegistryValueKind.String
        };

    public static bool Equals(object? actual, string type, string expected)
    {
        if (string.Equals(type, "REG_DWORD", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryParseInteger(expected, out var exp)) return false;
            return actual switch
            {
                int i => i == exp,
                uint ui => ui == (uint)exp,
                long l => l == exp,
                ulong ul => ul == (ulong)Math.Max(exp, 0),
                _ => false
            };
        }
        if (string.Equals(type, "REG_BINARY", StringComparison.OrdinalIgnoreCase))
        {
            if (actual is not byte[] data) return false;
            try { return Convert.ToHexString(data).Equals(expected.Replace("0x", "", StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }
        return string.Equals(Convert.ToString(actual, CultureInfo.InvariantCulture), expected.Trim('"'), StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryParseInteger(string text, out long value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }
}

public static class ServiceVerifier
{
    public static (bool Exists, int StartTypeCode, bool Running) Capture(string name)
    {
        try
        {
            var qc = ProcessRunner.Run("sc.exe", "qc", name);
            var qm = Regex.Match(qc, @"START_TYPE\s*:\s*(?<n>\d+)", RegexOptions.IgnoreCase);
            if (!qm.Success) return (true, 3, false);
            var q = ProcessRunner.Run("sc.exe", "query", name);
            return (true, int.Parse(qm.Groups["n"].Value, CultureInfo.InvariantCulture), q.Contains("RUNNING", StringComparison.OrdinalIgnoreCase));
        }
        // InvalidOperationException = sc.exe reported a non-zero exit (service does not exist).
        // TimeoutException = the probe exceeded ProbeTimeoutMs and was killed. Both are treated as
        // "no usable information", which is what the callers already expect; letting a timeout
        // escape here would abort an entire scan pass over one slow service query.
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
        {
            return (false, 0, false);
        }
    }

    public static (bool Matched, string Message) Verify(string command)
    {
        var m = Regex.Match(command, "sc\\s+(?<op>config|stop|start)\\s+(?:\"(?<name>[^\"]+)\"|(?<name>\\S+))(?:\\s+start=\\s*(?<start>\\S+))?", RegexOptions.IgnoreCase);
        if (!m.Success) return (false, "Unsupported service command shape.");
        var name = m.Groups["name"].Value;
        var (_, startCode, running) = Capture(name);
        if (m.Groups["op"].Value.Equals("config", StringComparison.OrdinalIgnoreCase))
        {
            var requested = m.Groups["start"].Value.ToLowerInvariant();
            var expectedCode = requested switch { "boot" => 0, "system" => 1, "auto" => 2, "demand" => 3, "disabled" => 4, _ => -1 };
            if (expectedCode >= 0 && startCode != expectedCode) return (false, $"{name} start type is {startCode}, expected {expectedCode}.");
        }
        else if (m.Groups["op"].Value.Equals("stop", StringComparison.OrdinalIgnoreCase) && running)
            return (false, $"{name} is still running.");
        else if (m.Groups["op"].Value.Equals("start", StringComparison.OrdinalIgnoreCase) && !running)
            return (false, $"{name} is not running.");
        return (true, $"{name} matches requested state.");
    }

    public static string StartToken(int code) => code switch { 0 => "boot", 1 => "system", 2 => "auto", 3 => "demand", 4 => "disabled", _ => "demand" };
}

public static class BcdVerifier
{
    public static bool TryParseSet(string command, out string key, out string value)
    {
        var m = Regex.Match(command, @"bcdedit\s+/set\s+(?<key>useplatformtick|disabledynamictick|hypervisorlaunchtype)\s+(?<value>\S+)", RegexOptions.IgnoreCase);
        key = m.Groups["key"].Value.ToLowerInvariant(); value = m.Groups["value"].Value;
        return m.Success;
    }

    public static Dictionary<string, string> CaptureRelevant()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var output = ProcessRunner.Run("bcdedit.exe", "/enum", "{current}");
            foreach (var line in output.Split('\n'))
            {
                var m = Regex.Match(line.Trim(), @"^(useplatformtick|disabledynamictick|hypervisorlaunchtype)\s+(\S+)$", RegexOptions.IgnoreCase);
                if (m.Success) result[m.Groups[1].Value.ToLowerInvariant()] = m.Groups[2].Value;
            }
        }
        catch { }
        return result;
    }

    public static bool IsApplied(string command)
    {
        if (!TryParseSet(command, out var key, out var value)) return false;
        var current = CaptureRelevant();
        return current.TryGetValue(key, out var actual) && actual.Equals(value, StringComparison.OrdinalIgnoreCase);
    }
}

public static class PowerVerifier
{
    public static bool TryParseIndexCommand(string command, out bool ac, out string sub, out string setting, out int index)
    {
        ac = false;
        sub = string.Empty;
        setting = string.Empty;
        index = -1;
        var m = Regex.Match(command,
            @"powercfg\s+/(?<plane>setacvalueindex|setdcvalueindex)\s+SCHEME_CURRENT\s+(?<sub>\S+)\s+(?<setting>\S+)\s+(?<index>\d+)",
            RegexOptions.IgnoreCase);
        ac = m.Success && m.Groups["plane"].Value.Equals("setacvalueindex", StringComparison.OrdinalIgnoreCase);
        sub = m.Groups["sub"].Value; setting = m.Groups["setting"].Value;
        return m.Success && int.TryParse(m.Groups["index"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out index);
    }

    public static (int? Ac, int? Dc)? Capture(string sub, string setting)
    {
        try
        {
            var output = ProcessRunner.Run("powercfg.exe", "/query", "SCHEME_CURRENT", sub, setting);
            int? ac = null, dc = null;
            foreach (var line in output.Split('\n'))
            {
                var m = Regex.Match(line, @"Current\s+(AC|DC)\s+Power\s+Setting\s+Index:\s*0x(?<h>[0-9A-Fa-f]+)", RegexOptions.IgnoreCase);
                if (!m.Success) continue;
                var v = Convert.ToInt32(m.Groups["h"].Value, 16);
                if (m.Groups[1].Value.Equals("AC", StringComparison.OrdinalIgnoreCase)) ac = v; else dc = v;
            }
            return (ac, dc);
        }
        catch { return null; }
    }

    public static bool IsApplied(string command)
    {
        if (!TryParseIndexCommand(command, out var ac, out var sub, out var setting, out var idx)) return false;
        var current = Capture(sub, setting);
        return current is not null && (ac ? current.Value.Ac == idx : current.Value.Dc == idx);
    }

    public static bool IsHibernationOff()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Power", false);
            var value = key?.GetValue("HibernateEnabled", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is int i && i == 0;
        }
        catch { return false; }
    }
}

public static class NetworkVerifier
{
    public static bool TryParseSet(string command, out string key, out string value)
    {
        var m = Regex.Match(command, @"netsh\s+int\s+tcp\s+set\s+global\s+(?<key>\w+)=(?<value>\w+)", RegexOptions.IgnoreCase);
        key = m.Groups["key"].Value.ToLowerInvariant(); value = m.Groups["value"].Value.ToLowerInvariant();
        return m.Success;
    }

    private static string? LabelFor(string key) => key switch
    {
        "autotuninglevel" => "Receive Window Auto-Tuning Level",
        "rss" => "Receive-Side Scaling State",
        "blackhole" => "PMTU Black Hole Detection",
        _ => null
    };

    public static string? Capture(string key)
    {
        try
        {
            var label = LabelFor(key);
            if (label is null) return null;
            var output = ProcessRunner.Run("netsh.exe", "int", "tcp", "show", "global");
            foreach (var line in output.Split('\n'))
            {
                if (!line.Contains(label, StringComparison.OrdinalIgnoreCase)) continue;
                var idx = line.IndexOf(':');
                if (idx >= 0) return line[(idx + 1)..].Trim().ToLowerInvariant();
            }
        }
        catch { }
        return null;
    }

    public static bool IsApplied(string command)
    {
        if (!TryParseSet(command, out var key, out var expected)) return false;
        var actual = Capture(key);
        if (actual is null) return false;
        return key switch
        {
            "autotuninglevel" => actual.Equals(expected, StringComparison.OrdinalIgnoreCase),
            "rss" => actual.Equals(expected, StringComparison.OrdinalIgnoreCase),
            "blackhole" => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }
}

public static class FsutilVerifier
{
    public static bool TryParseSet(string command, out string key, out int value)
    {
        key = string.Empty;
        value = 0;
        var m = Regex.Match(command, @"fsutil\s+behavior\s+set\s+(?<key>disable8dot3|disablelastaccess|memoryusage)\s+(?<value>\d+)", RegexOptions.IgnoreCase);
        key = m.Groups["key"].Value.ToLowerInvariant();
        return m.Success && int.TryParse(m.Groups["value"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    public static int? Capture(string key)
    {
        try
        {
            var output = ProcessRunner.Run("fsutil.exe", "behavior", "query", key);
            var m = Regex.Match(output, $@"{Regex.Escape(key)}\s*=\s*(?<v>\d+)", RegexOptions.IgnoreCase);
            if (!m.Success) return null;
            return int.Parse(m.Groups["v"].Value, CultureInfo.InvariantCulture);
        }
        catch { return null; }
    }

    public static bool IsApplied(string command)
    {
        if (!TryParseSet(command, out var key, out var expected)) return false;
        var actual = Capture(key);
        return actual == expected;
    }
}
