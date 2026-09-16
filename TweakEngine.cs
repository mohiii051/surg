using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SurgeApp.Models;
using SurgeApp.Services;

namespace SurgeApp;

public enum TweakStepKind { Backup, Apply, Verify, Rollback, RestoreVerify }

public sealed record TweakStepReport(TweakStepKind Step, bool Success, string Message);

public sealed record TweakScanResult(
    TweakEngineState State,
    string Message,
    bool Verified = false,
    bool RollbackPerformed = false,
    string? OldValue = null,
    string? NewValue = null);

public sealed class TweakEngine
{
    public Func<CancellationToken, Task<bool>>? OnlineGate { get; set; }
    public BackupEngine Backups { get; } = new();

    public bool HasImplementation(TweakItem tweak) => tweak.SourceCommands.Any(c => !string.IsNullOrWhiteSpace(c));

    public void EnrichMetadata(TweakItem tweak)
    {
        var kinds = tweak.SourceCommands
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(TweakClassifier.Classify)
            .Distinct()
            .ToList();

        tweak.VerifyMethod = kinds.Count == 0 ? "Unsupported" : string.Join("+", kinds);
        tweak.BackupType = kinds.Count == 0 ? "None" : string.Join("+", kinds);
        tweak.RollbackMethod = kinds.Count == 0 ? "Unsupported" : "BackupRestore";
        tweak.IsImplemented = kinds.Count > 0;
    }

    public async Task<TweakScanResult> ScanAsync(TweakItem tweak, CancellationToken ct = default)
        => await Task.Run(() => Scan(tweak), ct).ConfigureAwait(true);

    public async Task<TweakScanResult> ApplyAsync(TweakItem tweak, CancellationToken ct = default, IProgress<TweakStepReport>? progress = null)
    {
        if (OnlineGate is not null && !await OnlineGate(ct).ConfigureAwait(true))
            return new(TweakEngineState.Failed, "Online license validation failed · tuning action locked.");

        return await Task.Run(() => Apply(tweak, ct, progress), ct).ConfigureAwait(true);
    }

    public async Task<TweakScanResult> RevertAsync(TweakItem tweak, CancellationToken ct = default, IProgress<TweakStepReport>? progress = null)
    {
        if (OnlineGate is not null && !await OnlineGate(ct).ConfigureAwait(true))
            return new(TweakEngineState.Failed, "Online license validation failed · tuning action locked.");

        return await Task.Run(() => Revert(tweak, ct, progress), ct).ConfigureAwait(true);
    }

    private TweakScanResult Scan(TweakItem tweak)
    {
        var commands = tweak.SourceCommands.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
        if (commands.Count == 0)
            return new(TweakEngineState.Unsupported, "No executable action is defined for this tweak.");

        bool anyUnsupported = false;
        bool anyNeedsRestart = false;
        bool anyAppliedMismatch = false;
        var problems = new List<string>();

        try
        {
            foreach (var command in commands)
            {
                var kind = TweakClassifier.Classify(command);
                switch (kind)
                {
                    case TweakVerifyKind.Registry:
                        if (!RegistryProbe.TryParseRegAdd(command, out var reg)) { anyUnsupported = true; break; }
                        var actual = RegistryProbe.Read(reg.hive, reg.path, reg.name);
                        if (!RegistryProbe.Equals(actual, reg.type, reg.expected)) anyAppliedMismatch = true;
                        break;

                    case TweakVerifyKind.Service:
                        var sv = ServiceVerifier.Verify(command);
                        if (!sv.Matched) anyAppliedMismatch = true;
                        break;

                    case TweakVerifyKind.Bcd:
                        if (!BcdVerifier.IsApplied(command)) anyAppliedMismatch = true;
                        else anyNeedsRestart = true;
                        break;

                    case TweakVerifyKind.Power:
                        if (command.StartsWith("powercfg /setactive", StringComparison.OrdinalIgnoreCase))
                            break;
                        if (command.Equals("powercfg /hibernate off", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!PowerVerifier.IsHibernationOff()) anyAppliedMismatch = true;
                        }
                        else if (!PowerVerifier.IsApplied(command)) anyAppliedMismatch = true;
                        break;

                    case TweakVerifyKind.Network:
                        if (!NetworkVerifier.IsApplied(command)) anyAppliedMismatch = true;
                        break;

                    case TweakVerifyKind.Fsutil:
                        if (!FsutilVerifier.IsApplied(command)) anyAppliedMismatch = true;
                        break;

                    default:
                        anyUnsupported = true;
                        break;
                }
            }

            if (anyAppliedMismatch)
                return new(TweakEngineState.Default, string.Join(" ", problems.Count == 0 ? new[] { "Live state does not match the applied values." } : problems));
            if (anyNeedsRestart && !anyUnsupported)
                return new(TweakEngineState.NeedsRestart, "Applied and verified · restart required.", true);
            if (anyUnsupported && !anyAppliedMismatch)
                return new(TweakEngineState.Unsupported, "This tweak contains operations without a reliable live verifier.");
            if (!anyUnsupported)
                return new(TweakEngineState.Applied, "Live state matches the configured tweak values.", true);
            return new(TweakEngineState.Unknown, "Live state could not be determined for every operation.");
        }
        catch (Exception ex)
        {
            return new(TweakEngineState.Unknown, ex.Message);
        }
    }

    private TweakScanResult Apply(TweakItem tweak, CancellationToken ct, IProgress<TweakStepReport>? progress)
    {
        var commands = tweak.SourceCommands.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
        if (commands.Count == 0)
            return new(TweakEngineState.Unsupported, "No executable action is defined for this tweak.");

        SurgeBackup? snapshot = null;
        string? oldSummary = null;
        progress?.Report(new(TweakStepKind.Backup, true, "Creating protected pre-change snapshot…"));

        try
        {
            snapshot = Backups.CaptureTweakSnapshot(tweak, out oldSummary);
            TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "APPLY", "BACKUP", TweakEngineState.BackingUp.ToString(), "Protected pre-change snapshot created: " + oldSummary, commands));
            if (!CanReliablyRestore(snapshot, commands, out var backupMessage))
                return new(TweakEngineState.Unsupported, backupMessage ?? "No complete rollback path is available for this tweak.");

            progress?.Report(new(TweakStepKind.Apply, true, "Executing tweak commands…"));
            foreach (var command in commands)
            {
                ct.ThrowIfCancellationRequested();
                Execute(command);
            }
            TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "APPLY", "EXECUTED", TweakEngineState.Applying.ToString(), "All commands completed without process errors.", commands));

            progress?.Report(new(TweakStepKind.Verify, true, "Verifying live system state…"));
            var verify = VerifyApplied(tweak, oldSummary);
            TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "APPLY", verify.State is TweakEngineState.Applied or TweakEngineState.NeedsRestart ? "VERIFIED" : "VERIFY_FAILED", verify.State.ToString(), verify.Message, commands));

            if (verify.State is TweakEngineState.Applied or TweakEngineState.NeedsRestart)
                return verify;

            progress?.Report(new(TweakStepKind.Rollback, false, "Verification failed · restoring exact pre-change snapshot…"));
            var restored = RestoreSnapshot(tweak, snapshot, ct, progress);
            TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "ROLLBACK", restored.State == TweakEngineState.Default ? "SUCCESS" : "FAILED", restored.State.ToString(), restored.Message, commands));
            return restored with { RollbackPerformed = true };
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            if (snapshot is not null)
            {
                try
                {
                            progress?.Report(new(TweakStepKind.Rollback, false, "Apply failed · restoring exact pre-change snapshot…"));
                    var restored = RestoreSnapshot(tweak, snapshot, ct, progress);
                    return restored with { State = restored.State == TweakEngineState.Default ? TweakEngineState.Failed : restored.State,
                                           Message = restored.State == TweakEngineState.Default
                                               ? ex.Message + " · rollback verified"
                                               : ex.Message + " · rollback could not be fully verified",
                                           RollbackPerformed = true };
                }
                catch (Exception restoreEx)
                {
                    return new(TweakEngineState.Failed, ex.Message + " · rollback failed: " + restoreEx.Message, false, true);
                }
            }
            return new(TweakEngineState.Failed, ex.Message);
        }
    }

    private TweakScanResult Revert(TweakItem tweak, CancellationToken ct, IProgress<TweakStepReport>? progress)
    {
        try
        {
            var snapshot = Backups.FindTweakBackup(tweak);
            if (snapshot is null)
                return new(TweakEngineState.Failed, "No protected pre-change snapshot exists for this tweak.");

            ct.ThrowIfCancellationRequested();
            progress?.Report(new(TweakStepKind.Rollback, true, "Restoring protected pre-change snapshot…"));
            Backups.Restore(snapshot);

            progress?.Report(new(TweakStepKind.RestoreVerify, true, "Verifying restored state…"));
            if (!Backups.VerifyRestore(snapshot))
            {
                TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "REVERT", "VERIFY_FAILED", TweakEngineState.Failed.ToString(), "Exact restore verification failed.", tweak.SourceCommands));
                return new(TweakEngineState.Failed, "Restore executed, but the exact pre-change state could not be verified.", false, true);
            }

            Backups.DeleteTweakBackup(tweak);
            var ok = new TweakScanResult(TweakEngineState.Default, "Reverted and verified against the exact pre-change snapshot.", true, false, null, null);
            TweakOperationLog.Write(new(DateTime.UtcNow, tweak.Number, tweak.Title, "REVERT", "SUCCESS", ok.State.ToString(), ok.Message, tweak.SourceCommands));
            return ok;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new(TweakEngineState.Failed, ex.Message, false, true);
        }
    }

    private TweakScanResult VerifyApplied(TweakItem tweak, string? oldSummary)
    {
        bool anyNeedsRestart = false;
        bool anyUnsupported = false;
        var problems = new List<string>();
        var commands = tweak.SourceCommands.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();

        foreach (var command in commands)
        {
            switch (TweakClassifier.Classify(command))
            {
                case TweakVerifyKind.Registry:
                    if (!RegistryProbe.TryParseRegAdd(command, out var reg)) { anyUnsupported = true; break; }
                    if (!RegistryProbe.Equals(RegistryProbe.Read(reg.hive, reg.path, reg.name), reg.type, reg.expected))
                        problems.Add($"{reg.name}: expected {reg.expected}.");
                    break;
                case TweakVerifyKind.Service:
                    var sv = ServiceVerifier.Verify(command);
                    if (!sv.Matched) problems.Add(sv.Message);
                    break;
                case TweakVerifyKind.Bcd:
                    if (!BcdVerifier.IsApplied(command)) problems.Add("BCD setting does not match the requested value.");
                    else anyNeedsRestart = true;
                    break;
                case TweakVerifyKind.Power:
                    if (command.StartsWith("powercfg /setactive", StringComparison.OrdinalIgnoreCase)) break;
                    var powerOk = command.Equals("powercfg /hibernate off", StringComparison.OrdinalIgnoreCase)
                        ? PowerVerifier.IsHibernationOff()
                        : PowerVerifier.IsApplied(command);
                    if (!powerOk) problems.Add("Power setting does not match the requested value.");
                    break;
                case TweakVerifyKind.Network:
                    if (!NetworkVerifier.IsApplied(command)) problems.Add("Network setting does not match the requested value.");
                    break;
                case TweakVerifyKind.Fsutil:
                    if (!FsutilVerifier.IsApplied(command)) problems.Add("FSUTIL setting does not match the requested value.");
                    break;
                default:
                    anyUnsupported = true;
                    break;
            }
        }

        if (problems.Count > 0)
            return new(TweakEngineState.Failed, string.Join(" ", problems), false, false, oldSummary, null);
        if (anyUnsupported)
            return new(TweakEngineState.Unsupported, "Applied, but one or more operations do not have a reliable live verifier.", false, false, oldSummary, null);
        if (anyNeedsRestart)
            return new(TweakEngineState.NeedsRestart, "Applied and verified · restart required.", true, false, oldSummary, "applied");
        return new(TweakEngineState.Applied, "Applied and verified against the live system state.", true, false, oldSummary, "applied");
    }

    private static bool CanReliablyRestore(SurgeBackup snapshot, IReadOnlyList<string> commands, out string? message)
    {
        message = null;
        var supported = commands.Select(TweakClassifier.Classify).ToHashSet();
        if (supported.Contains(TweakVerifyKind.Unsupported)) { message = "One or more source operations are unsupported by the transactional engine."; return false; }
        if (supported.Contains(TweakVerifyKind.Registry) && snapshot.Registry.Count == 0) { message = "Registry backup could not be captured."; return false; }
        if (supported.Contains(TweakVerifyKind.Service) && snapshot.Services.Count == 0) { message = "Service backup could not be captured."; return false; }
        if (supported.Contains(TweakVerifyKind.Power) && commands.Any(c => c.Contains("setacvalueindex", StringComparison.OrdinalIgnoreCase) || c.Contains("setdcvalueindex", StringComparison.OrdinalIgnoreCase)) && snapshot.Power.Count == 0) { message = "Power setting backup could not be captured."; return false; }
        if (commands.Any(c => c.Equals("powercfg /hibernate off", StringComparison.OrdinalIgnoreCase)) && snapshot.HibernationEnabled is null) { message = "Hibernation state could not be captured."; return false; }
        if (supported.Contains(TweakVerifyKind.Network) && snapshot.Network.Count == 0) { message = "Network state backup could not be captured."; return false; }
        if (supported.Contains(TweakVerifyKind.Fsutil) && snapshot.Fsutil.Count == 0) { message = "FSUTIL state backup could not be captured."; return false; }
        return true;
    }

    private TweakScanResult RestoreSnapshot(TweakItem tweak, SurgeBackup snapshot, CancellationToken ct, IProgress<TweakStepReport>? progress)
    {
        ct.ThrowIfCancellationRequested();
        Backups.Restore(snapshot);
        progress?.Report(new(TweakStepKind.RestoreVerify, true, "Verifying exact restore…"));
        if (!Backups.VerifyRestore(snapshot))
            return new(TweakEngineState.Failed, "Rollback executed, but exact restore verification failed.", false, true);
        Backups.DeleteTweakBackup(tweak);
        return new(TweakEngineState.Default, "Operation failed · exact pre-change state restored and verified.", true, true);
    }

    public async Task<(bool Success, string Message)> RestoreSnapshotAsync(string snapshotId, CancellationToken ct = default, IProgress<TweakStepReport>? progress = null)
    {
        return await Task.Run(() =>
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var snapshot = Backups.Load(snapshotId);
                progress?.Report(new(TweakStepKind.Rollback, true, "Restoring full snapshot…"));
                Backups.Restore(snapshot);
                progress?.Report(new(TweakStepKind.RestoreVerify, true, "Verifying full restore…"));
                var ok = Backups.VerifyRestore(snapshot);
                return (ok, ok ? "Global rollback complete · restore verified." : "Global rollback verification failed.");
            }
            catch (Exception ex) { return (false, ex.Message); }
        }, ct).ConfigureAwait(true);
    }

    private static void Execute(string command)
    {
        // Applying a tweak is a write path, so it gets ProcessRunner.ApplyTimeoutMs (30 s) rather
        // than the 2.5 s probe timeout. The probe timeout exists to stop verification passes from
        // freezing the UI; capping an in-flight bcdedit or powercfg at 2.5 s would instead leave
        // the machine partially modified with a backup snapshot that no longer matches reality.
        if (RegistryProbe.TryParseRegAdd(command, out var reg))
        {
            ProcessRunner.Run("reg.exe", ProcessRunner.ApplyTimeoutMs,
                "add", reg.hive + "\\" + reg.path, "/v", reg.name, "/t", reg.type, "/f", "/d", reg.expected);
            return;
        }
        ProcessRunner.Run(Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe", ProcessRunner.ApplyTimeoutMs,
            "/d", "/c", command);
    }
}
