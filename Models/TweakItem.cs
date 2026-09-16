using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SurgeApp.Models;

public enum TweakEngineState
{
    Default,
    Pending,
    BackingUp,
    Applying,
    Verifying,
    Applied,
    Failed,
    Rollback,
    Restored,
    Unknown,
    Unsupported,
    NeedsRestart
}

public enum TweakScanDisplayState { Default, AppliedUnverified, Unknown }
public enum TweakStatus { Applied, Default, Auto }

public sealed class TweakItem : INotifyPropertyChanged
{
    public int Number { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string TechnicalNotes { get; init; } = "";
    public ObservableCollection<string> Tags { get; init; } = new();
    public ObservableCollection<string> SourceCommands { get; init; } = new();
    public string Category { get; init; } = "";
    public string Risk { get; init; } = "Safe";
    public string Mode { get; init; } = "Standard";
    public bool RequiresReboot { get; init; }
    public bool IsImplemented { get; set; }
    public bool IsAuto { get; init; }

    public string VerifyMethod { get; set; } = "";
    public string RollbackMethod { get; set; } = "";
    public string BackupType { get; set; } = "";

    private TweakEngineState _engineState = TweakEngineState.Unknown;
    public TweakEngineState EngineState
    {
        get => _engineState;
        set
        {
            if (_engineState == value) return;
            _engineState = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(ActionText));
            OnPropertyChanged(nameof(IsApplied));
            OnPropertyChanged(nameof(ToggleEnabled));
            OnPropertyChanged(nameof(CanApplyFromUi));
            OnPropertyChanged(nameof(RestartText));
        }
    }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (_isBusy == value) return;
            _isBusy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanApplyFromUi));
            OnPropertyChanged(nameof(ToggleEnabled));
            OnPropertyChanged(nameof(StatusText));
        }
    }

    private bool _verificationFailed;
    public bool VerificationFailed
    {
        get => _verificationFailed;
        set
        {
            if (_verificationFailed == value) return;
            _verificationFailed = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(CanApplyFromUi));
        }
    }

    private string _verificationText = "Not scanned";
    public string VerificationText
    {
        get => _verificationText;
        set
        {
            if (_verificationText == value) return;
            _verificationText = value;
            OnPropertyChanged();
        }
    }

    private DateTime? _lastVerificationUtc;
    public DateTime? LastVerificationUtc
    {
        get => _lastVerificationUtc;
        set { if (_lastVerificationUtc != value) { _lastVerificationUtc = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastVerificationText)); } }
    }

    public string LastVerificationText => LastVerificationUtc is null
        ? "Never"
        : LastVerificationUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public bool IsApplied => EngineState is TweakEngineState.Applied or TweakEngineState.NeedsRestart;

    // Failed/Unknown/Unsupported are intentionally locked until a fresh scan clears the state.
    public bool ToggleEnabled => !IsBusy && !IsAuto && (EngineState is TweakEngineState.Applied or TweakEngineState.Default or TweakEngineState.NeedsRestart);
    public bool CanApplyFromUi => ToggleEnabled && !VerificationFailed;

    public TweakScanDisplayState DisplayState { get; set; } = TweakScanDisplayState.Unknown;

    public string StatusText => IsBusy ? EngineState switch
        {
            TweakEngineState.BackingUp => "BACKUP",
            TweakEngineState.Applying => "APPLYING",
            TweakEngineState.Verifying => "VERIFYING",
            TweakEngineState.Rollback => "ROLLBACK",
            _ => "WORKING"
        }
        : IsAuto ? "AUTO"
        : EngineState switch
        {
            TweakEngineState.Applied => "APPLIED",
            TweakEngineState.NeedsRestart => "APPLIED · RESTART",
            TweakEngineState.Default => "DEFAULT",
            TweakEngineState.Failed => "FAILED",
            TweakEngineState.Unknown => "UNKNOWN",
            TweakEngineState.Unsupported => "UNSUPPORTED",
            TweakEngineState.Restored => "DEFAULT",
            TweakEngineState.Pending => "PENDING",
            _ => "UNKNOWN"
        };

    public string ActionText => IsAuto ? "AUTO" : IsApplied ? "REVERT" : "APPLY";
    public string RestartText => EngineState == TweakEngineState.NeedsRestart
        ? "Restart required"
        : RequiresReboot ? "Restart recommended" : "";

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
