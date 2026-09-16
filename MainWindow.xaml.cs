using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using SurgeApp.Models;
using System.Windows.Media;
using System.Security.Principal;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System.Windows.Threading;
using System.Windows.Media.Animation;
using SurgeApp.Services;

namespace SurgeApp
{
    public partial class MainWindow : Window
    {
        public static readonly DependencyProperty IsTuningAllowedProperty =
            DependencyProperty.Register(nameof(IsTuningAllowed), typeof(bool), typeof(MainWindow),
                new PropertyMetadata(false));

        public bool IsTuningAllowed
        {
            get => (bool)GetValue(IsTuningAllowedProperty);
            private set => SetValue(IsTuningAllowedProperty, value);
        }
        /// <summary>
        /// Offline grace period before Surge closes itself.
        ///
        /// DO NOT CHANGE. This value is the anti-crack strictness budget: it is the entire window
        /// in which a user can hold the application open without the license server confirming the
        /// license. Raising it proportionally widens the window for an offline bypass.
        /// </summary>
        private static readonly TimeSpan OfflineGracePeriod = TimeSpan.FromSeconds(30);

        private readonly ObservableCollection<TweakItem> _allTweaks = new();
        private ICollectionView _view = null!;
        private string _selectedCategory = "ALL";
        private readonly TweakEngine _tweakEngine = new();
        private bool _isScanRunning;
        private readonly AuthSession _authSession;
        private readonly AuthService _authService;
        private readonly DispatcherTimer _licenseTimer;
        private readonly DispatcherTimer _offlineTimer;
        private DateTime _offlineDeadlineUtc;
        private DateTime _nextReconnectAttemptUtc;
        private bool _validationInProgress;
        private bool _licenseValid;

        // Apply All engine
        private CancellationTokenSource? _applyAllCts;
        private bool _applyAllPaused;
        private bool _isApplyAllRunning;

        public MainWindow(AuthSession authSession, AuthService authService)
        {
            _authSession = authSession;
            _authService = authService;
            _tweakEngine.OnlineGate = _ => EnsureOnlineLicenseAsync();
            _licenseValid = false;
            IsTuningAllowed = false;
            _licenseValid = authSession.ActiveLicense is not null && (authSession.ActiveLicense.ExpiresUtc is null || authSession.ActiveLicense.ExpiresUtc > DateTime.UtcNow);
            _licenseTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(1) };
            _licenseTimer.Tick += LicenseTimer_Tick;
            _offlineTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _offlineTimer.Tick += OfflineTimer_Tick;
            try
            {
                // The application manifest requests elevation before startup, so the
                // process never needs to restart itself after authentication.
                WindowState = WindowState.Normal;
                InitializeComponent();
                LoadTweaks();
                foreach (var tweak in _allTweaks)
                    _tweakEngine.EnrichMetadata(tweak);

                _view = CollectionViewSource.GetDefaultView(_allTweaks);
                _view.Filter = FilterTweak;
                TweaksItemsControl.ItemsSource = _view;

                foreach (var t in _allTweaks)
                    t.PropertyChanged += Tweak_PropertyChanged;

                BuildCategories();
                UpdateCounts();
                UpdateAccountUi();
            }
            catch (Exception ex)
            {
                // Release builds must not print a stack trace into a MessageBox: it hands an
                // attacker a map of the licensing and anti-tamper internals. Full detail goes to
                // the protected local log instead.
                ErrorReporter.Show("Surge — Startup Error", "Startup error:", ex);
                Application.Current.Shutdown();
            }
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Normal;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            var work = SystemParameters.WorkArea;
            Width = Math.Min(Width, work.Width - 48);
            Height = Math.Min(Height, work.Height - 48);
            Left = work.Left + Math.Max(0, (work.Width - Width) / 2);
            Top = work.Top + Math.Max(0, (work.Height - Height) / 2);
            await Dispatcher.BeginInvoke(new Action(() => LibraryScroll?.ScrollToTop()),
                System.Windows.Threading.DispatcherPriority.Loaded);
            ApplyWindowCornerState();
            RootChrome.Opacity = 0;
            RootChrome.RenderTransform = new TranslateTransform(0, 8);
            await Dispatcher.BeginInvoke(new Action(() => AnimateWindowIn()), DispatcherPriority.Render);
            UpdateRestorePointStatus();

            if (await EnsureOnlineLicenseAsync())
            {
                await ScanAllTweaksAsync();
                _licenseTimer.Start();
            }
            else
            {
                ScanStatusText.Text = "Online license validation required · tuning actions locked";
            }
        }

        private async Task ScanAllTweaksAsync()
        {
            if (_isScanRunning) return;
            _isScanRunning = true;
            try
            {
                ScanStatusText.Text = "Scanning system state…";
                foreach (var tweak in _allTweaks)
                {
                    tweak.IsBusy = true;
                    tweak.VerificationFailed = false;
                    tweak.VerificationText = "Checking…";
                }

                foreach (var tweak in _allTweaks)
                {
                    var result = await _tweakEngine.ScanAsync(tweak);
                    ApplyScanResult(tweak, result);
                }

                UpdateCounts();
                ScanStatusText.Text = "System scan complete · live states checked";
            }
            finally
            {
                foreach (var tweak in _allTweaks) tweak.IsBusy = false;
                _isScanRunning = false;
            }
        }

        private void ApplyScanResult(TweakItem tweak, TweakScanResult result)
        {
            tweak.EngineState = result.State;
            tweak.VerificationFailed = result.State == TweakEngineState.Failed;
            tweak.LastVerificationUtc = DateTime.UtcNow;
            tweak.VerificationText = result.Message;
            tweak.DisplayState = result.State switch
            {
                TweakEngineState.Applied => TweakScanDisplayState.AppliedUnverified,
                TweakEngineState.NeedsRestart => TweakScanDisplayState.AppliedUnverified,
                TweakEngineState.Default or TweakEngineState.Restored => TweakScanDisplayState.Default,
                _ => TweakScanDisplayState.Unknown
            };
        }

        private async void LicenseTimer_Tick(object? sender, EventArgs e)
        {
            if (!await EnsureOnlineLicenseAsync())
                EnterOnlineFailure("License server unavailable · tuning actions locked");
        }

        private async void OfflineTimer_Tick(object? sender, EventArgs e)
        {
            if (_licenseValid)
            {
                _offlineTimer.Stop();
                return;
            }

            var remaining = _offlineDeadlineUtc - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                _offlineTimer.Stop();
                _licenseTimer.Stop();
                IsTuningAllowed = false;
                ScanStatusText.Text = "Online license validation timed out · Surge is closing";
                await Task.Delay(700);
                Close();
                return;
            }

            if (DateTime.UtcNow >= _nextReconnectAttemptUtc && !_validationInProgress)
            {
                _nextReconnectAttemptUtc = DateTime.UtcNow.AddSeconds(5);
                if (await EnsureOnlineLicenseAsync())
                {
                    _offlineTimer.Stop();
                    ScanStatusText.Text = "Online license restored · rechecking system state…";
                    await ScanAllTweaksAsync();
                    _licenseTimer.Start();
                    return;
                }
            }

            var seconds = Math.Max(0, (int)Math.Ceiling(remaining.TotalSeconds));
            ScanStatusText.Text = $"SERVER OFFLINE · tuning locked · closing in {seconds}s";
        }

        private void EnterOnlineFailure(string message)
        {
            _licenseValid = false;
            IsTuningAllowed = false;
            UpdateAccountUi();
            ScanStatusText.Text = message;
            if (!_offlineTimer.IsEnabled)
            {
                _offlineDeadlineUtc = DateTime.UtcNow.Add(OfflineGracePeriod);
                _nextReconnectAttemptUtc = DateTime.UtcNow;
                _offlineTimer.Start();
            }
        }

        private void UpdateAccountUi()
        {
            if (AccountEmailText != null) AccountEmailText.Text = _authSession.User.Email;
            if (LicenseStatusText != null) LicenseStatusText.Text = _licenseValid ? "LICENSE ACTIVE" : "LICENSE INACTIVE";
            if (LicenseDetailText != null && _authSession.ActiveLicense is { } l)
                LicenseDetailText.Text = $"ID {l.Id[..Math.Min(10, l.Id.Length)]}… · {l.LicenseKeyMasked} · {l.ActiveDevices}/{l.MaxDevices} devices";
            if (LicenseDetailText != null && _authSession.ActiveLicense is null)
                LicenseDetailText.Text = "No active license on this device.";
            if (LicenseDot != null) LicenseDot.Fill = new SolidColorBrush(_licenseValid ? Color.FromRgb(48,211,160) : Color.FromRgb(255,135,149));
        }

        private void Window_StateChanged(object? sender, EventArgs e) => ApplyWindowCornerState();

        private void ApplyWindowCornerState()
        {
            if (RootChrome == null) return;
            var max = WindowState == WindowState.Maximized;
            RootChrome.CornerRadius = new CornerRadius(max ? 0 : 16);
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            AcrylicHelper.EnableAcrylic(this);
        }

        private void RootChrome_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            double radius = RootChrome.CornerRadius.TopLeft;
            RootChrome.Clip = new RectangleGeometry(new Rect(0, 0, e.NewSize.Width, e.NewSize.Height), radius, radius);
        }

        private void Tweak_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(TweakItem.IsApplied))
                UpdateCounts();
        }

        private void LoadTweaks()
        {
            _allTweaks.Clear();
            _allTweaks.Add(new TweakItem
            {
                Number = 1,
                Title = "Optimize DPC Latency",
                Description = "Adjusts the DPC watchdog profile offset to reduce deferred procedure call latency, improving real-time responsiveness.",
                TechnicalNotes = "Tweak #1 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v DpcWatchdogProfileOffset /t REG_DWORD /f /d 0x2710" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 2,
                Title = "Extend DPC Watchdog Period",
                Description = "Extends the DPC watchdog timeout period, preventing false watchdog triggers under sustained high-interrupt workloads.",
                TechnicalNotes = "Tweak #2 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v DpcWatchdogPeriod /t REG_DWORD /f /d 0xF0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 3,
                Title = "Disable Threaded DPCs",
                Description = "Disables threaded DPC dispatching, forcing DPCs to execute on the originating CPU and reducing cross-core dispatch overhead.",
                TechnicalNotes = "Tweak #3 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v ThreadDpcEnable /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 4,
                Title = "Increase Delayed Worker Threads",
                Description = "Increases the pool of delayed worker threads, reducing queueing delays for background kernel work items.",
                TechnicalNotes = "Tweak #4 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Executive\" /v AdditionalDelayedWorkerThreads /t REG_DWORD /f /d 0x20" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 5,
                Title = "Increase Max Kernel Worker Threads (Increase Critical Worker Threads)",
                Description = "Raises the number of critical kernel worker threads, improving throughput for high-priority asynchronous I/O and system calls.",
                TechnicalNotes = "Tweak #5 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Executive\" /v AdditionalCriticalWorkerThreads /t REG_DWORD /f /d 0x20" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 6,
                Title = "Enable Mutant Autoboost",
                Description = "Enables mutant (mutex) autoboost so that threads waiting on a mutex automatically inherit the holding thread's priority.",
                TechnicalNotes = "Tweak #6 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\" /v MutantAutoboost /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 7,
                Title = "Disable Passive-Level Watchdog",
                Description = "Disables the passive-level DPC watchdog, eliminating watchdog interrupts that can stall time-sensitive kernel threads.",
                TechnicalNotes = "Tweak #7 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\" /v DisablePassiveLevelWatchdog /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 8,
                Title = "Disable Worker Thread Timeout",
                Description = "Sets the worker thread timeout to zero, removing idle thread expiration and preventing thread recreation overhead.",
                TechnicalNotes = "Tweak #8 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Executive\" /v WorkerThreadTimeout /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 9,
                Title = "Enable Scheduler Assist",
                Description = "Enables Windows Scheduler Assist, a hint to the kernel scheduler that assists in reducing scheduling jitter.",
                TechnicalNotes = "Tweak #9 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v SchedulerAssist /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 10,
                Title = "Disable Intel TSX",
                Description = "Disables Intel TSX (Transactional Synchronization Extensions) to avoid known errata and potential IPC stalls on affected CPUs.",
                TechnicalNotes = "Tweak #10 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\" /v DisableTsx /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 11,
                Title = "Enable AFD Fast Socket Route",
                Description = "Enables the AFD fast socket route, allowing the Ancillary Function Driver to bypass slower kernel paths for socket I/O.",
                TechnicalNotes = "Tweak #11 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters\" /v FastSocketRoute /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 12,
                Title = "Increase IRP Stack Depth",
                Description = "Increases the IRP (I/O Request Packet) stack depth, reducing IRP stack overflow conditions in deep driver chains.",
                TechnicalNotes = "Tweak #12 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\I/O System\" /v StackSize /t REG_DWORD /f /d 20" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 13,
                Title = "Disable Foreground Boost Decay",
                Description = "Disables foreground boost decay so that UI threads retain elevated priority for longer after receiving input focus.",
                TechnicalNotes = "Tweak #13 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl\" /v ForegroundBoostDecay /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 14,
                Title = "Optimize System Responsiveness",
                Description = "Sets SystemResponsiveness to 10, reserving less CPU time for MMCSS background tasks and giving more headroom to games.",
                TechnicalNotes = "Tweak #14 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /f /d 10" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 15,
                Title = "Optimize Thread Scheduling",
                Description = "Sets Win32PrioritySeparation to 0x26 (short, variable, foreground boost active) for tighter foreground scheduling.",
                TechnicalNotes = "Tweak #15 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl\" /v Win32PrioritySeparation /t REG_DWORD /f /d 0x26" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 16,
                Title = "Disable Serialize Timer Expiration",
                Description = "Sets the Explorer shell timer delay to zero, eliminating the artificial startup serialization pause.",
                TechnicalNotes = "Tweak #16 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Serialize\" /v StartDelayInSeconds /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 17,
                Title = "Per-CPU Timer Interrupt Distribution & Limit Dynamic Tick",
                Description = "Configures the BCD bootloader to use a per-CPU hardware timer and disables the dynamic tick to prevent timer coalescing.",
                TechnicalNotes = "Tweak #17 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = true,
                SourceCommands = new ObservableCollection<string> { "bcdedit /set useplatformtick yes", "bcdedit /set disabledynamictick yes" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel", "reboot" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 18,
                Title = "Disable Low-QoS Timer Resolution Throttling",
                Description = "Enables global timer resolution requests so that high-resolution timer requests from any process take system-wide effect.",
                TechnicalNotes = "Tweak #18 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v GlobalTimerResolutionRequests /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 19,
                Title = "Passive Interrupt Worker Priority",
                Description = "Disables interrupt steering, keeping hardware interrupts pinned to their originating logical processor.",
                TechnicalNotes = "Tweak #19 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v InterruptSteeringEnabled /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 20,
                Title = "MMCSS Games Priority & Scheduler Idle",
                Description = "Elevates the MMCSS Games task to Priority 6 with High scheduling category and High SFIO priority for game thread scheduling.",
                TechnicalNotes = "Tweak #20 · TIMER / DPC / KERNEL",
                Category = "TIMER / DPC / KERNEL",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v Priority /t REG_DWORD /f /d 6", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Scheduling Category\" /t REG_SZ /f /d \"High\"", "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"SFIO Priority\" /t REG_SZ /f /d \"High\"" },
                Tags = new ObservableCollection<string> { "timer / dpc / kernel" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 21,
                Title = "Disable Paging Executive",
                Description = "Locks core kernel code and data structures in physical RAM, preventing them from being paged out to the swap file.",
                TechnicalNotes = "Tweak #21 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v DisablePagingExecutive /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 22,
                Title = "Disable Memory Page Combining",
                Description = "Disables memory page combining, reducing the overhead of the periodic background scan that merges identical pages.",
                TechnicalNotes = "Tweak #22 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v DisablePageCombining /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 23,
                Title = "Disable Superfetch (SysMain)",
                Description = "Stops and disables the SysMain (Superfetch) service to eliminate its background I/O prefetch activity.",
                TechnicalNotes = "Tweak #23 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "sc config \"SysMain\" start= disabled", "sc stop \"SysMain\"" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 24,
                Title = "Tune Heap Decommit Threshold",
                Description = "Raises the heap decommit free block threshold so that the allocator retains freed memory pages longer before releasing them.",
                TechnicalNotes = "Tweak #24 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v HeapDeCommitFreeBlockThreshold /t REG_DWORD /f /d 0x4000" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 25,
                Title = "Tune Lazy Writer",
                Description = "Enables the large system cache mode, tuning the Lazy Writer to favour caching file data in RAM.",
                TechnicalNotes = "Tweak #25 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v LargeSystemCache /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 26,
                Title = "Raise Modified Page Writer Limit",
                Description = "Increases the Modified Page Writer threshold, delaying writeback of dirty pages and reducing burst write activity.",
                TechnicalNotes = "Tweak #26 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v ModifiedPageWriterLimit /t REG_DWORD /f /d 64" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 27,
                Title = "Aggressive Cache Unmap Behind",
                Description = "Reduces the cache manager unmap-behind length, controlling how aggressively previously accessed file pages are evicted.",
                TechnicalNotes = "Tweak #27 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v UnmapBehindLength /t REG_DWORD /f /d 16" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 28,
                Title = "Disable NTFS 8.3 Name Creation & Last Access Metadata",
                Description = "Disables NTFS 8.3 short filename generation and last-access timestamp updates, reducing per-file metadata write overhead.",
                TechnicalNotes = "Tweak #28 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "fsutil behavior set disable8dot3 1", "fsutil behavior set disablelastaccess 1" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 29,
                Title = "fsutil Memory Usage",
                Description = "Sets the NTFS memory usage level to 2, allowing the file system driver to use a larger portion of RAM for its internal caches.",
                TechnicalNotes = "Tweak #29 · MEMORY / STORAGE",
                Category = "MEMORY / STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "fsutil behavior set memoryusage 2" },
                Tags = new ObservableCollection<string> { "memory / storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 30,
                Title = "Async NTFS Lazy Writer (Already handled by fsutil memoryusage)",
                Description = "No executable command — async lazy writer behaviour is already governed by the fsutil memoryusage setting above.",
                TechnicalNotes = "Tweak #30 · I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> {  },
                Tags = new ObservableCollection<string> { "i/o & storage", "info" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 31,
                Title = "Disable NVMe Power Management",
                Description = "Disables NVMe device power management, preventing the controller from entering low-power states that cause latency spikes.",
                TechnicalNotes = "Tweak #31 · I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\stornvme\\Parameters\" /v NvmeDisablePowerManagement /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 32,
                Title = "Disable Storage Sense",
                Description = "Disables Windows Storage Sense automatic disk cleanup to prevent background scans from causing unexpected I/O bursts.",
                TechnicalNotes = "Tweak #32 · I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy\" /v 01 /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 33,
                Title = "Split Large Caches",
                Description = "Sets the system cache split threshold so that large and small allocations use separate cache regions, reducing contention.",
                TechnicalNotes = "Category: I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v LargeCacheSplit /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 34,
                Title = "Reduce Registry Flush Frequency",
                Description = "Reduces the registry flush interval, lowering the chance that registry writes cause a burst of disk I/O at inopportune times.",
                TechnicalNotes = "Category: I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager\" /v RegistryLazyFlushInterval /t REG_DWORD /f /d 120" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 35,
                Title = "Reduce Service Host Processes (SvcHostSplitThreshold)",
                Description = "Raises the service host split threshold so that fewer services are separated into individual processes, saving RAM overhead.",
                TechnicalNotes = "Category: I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v SvcHostSplitThresholdInKB /t REG_DWORD /f /d 0xFFFFFFFF" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 36,
                Title = "Disable Reserved Storage",
                Description = "Disables the Windows reserved storage partition that pre-allocates disk space for updates.",
                TechnicalNotes = "Tweak #36 · I/O & STORAGE",
                Category = "I/O & STORAGE",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ReserveManager\" /v ShippedWithReserves /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "i/o & storage" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 37,
                Title = "Disable MMCCS Network Throttling",
                Description = "Disables the MMCSS network throttle, allowing network I/O to proceed without artificial bandwidth limits during media tasks.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v NetworkThrottlingIndex /t REG_DWORD /f /d 0xFFFFFFFF" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 38,
                Title = "Enable TCP Window Scaling",
                Description = "Enables TCP window scaling so that TCP receive windows can grow beyond 64 KB, improving throughput on high-latency links.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "netsh int tcp set global autotuninglevel=normal" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 39,
                Title = "Optimize TCP Keep-Alive",
                Description = "Reduces the TCP keep-alive timeout and interval, detecting dead connections faster and freeing socket resources sooner.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v KeepAliveTime /t REG_DWORD /f /d 30000" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 40,
                Title = "Reduce TCP TIME_WAIT Delay",
                Description = "Reduces the TCP TIME_WAIT delay, allowing ports to be recycled faster after a connection closes.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TcpTimedWaitDelay /t REG_DWORD /f /d 30" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 41,
                Title = "Minimize TCP Packet Latency",
                Description = "Sets TCP no-delay (Nagle disabled) to send small packets immediately without waiting for a full segment to accumulate.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TcpAckFrequency /t REG_DWORD /f /d 1", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\" /v TCPNoDelay /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 42,
                Title = "Disable NetBIOS Broadcasts",
                Description = "Disables NetBIOS over TCP/IP on all adapters, stopping broadcast traffic that adds latency to LAN name resolution.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\" /v NodeType /t REG_DWORD /f /d 2" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 43,
                Title = "Enable PMTU Black Hole Detection",
                Description = "Enables PMTU black-hole detection so TCP can fall back to a smaller MTU when routers silently discard oversized packets.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "netsh int tcp set global blackhole=enabled" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 44,
                Title = "Enable Network RSS Offloading",
                Description = "Enables Receive Side Scaling (RSS) offloading to spread incoming network packet processing across multiple CPU cores.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "netsh int tcp set global rss=enabled" },
                Tags = new ObservableCollection<string> { "network" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 45,
                Title = "Disable Adapter Interrupt Moderation & Energy Efficient Ethernet",
                Description = "Disables adapter interrupt moderation and Energy Efficient Ethernet to minimise latency at the cost of slightly higher power use.",
                TechnicalNotes = "Category: NETWORK",
                Category = "NETWORK",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> {  },
                Tags = new ObservableCollection<string> { "network", "info" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 46,
                Title = "Disable Power Throttling (EcoQoS)",
                Description = "Disables the EcoQoS (power throttling) mechanism that reduces CPU frequency for background processes.",
                TechnicalNotes = "Category: POWER MANAGEMENT",
                Category = "POWER MANAGEMENT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling\" /v PowerThrottlingOff /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "power management" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 47,
                Title = "Disable Fast Startup",
                Description = "Disables the Fast Startup hybrid boot feature, ensuring a full cold boot and preventing stale driver state from persisting.",
                TechnicalNotes = "Category: POWER MANAGEMENT",
                Category = "POWER MANAGEMENT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\" /v HiberbootEnabled /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "power management" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 48,
                Title = "Disable System Hibernation",
                Description = "Disables system hibernation and removes the hiberfil.sys file, freeing disk space and eliminating hibernate-related overhead.",
                TechnicalNotes = "Category: POWER MANAGEMENT",
                Category = "POWER MANAGEMENT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "powercfg /hibernate off" },
                Tags = new ObservableCollection<string> { "power management" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 49,
                Title = "Disable USB Selective Suspend",
                Description = "Disables USB selective suspend, preventing USB controllers from powering down idle ports and causing reconnect latency.",
                TechnicalNotes = "Category: POWER MANAGEMENT",
                Category = "POWER MANAGEMENT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "powercfg /setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0", "powercfg /setdcvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0", "powercfg /setactive SCHEME_CURRENT" },
                Tags = new ObservableCollection<string> { "power management" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 50,
                Title = "Disable Core Parking",
                Description = "Disables CPU core parking so that all logical processors remain active and immediately schedulable at all times.",
                TechnicalNotes = "Category: POWER MANAGEMENT",
                Category = "POWER MANAGEMENT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100", "powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100", "powercfg /setactive SCHEME_CURRENT" },
                Tags = new ObservableCollection<string> { "power management" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 51,
                Title = "Force Direct Flip Compositing & Disable Multi-Plane Overlays",
                Description = "Forces Direct Flip compositing mode and disables Multi-Plane Overlays to reduce DWM frame latency in full-screen apps.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm\" /v OverlayTestMode /t REG_DWORD /f /d 5" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 52,
                Title = "Disable Small GPU Context Quantum",
                Description = "Disables the small GPU context quantum, allowing GPU contexts to hold the hardware for longer before being preempted.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v DisableSmallGpuQuantum /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 53,
                Title = "Disable GPU Runtime D3 Power Management",
                Description = "Disables GPU runtime D3 (deepest dynamic) power management state, keeping the GPU ready to execute work immediately.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v DisableRuntimeD3 /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 54,
                Title = "Disable GPU P-State Management",
                Description = "Disables GPU P-state management, preventing driver-controlled GPU clock downscaling between frames.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v PStateOverride /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 55,
                Title = "Disable GPU TDR Recovery",
                Description = "Disables GPU TDR (Timeout Detection and Recovery), preventing the OS from resetting an unresponsive GPU.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v TdrLevel /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "gpu & display", "advanced" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 56,
                Title = "Extend GPU TDR Timeouts",
                Description = "Extends the GPU TDR timeout threshold and delay, giving compute or VR workloads more time before a watchdog fires.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v TdrDelay /t REG_DWORD /f /d 60" },
                Tags = new ObservableCollection<string> { "gpu & display", "advanced" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 57,
                Title = "Extend GPU TDR Retry Limit",
                Description = "Extends the GPU TDR retry limit, allowing more recovery attempts before Windows declares the GPU lost.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v TdrLimitCount /t REG_DWORD /f /d 10" },
                Tags = new ObservableCollection<string> { "gpu & display", "advanced" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 58,
                Title = "Enable Hardware GPU Scheduling",
                Description = "Enables Hardware-Accelerated GPU Scheduling (HAGS), reducing CPU-side scheduling latency for GPU command submission.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\" /v HwSchMode /t REG_DWORD /f /d 2" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 59,
                Title = "Elevate DWM Thread Priority",
                Description = "Sets the Desktop Window Manager thread priority to high, reducing compositor frame jitter under CPU load.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm\" /v ThreadPriority /t REG_DWORD /f /d 31" },
                Tags = new ObservableCollection<string> { "gpu & display" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 60,
                Title = "Enable Performance Isolation (Requires Hybrid CPU + specific scheduler, generally automatic)",
                Description = "Marks the process as preferring performance isolation; effective only on hybrid CPUs with the required scheduler support.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> {  },
                Tags = new ObservableCollection<string> { "gpu & display", "info" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 61,
                Title = "Enable L3 Cache Isolation (Requires Intel CAT hardware, cannot be done via simple BAT)",
                Description = "Marks the process for L3 cache isolation; requires Intel Cache Allocation Technology hardware and an OS-level CAT driver.",
                TechnicalNotes = "Category: GPU & DISPLAY",
                Category = "GPU & DISPLAY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> {  },
                Tags = new ObservableCollection<string> { "gpu & display", "info" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 62,
                Title = "Disable Advertising ID",
                Description = "Disables the Windows Advertising ID, preventing apps from tracking your advertising identifier across sessions.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\" /v Enabled /t REG_DWORD /f /d 0", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo\" /v DisabledByGroupPolicy /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 63,
                Title = "Disable Windows Telemetry",
                Description = "Disables DiagTrack and related telemetry services, stopping background data collection and phone-home traffic.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\" /v AllowTelemetry /t REG_DWORD /f /d 0", "sc config \"DiagTrack\" start= disabled", "sc stop \"DiagTrack\"" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 64,
                Title = "Disable Remote Assistance",
                Description = "Disables the Remote Assistance feature, closing the listening port and preventing unsolicited remote help requests.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance\" /v fAllowToGetHelp /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 65,
                Title = "Disable Windows Error Reporting",
                Description = "Disables Windows Error Reporting, stopping the WER service from collecting and sending crash data to Microsoft.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\" /v Disabled /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 66,
                Title = "Disable Tailored Experiences",
                Description = "Disables Tailored Experiences, preventing Cortana and the OS from using diagnostic data to suggest tips and ads.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy\" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 67,
                Title = "Disable Activity History",
                Description = "Disables Activity History tracking, stopping the OS from logging which apps and files you open for the Timeline feature.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v EnableActivityFeed /t REG_DWORD /f /d 0", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v PublishUserActivities /t REG_DWORD /f /d 0", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\" /v UploadUserActivities /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 68,
                Title = "Disable Defender Cloud Lookup",
                Description = "Disables Windows Defender cloud-based protection lookups, reducing background network requests during file scans.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "High",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SpynetReporting /t REG_DWORD /f /d 0", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\" /v SubmitSamplesConsent /t REG_DWORD /f /d 2" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 69,
                Title = "Disable Delivery Optimization P2P",
                Description = "Disables Delivery Optimization peer-to-peer update sharing, stopping Windows from uploading update data to other PCs.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config\" /v DODownloadMode /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 70,
                Title = "Disable Game Bar, Game DVR & Game Mode",
                Description = "Disables Xbox Game Bar, Game DVR background recording, and Game Mode to reduce overhead and background CPU usage.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\System\\GameConfigStore\" /v GameDVR_Enabled /t REG_DWORD /f /d 0", "reg add \"HKCU\\Software\\Microsoft\\GameBar\" /v AllowAutoGameMode /t REG_DWORD /f /d 0", "reg add \"HKCU\\Software\\Microsoft\\GameBar\" /v AutoGameModeEnabled /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 71,
                Title = "Disable Auto Maintenance",
                Description = "Disables Windows automatic maintenance tasks that can run I/O-heavy jobs at unexpected times.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance\" /v MaintenanceDisabled /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 72,
                Title = "Disable Start Web Search",
                Description = "Disables the Bing web search integration in the Start menu search box, keeping searches local.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer\" /v DisableSearchBoxSuggestions /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 73,
                Title = "Disable Automatic Driver Updates",
                Description = "Disables the Windows Update automatic driver search, preventing the OS from silently replacing vendor drivers.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DriverSearching\" /v SearchOrderConfig /t REG_DWORD /f /d 0", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 74,
                Title = "Disable UWP Background Apps",
                Description = "Prevents UWP (Store) applications from running background tasks when they are not in the foreground.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications\" /v GlobalUserDisabled /t REG_DWORD /f /d 1" },
                Tags = new ObservableCollection<string> { "privacy & telemetry" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 75,
                Title = "Disable Virtualization Security (VBS/HVCI) - Requires bcdedit and reboot",
                Description = "Disables Virtualization Based Security and HVCI via BCD flags; requires a reboot to take effect and reduces attack surface for some workloads.",
                TechnicalNotes = "Category: PRIVACY & TELEMETRY",
                Category = "PRIVACY & TELEMETRY",
                Risk = "Advanced",
                Mode = "Source",
                RequiresReboot = true,
                SourceCommands = new ObservableCollection<string> { "bcdedit /set hypervisorlaunchtype off", "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "privacy & telemetry", "reboot", "advanced" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 76,
                Title = "Remove Menu Delay",
                Description = "Sets the menu show delay to zero, removing the animation pause before popup menus appear.",
                TechnicalNotes = "Tweak #76 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Desktop\" /v MenuShowDelay /t REG_SZ /f /d \"0\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 77,
                Title = "Disable Mouse Acceleration",
                Description = "Disables mouse pointer acceleration (enhance pointer precision), giving a 1:1 linear mapping between physical and on-screen movement.",
                TechnicalNotes = "Tweak #77 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Mouse\" /v MouseSpeed /t REG_SZ /f /d \"0\"", "reg add \"HKCU\\Control Panel\\Mouse\" /v MouseThreshold1 /t REG_SZ /f /d \"0\"", "reg add \"HKCU\\Control Panel\\Mouse\" /v MouseThreshold2 /t REG_SZ /f /d \"0\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 78,
                Title = "Reduce Mouse Hover Area & Minimize Double-Click Area",
                Description = "Reduces the mouse hover detection rectangle and double-click zone to their minimum values, improving precision input.",
                TechnicalNotes = "Tweak #78 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Mouse\" /v MouseHoverWidth /t REG_SZ /f /d \"2\"", "reg add \"HKCU\\Control Panel\\Mouse\" /v MouseHoverHeight /t REG_SZ /f /d \"2\"", "reg add \"HKCU\\Control Panel\\Mouse\" /v DoubleClickWidth /t REG_SZ /f /d \"2\"", "reg add \"HKCU\\Control Panel\\Mouse\" /v DoubleClickHeight /t REG_SZ /f /d \"2\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 79,
                Title = "Minimize Mouse Class Buffer",
                Description = "Reduces the mouse class driver input buffer to its minimum, lowering input-to-render pipeline depth.",
                TechnicalNotes = "Tweak #79 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Mouclass\\Parameters\" /v MouseDataQueueSize /t REG_DWORD /f /d 20" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 80,
                Title = "Minimize Keyboard Repeat Delay",
                Description = "Sets keyboard auto-repeat delay to the minimum (250 ms), so held keys begin repeating faster.",
                TechnicalNotes = "Tweak #80 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Keyboard\" /v KeyboardDelay /t REG_SZ /f /d \"0\"", "reg add \"HKCU\\Control Panel\\Keyboard\" /v KeyboardSpeed /t REG_SZ /f /d \"31\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 81,
                Title = "Minimize Keyboard Class Buffer",
                Description = "Reduces the keyboard class driver input buffer to its minimum size, lowering keystroke pipeline depth.",
                TechnicalNotes = "Tweak #81 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kbdclass\\Parameters\" /v KeyboardDataQueueSize /t REG_DWORD /f /d 20" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 82,
                Title = "Disable Acrylic Transparency",
                Description = "Disables Windows Acrylic transparency effects, reducing GPU compositor load from blur and alpha operations.",
                TechnicalNotes = "Tweak #82 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v EnableTransparency /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 83,
                Title = "Disable Smooth Scrolling",
                Description = "Disables smooth list-view scrolling animations in Explorer and common controls, reducing animation CPU overhead.",
                TechnicalNotes = "Tweak #83 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Desktop\" /v SmoothScroll /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 84,
                Title = "Disable Shell Animations",
                Description = "Disables shell window animations including minimize, maximize, and transition effects.",
                TechnicalNotes = "Tweak #84 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Control Panel\\Desktop\\WindowMetrics\" /v MinAnimate /t REG_SZ /f /d \"0\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 85,
                Title = "Disable Snap Assist",
                Description = "Disables Snap Assist and the snap layout overlay that appears when dragging windows to screen edges.",
                TechnicalNotes = "Tweak #85 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v SnapAssist /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 86,
                Title = "Disable Auto Folder Type Detection",
                Description = "Disables automatic folder type detection in Explorer, preventing the shell from scanning folder contents to choose a view template.",
                TechnicalNotes = "Tweak #86 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\\AllFolders\\Shell\" /v FolderType /t REG_SZ /f /d \"NotSpecified\"" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            _allTweaks.Add(new TweakItem
            {
                Number = 87,
                Title = "Disable Windows Spotlight Wallpaper",
                Description = "Disables Windows Spotlight on the lock screen, stopping the OS from downloading and rotating background images.",
                TechnicalNotes = "Tweak #87 · UI & INPUT",
                Category = "UI & INPUT",
                Risk = "Standard",
                Mode = "Source",
                RequiresReboot = false,
                SourceCommands = new ObservableCollection<string> { "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v RotatingLockScreenEnabled /t REG_DWORD /f /d 0", "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\" /v SubscribedContent-338387Enabled /t REG_DWORD /f /d 0" },
                Tags = new ObservableCollection<string> { "ui & input" }
            });
            BuildCategories();
        }
        private void BuildCategories()
        {
            CategoryList.Items.Clear();
            AddCategory("ALL", "All");
            foreach (var category in _allTweaks.Select(t => t.Category).Distinct())
                AddCategory(category, CategoryDisplay(category));
            CategoryList.SelectedIndex = 0;
        }

        private void AddCategory(string tag, string title)
        {
            var item = new ListBoxItem { Tag = tag };
            var grid = new Grid { Margin = new Thickness(0) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var tb = new TextBlock { Text = title, VerticalAlignment = VerticalAlignment.Center };
            var count = new Border { Style = (Style)FindResource("CountBadge"), VerticalAlignment = VerticalAlignment.Center };
            count.Child = new TextBlock { Text = tag == "ALL" ? _allTweaks.Count.ToString() : _allTweaks.Count(t => t.Category == tag).ToString() };
            Grid.SetColumn(count, 1);
            grid.Children.Add(tb);
            grid.Children.Add(count);
            item.Content = grid;
            CategoryList.Items.Add(item);
        }

        private static string CategoryDisplay(string category) => category switch
        {
            "MEMORY / STORAGE" => "Memory & Storage",
            "GRAPHICS / SHELL" => "Graphics & Shell",
            "INPUT / SECURITY" => "Input & Security",
            "SERVICES / TELEMETRY / MMCSS" => "Services & Telemetry",
            "TIMER / DPC / KERNEL" => "Timers / DPC / Kernel",
            "SCHEDULER / CPU" => "Scheduler & CPU",
            "NETWORK / POWER" => "Network & Power",
            "POWER / STORAGE / CPU" => "Power / Storage / CPU",
            "TIMERS / GPU / CACHE" => "Timers / GPU / Cache",
            _ => category
        };

        private bool FilterTweak(object obj)
        {
            if (obj is not TweakItem t) return false;
            if (_selectedCategory != "ALL" && t.Category != _selectedCategory) return false;

            var query = SearchBox.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(query)) return true;

            return t.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
                || t.Description.Contains(query, StringComparison.OrdinalIgnoreCase)
                || t.Tags.Any(tag => tag.Contains(query, StringComparison.OrdinalIgnoreCase))
                || t.Category.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void UpdateCounts()
        {
            int total = _allTweaks.Count;
            int applied = _allTweaks.Count(t => t.IsApplied);
            int shown = _view?.Cast<TweakItem>().Count() ?? total;

            if (ResultCountRun != null) ResultCountRun.Text = shown.ToString();
            if (AppliedCountRun != null) AppliedCountRun.Text = applied.ToString();
            if (LibraryCountRun != null) LibraryCountRun.Text = total.ToString();
        }

        private void CategoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_view == null) return;
            if (CategoryList.SelectedItem is ListBoxItem item && item.Tag is string tag)
            {
                _selectedCategory = tag;
                _view.Refresh();
                UpdateCounts();
                LibraryScroll?.ScrollToTop();
            }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_view == null) return;
            _view.Refresh();
            UpdateCounts();
        }

        private async Task<bool> EnsureOnlineLicenseAsync()
        {
            if (_validationInProgress) return _licenseValid;
            _validationInProgress = true;
            try
            {
                var state = await _authService.ValidateOnlineAsync(_authSession);
                var active = state.ActiveLicense;
                _authSession.SetActiveLicense(active);
                _licenseValid = active is not null && active.ActivatedOnThisDevice && (active.ExpiresUtc is null || active.ExpiresUtc > DateTime.UtcNow);
                IsTuningAllowed = _licenseValid;
                UpdateAccountUi();
                if (_licenseValid)
                {
                    _offlineTimer.Stop();
                    ScanStatusText.Text = "Online license validated";
                }
                else
                {
                    EnterOnlineFailure("License inactive · tuning actions locked");
                }
                return _licenseValid;
            }
            catch
            {
                EnterOnlineFailure("Online license validation required · tuning actions locked");
                return false;
            }
            finally
            {
                _validationInProgress = false;
            }
        }

        private static (bool Available, bool HasRestorePoint, string Message) GetRestorePointStatus()
        {
            try
            {
                using var p = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        Arguments = "-NoProfile -Command \"$rp = Get-ComputerRestorePoint -ErrorAction Stop; if ($null -eq $rp) { 'NONE' } else { 'FOUND' }\""
                    }
                };
                p.Start();
                var stdout = p.StandardOutput.ReadToEnd().Trim();
                var stderr = p.StandardError.ReadToEnd().Trim();
                p.WaitForExit();
                if (p.ExitCode != 0)
                    return (false, false, string.IsNullOrWhiteSpace(stderr) ? "System Restore unavailable" : "System Restore unavailable");
                return stdout.Equals("FOUND", StringComparison.OrdinalIgnoreCase)
                    ? (true, true, "Restore point available")
                    : (true, false, "No restore point detected");
            }
            catch
            {
                return (false, false, "System Restore unavailable");
            }
        }

        private void UpdateRestorePointStatus()
        {
            var status = GetRestorePointStatus();
            if (RestorePointStatusText != null)
                RestorePointStatusText.Text = status.Message;
            var dot = status.Available && status.HasRestorePoint
                ? Color.FromRgb(53, 212, 154)
                : status.Available
                    ? Color.FromRgb(241, 184, 74)
                    : Color.FromRgb(255, 135, 149);
            if (RestorePointStatusDot != null) RestorePointStatusDot.Fill = new SolidColorBrush(dot);
        }

        private async void CreateRestorePoint_Click(object sender, RoutedEventArgs e)
        {
            if (!IsAdministrator()) return;
            CreateRestorePointButton.IsEnabled = false;
            if (RestorePointStatusText != null) RestorePointStatusText.Text = "Creating restore point…";
            try
            {
                var result = await Task.Run(() =>
                {
                    using var p = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            Arguments = "-NoProfile -Command \"Checkpoint-Computer -Description 'Surge - Before Tuning' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop; 'OK'\""
                        }
                    };
                    // Drain both pipes concurrently and bound the wait. Reading stdout to
                    // completion before touching stderr deadlocks as soon as the child fills the
                    // stderr buffer, and WaitForExit() with no timeout pinned this thread
                    // indefinitely when Checkpoint-Computer stalled on a busy VSS writer.
                    p.Start();
                    var stdoutTask = p.StandardOutput.ReadToEndAsync();
                    var stderrTask = p.StandardError.ReadToEndAsync();

                    const int restorePointTimeoutMs = 90_000; // VSS snapshots are legitimately slow.
                    if (!p.WaitForExit(restorePointTimeoutMs))
                    {
                        try { p.Kill(entireProcessTree: true); } catch { }
                        return (false, "Creating the restore point timed out.");
                    }

                    var stdout = (stdoutTask.Wait(2000) ? stdoutTask.Result : string.Empty).Trim();
                    var stderr = (stderrTask.Wait(2000) ? stderrTask.Result : string.Empty).Trim();
                    return (p.ExitCode == 0 && stdout.Contains("OK", StringComparison.OrdinalIgnoreCase), stderr);
                });

                if (!result.Item1)
                {
                    MessageBox.Show(
                        string.IsNullOrWhiteSpace(result.Item2)
                            ? "Windows could not create a restore point. System Restore may be disabled or Windows may be enforcing its restore-point frequency policy."
                            : result.Item2,
                        "Surge — Restore Point", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                ErrorReporter.Show("Surge — Restore Point", "Unable to create the system restore point:", ex, MessageBoxImage.Warning);
            }
            finally
            {
                UpdateRestorePointStatus();
                CreateRestorePointButton.IsEnabled = true;
            }
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void AnimateWindowIn()
        {
            if (RootChrome == null) return;
            RootChrome.Opacity = 0;
            RootChrome.RenderTransform = new TranslateTransform(0, 10);
            var sb = new Storyboard();
            var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(320))) { DecelerationRatio = 0.8 };
            Storyboard.SetTarget(fade, RootChrome);
            Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
            var slide = new DoubleAnimation(10, 0, new Duration(TimeSpan.FromMilliseconds(420))) { DecelerationRatio = 0.85 };
            Storyboard.SetTarget(slide, RootChrome);
            Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
            sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();

            if (AmbientGlowA != null && AmbientGlowB != null)
            {
                var ambience = new Storyboard();
                var a = new DoubleAnimation(0.08, 0.15, new Duration(TimeSpan.FromSeconds(2.8))) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever };
                Storyboard.SetTarget(a, AmbientGlowA); Storyboard.SetTargetProperty(a, new PropertyPath(UIElement.OpacityProperty));
                var b = new DoubleAnimation(0.028, 0.065, new Duration(TimeSpan.FromSeconds(3.6))) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever };
                Storyboard.SetTarget(b, AmbientGlowB); Storyboard.SetTargetProperty(b, new PropertyPath(UIElement.OpacityProperty));
                ambience.Children.Add(a); ambience.Children.Add(b); ambience.Begin();
            }
        }

        private void AccountCenter_Click(object sender, RoutedEventArgs e)
        {
            var window = new AccountCenterWindow(_authSession, _authService);
            window.Owner = this;
            Hide();
            window.ShowDialog();
            if (window.SignedOut)
            {
                var login = new AuthWindow(_authService);
                Application.Current.MainWindow = login;
                login.Show();
                Close();
                return;
            }
            if (_authSession.ActiveLicense is null || !_authSession.ActiveLicense.ActivatedOnThisDevice)
            {
                var login = new AuthWindow(_authService);
                Application.Current.MainWindow = login;
                login.Show();
                Close();
                return;
            }
            Show();
            WindowState = WindowState.Normal;
            AnimateWindowIn();
            UpdateAccountUi();
        }

        private async void TweakToggle_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not CheckBox checkBox || checkBox.DataContext is not TweakItem tweak) return;
            if (!IsTuningAllowed || !_licenseValid) { checkBox.IsChecked = tweak.IsApplied; ScanStatusText.Text = "License inactive or server unavailable · tuning action blocked"; return; }
            if (tweak.IsBusy) return;
            if (!await EnsureOnlineLicenseAsync())
            {
                checkBox.IsChecked = tweak.IsApplied;
                return;
            }

            bool previous = tweak.IsApplied;
            bool requestedApplied = checkBox.IsChecked == true;
            tweak.IsBusy = true;
            tweak.VerificationFailed = false;
            tweak.VerificationText = requestedApplied ? "Applying…" : "Reverting…";
            try
            {
                var result = requestedApplied
                    ? await _tweakEngine.ApplyAsync(tweak)
                    : await _tweakEngine.RevertAsync(tweak);

                ApplyScanResult(tweak, result);

                if (result.State is TweakEngineState.Failed or TweakEngineState.Unknown or TweakEngineState.Unsupported)
                    checkBox.IsChecked = previous;
            }
            finally
            {
                tweak.IsBusy = false;
                UpdateCounts();
            }
        }

        private async void ApplyAll_Click(object sender, RoutedEventArgs e)
        {
            if (_isApplyAllRunning)
            {
                // Pause / Resume toggle
                _applyAllPaused = !_applyAllPaused;
                ScanStatusText.Text = _applyAllPaused ? "Apply All paused · click Apply All to resume" : "Apply All resumed…";
                return;
            }

            if (!await EnsureOnlineLicenseAsync()) return;

            var pending = _allTweaks.Where(x => x.CanApplyFromUi && !x.IsApplied).ToList();
            if (pending.Count == 0) { ScanStatusText.Text = "All tweaks are already applied."; return; }

            _isApplyAllRunning = true;
            _applyAllPaused = false;
            CancelApplyAllButton.Visibility = Visibility.Visible;
            _applyAllCts = new CancellationTokenSource();
            var ct = _applyAllCts.Token;

            int total = pending.Count;
            int done = 0, failed = 0, rolledBack = 0;

            try
            {
                foreach (var tweak in pending)
                {
                    if (ct.IsCancellationRequested) break;

                    // Pause support — spin-wait until unpaused or cancelled
                    while (_applyAllPaused && !ct.IsCancellationRequested)
                        await Task.Delay(200, CancellationToken.None);

                    if (ct.IsCancellationRequested) break;

                    tweak.IsBusy = true;
                    tweak.VerificationText = $"Applying… ({done + 1}/{total})";
                    ScanStatusText.Text = $"Applying tweaks — {done + 1} / {total}  ·  {tweak.Title}";

                    var result = await _tweakEngine.ApplyAsync(tweak, ct);
                    ApplyScanResult(tweak, result);
                    tweak.IsBusy = false;

                    done++;
                    if (result.State == TweakEngineState.Failed)
                    {
                        failed++;
                        if (result.RollbackPerformed) rolledBack++;
                        tweak.VerificationText = result.RollbackPerformed ? "Failed · rolled back" : "Failed";
                    }
                    else if (result.State == TweakEngineState.Default && result.RollbackPerformed)
                    {
                        failed++;
                        rolledBack++;
                        tweak.VerificationText = "Failed · exact state restored";
                    }

                    UpdateCounts();
                }
            }
            catch (OperationCanceledException) { /* user cancelled */ }
            finally
            {
                foreach (var t in _allTweaks) t.IsBusy = false;
                _isApplyAllRunning = false;
                _applyAllPaused = false;
                _applyAllCts?.Dispose();
                _applyAllCts = null;
                CancelApplyAllButton.Visibility = Visibility.Collapsed;
                UpdateCounts();

                bool cancelled = ct.IsCancellationRequested;
                if (cancelled)
                    ScanStatusText.Text = $"Apply All cancelled — {done}/{total} processed · {failed} failed";
                else if (failed == 0)
                    ScanStatusText.Text = $"Apply All complete — {done}/{total} applied · all verified";
                else
                    ScanStatusText.Text = $"Apply All complete — {done}/{total} processed · {failed} failed · {rolledBack} rolled back";
            }
        }

        private void CancelApplyAll_Click(object sender, RoutedEventArgs e)
        {
            _applyAllCts?.Cancel();
        }

        private async void RevertAll_Click(object sender, RoutedEventArgs e)
        {
            if (!await EnsureOnlineLicenseAsync()) return;
            var pending = _allTweaks.Where(x => x.CanApplyFromUi && x.IsApplied).ToList();
            int total = pending.Count, done = 0, failed = 0;
            ScanStatusText.Text = $"Reverting tweaks — 0 / {total}";
            foreach (var tweak in pending)
            {
                tweak.IsBusy = true;
                done++;
                tweak.VerificationText = $"Reverting… ({done}/{total})";
                ScanStatusText.Text = $"Reverting tweaks — {done} / {total}  ·  {tweak.Title}";
                var result = await _tweakEngine.RevertAsync(tweak);
                ApplyScanResult(tweak, result);
                if (result.State == TweakEngineState.Failed)
                {
                    failed++;
                    tweak.EngineState = TweakEngineState.Applied;
                    tweak.VerificationText = "Revert failed · state preserved";
                }
                tweak.IsBusy = false;
                UpdateCounts();
            }
            UpdateCounts();
            ScanStatusText.Text = failed == 0
                ? $"Revert All complete — {done}/{total} reverted · all verified"
                : $"Revert All complete — {done}/{total} processed · {failed} could not revert";
        }

        private void ReadMore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button button || button.DataContext is not TweakItem tweak) return;
            var detail = new TweakDescriptionWindow(tweak.Title, tweak.Category, tweak.Description, tweak.TechnicalNotes)
            {
                Owner = this
            };
            detail.ShowDialog();
        }

        private void OpenLog_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var window = new OperationLogWindow { Owner = this };
                window.ShowDialog();
            }
            catch (Exception ex)
            {
                ErrorReporter.Show("Surge — Operation Log", "Unable to open the protected operation log:", ex, MessageBoxImage.Warning);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _licenseTimer.Stop();
            _offlineTimer.Stop();
            base.OnClosed(e);
        }

        private bool EnsureAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                return true;

            MessageBox.Show(
                "Surge must run with Administrator permission. Please restart the application and approve the Windows UAC prompt.",
                "Surge — Administrator permission",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return false;
        }

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2) { Maximize_Click(sender, e); return; }
            if (e.LeftButton == MouseButtonState.Pressed) DragMove();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void Close_Click(object sender, RoutedEventArgs e) => Close();
    }
}
