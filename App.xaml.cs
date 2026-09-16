using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using SurgeApp.Services;

namespace SurgeApp;

public partial class App : Application
{
    private AuthService? _auth;

    public App()
    {
        DispatcherUnhandledException += (_, args) =>
        {
            ErrorReporter.Log("dispatcher_crash", args.Exception);
            try
            {
                MessageBox.Show(
                    "Surge encountered an unexpected UI error.\n\n" +
                    ErrorReporter.UserFacingDetail(args.Exception) +
                    "\n\nLog:\n" + SecureLogManager.LogFile,
                    "Surge — Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch { /* no UI available */ }
            args.Handled = true;
        };
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex) ErrorReporter.Log("crash", ex);
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            ErrorReporter.Log("unobserved", args.Exception);
            args.SetObserved();
        };

        try
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            _auth = new AuthService();

            // The login window is shown first and the version check runs afterwards, off the UI
            // thread. The previous code called CheckVersionAsync().GetAwaiter().GetResult() inside
            // OnStartup: blocking the WPF dispatcher thread on a task whose continuations are
            // posted back to that same dispatcher is a textbook deadlock, and even when it did not
            // deadlock it froze the app for the full HTTP timeout whenever the license server was
            // slow or unreachable.
            var login = new AuthWindow(_auth);
            MainWindow = login;
            login.Show();

            _ = CheckForForcedUpdateAsync();
        }
        catch (Exception ex)
        {
            ErrorReporter.Log("startup_fatal", ex);
            MessageBox.Show(
                "Surge could not start.\n\n" +
                ErrorReporter.UserFacingDetail(ex) +
                "\n\nA diagnostic log was written to:\n" + SecureLogManager.LogFile,
                "Surge — Startup Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    /// <summary>
    /// Best-effort forced-update check. A server or network problem must never make the desktop
    /// client silently disappear before the login window, so every failure path is non-fatal.
    /// </summary>
    private async Task CheckForForcedUpdateAsync()
    {
        if (_auth is null) return;

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var (latestText, minimumText, force) = await _auth.Api.CheckVersionAsync(cts.Token).ConfigureAwait(false);

            // Two independent reasons to block: an operator-forced upgrade, or a build older than
            // the server's declared minimum. Either one is a hard stop; neither is a silent update,
            // because this product ships no in-product updater.
            var belowMinimum = Version.TryParse(minimumText, out var minimum) && ErrorReporter.CurrentVersion < minimum;
            if (!force && !belowMinimum) return;
            if (!Version.TryParse(latestText, out var latest)) return;
            if (!belowMinimum && latest <= ErrorReporter.CurrentVersion) return;

            // Marshal back to the UI thread before touching any window.
            await Dispatcher.InvokeAsync(() =>
            {
                MessageBox.Show(
                    $"Surge {latestText} is required. Please download and install the new version manually.",
                    "Surge — Update Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                Shutdown();
            });
        }
        catch (Exception ex)
        {
            ErrorReporter.Log("startup_version_check", ex);
        }
    }
}
