using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Surge.AdminPanel;

public partial class App : Application
{
    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        try
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            var window = new MainWindow();
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            ShowFatal(ex);
            Shutdown(-1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ShowFatal(e.Exception);
        e.Handled = true;
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex) ShowFatal(ex);
    }

    private static void ShowFatal(Exception ex)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Surge");
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, "AdminPanel-startup.log");
            File.AppendAllText(file, $"[{DateTime.UtcNow:O}]\r\n{ex}\r\n\r\n");
            MessageBox.Show(
                "Surge Admin Panel could not start.\n\n" + ex.Message + "\n\nDiagnostic log:\n" + file,
                "Surge Admin Panel - Startup Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch { }
    }
}
