using SurgeApp.Models;
using SurgeApp.Services;
using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Input;

namespace SurgeApp;

public partial class AuthWindow : Window
{
    private readonly AuthService _auth;
    private AuthSession? _session;

    public AuthWindow(AuthService auth)
    {
        _auth = auth;
        InitializeComponent();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        AnimateWindowIn();
        try
        {
            var restored = await _auth.TryRestoreAsync();
            if (restored.Session is not null)
            {
                _session = restored.Session;
                ShowAccountPanel();
                if (_session.ActiveLicense is not null && IsLicenseUsable(_session.ActiveLicense))
                    OpenMainWindow();
            }
        }
        catch (Exception ex) { StatusText.Text = ex.Message; }
    }

    private async void Login_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async () =>
        {
            var (session, error) = await _auth.LoginAsync(EmailBox.Text, PasswordBox.Password);
            if (session is null) { StatusText.Text = error ?? "Sign-in failed."; return; }
            _session = session;
            _auth.Save(session);
            ShowAccountPanel();
            if (session.ActiveLicense is not null && IsLicenseUsable(session.ActiveLicense)) OpenMainWindow();
            else StatusText.Text = "Account connected. Activate a valid license on this device to continue.";
        });
    }

    private async void Register_Click(object sender, RoutedEventArgs e)
    {
        await RunBusyAsync(async () =>
        {
            var (session, error) = await _auth.RegisterAsync(EmailBox.Text, PasswordBox.Password);
            if (session is null) { StatusText.Text = error ?? "Account creation failed."; return; }
            _session = session;
            _auth.Save(session);
            ShowAccountPanel();
            StatusText.Text = "Account created. Enter your license key to activate this device.";
        });
    }

    private async void Activate_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || string.IsNullOrWhiteSpace(LicenseKeyBox.Text)) return;
        await RunBusyAsync(async () =>
        {
            try
            {
                var license = await _auth.ActivateAsync(_session, LicenseKeyBox.Text);
                UpdateLicenseUi(license);
                StatusText.Text = "License activated on this device.";
                OpenButton.Visibility = Visibility.Visible;
            }
            catch (Exception ex) { StatusText.Text = "Server validation required. " + ex.Message; }
        });
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;

        var confirm = MessageBox.Show(
            "Sign out on this PC? Your device, HWID, and license stay bound to this account — only an administrator can release them.",
            "Surge — Sign out", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await RunBusyAsync(async () =>
        {
            try
            {
                await _auth.SignOutAsync(_session);
                _session = null;
                AccountPanel.Visibility = Visibility.Collapsed;
                LoginPanel.Visibility = Visibility.Visible;
                SignOutButton.Visibility = Visibility.Collapsed;
                OpenButton.Visibility = Visibility.Collapsed;
                LicenseKeyBox.Clear();
                StatusText.Text = "Signed out. This device remains bound to your account.";
            }
            catch (Exception ex)
            {
                StatusText.Text = FormatAuthError(ex);
            }
        });
    }

    private void Open_Click(object sender, RoutedEventArgs e) => OpenMainWindow();

    private async void OpenMainWindow()
    {
        if (_session?.ActiveLicense is null || !IsLicenseUsable(_session.ActiveLicense))
        {
            StatusText.Text = "A valid active license is required.";
            return;
        }

        var main = new MainWindow(_session!, _auth);
        Application.Current.MainWindow = main;
        try
        {
            if (RootChrome != null)
            {
                var sb = new Storyboard();
                var fade = new DoubleAnimation(1, 0, new Duration(TimeSpan.FromMilliseconds(150)))
                { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn } };
                Storyboard.SetTarget(fade, RootChrome);
                Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
                sb.Children.Add(fade);
                sb.Begin();
                await Task.Delay(110);
            }
        }
        catch { }
        main.Show();
        Hide();
        main.Closed += (_, _) => Application.Current.Shutdown();
    }

    private void AnimateWindowIn()
    {
        if (RootChrome == null) return;
        RootChrome.Opacity = 0;
        var sb = new Storyboard();
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(360))) { DecelerationRatio = 0.8 };
        Storyboard.SetTarget(fade, RootChrome); Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
        var slide = new DoubleAnimation(10, 0, new Duration(TimeSpan.FromMilliseconds(440))) { DecelerationRatio = 0.85 };
        Storyboard.SetTarget(slide, RootChrome); Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
        sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();
    }

    private static void AnimatePanelIn(UIElement element)
    {
        if (element.RenderTransform is not TranslateTransform) element.RenderTransform = new TranslateTransform(0, 8);
        element.Opacity = 0;
        var sb = new Storyboard();
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(220)));
        Storyboard.SetTarget(fade, element); Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
        var slide = new DoubleAnimation(8, 0, new Duration(TimeSpan.FromMilliseconds(280))) { DecelerationRatio = 0.82 };
        Storyboard.SetTarget(slide, element); Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
        sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();
    }

    private void ShowAccountPanel()
    {
        LoginPanel.Visibility = Visibility.Collapsed;
        AccountPanel.Visibility = Visibility.Visible;
        AnimatePanelIn(AccountPanel);
        if (_session is null) return;
        AccountEmailText.Text = _session.User.Email;
        DeviceText.Text = "Device " + _session.DeviceId[..Math.Min(12, _session.DeviceId.Length)] + "…";
        UpdateLicenseUi(_session.ActiveLicense);
    }

    private void UpdateLicenseUi(LicenseDto? license)
    {
        if (license is null)
        {
            LicenseStatusText.Text = "Not activated";
            LicenseDetailText.Text = "No active license on this device.";
            LicenseDot.Fill = new SolidColorBrush(Color.FromRgb(119, 123, 144));
            OpenButton.Visibility = Visibility.Collapsed;
            SignOutButton.Visibility = Visibility.Visible;
            return;
        }

        LicenseStatusText.Text = IsLicenseUsable(license) ? "Active · " + license.Plan : "Expired";
        LicenseDetailText.Text = $"ID {license.Id[..Math.Min(10, license.Id.Length)]}… · {license.LicenseKeyMasked} · {license.ActiveDevices}/{license.MaxDevices} devices" +
            (license.ExpiresUtc is null ? " · no expiry" : " · expires " + license.ExpiresUtc.Value.ToLocalTime().ToString("yyyy-MM-dd"));
        LicenseDot.Fill = IsLicenseUsable(license)
            ? new SolidColorBrush(Color.FromRgb(48, 211, 160))
            : new SolidColorBrush(Color.FromRgb(255, 135, 149));
        OpenButton.Visibility = IsLicenseUsable(license) ? Visibility.Visible : Visibility.Collapsed;
        SignOutButton.Visibility = Visibility.Visible;
    }

    private static bool IsLicenseUsable(LicenseDto license) =>
        license.ActivatedOnThisDevice && (license.ExpiresUtc is null || license.ExpiresUtc > DateTime.UtcNow);

    private async Task RunBusyAsync(Func<Task> action)
    {
        SetBusy(true);
        try { await action(); }
        finally { SetBusy(false); }
    }

    private static string FormatAuthError(Exception ex)
    {
        var text = ex.Message ?? "Request failed.";
        if (text.Contains("HTTP 400", StringComparison.OrdinalIgnoreCase)) return "Request rejected · " + text;
        if (text.Contains("HTTP 401", StringComparison.OrdinalIgnoreCase)) return "Session rejected · sign in again.";
        if (text.Contains("HTTP 403", StringComparison.OrdinalIgnoreCase)) return "Access denied · " + text;
        if (text.Contains("actively refused", StringComparison.OrdinalIgnoreCase) || text.Contains("No connection", StringComparison.OrdinalIgnoreCase)) return "License server unavailable · internet/server connection required.";
        return text;
    }

    private void SetBusy(bool busy)
    {
        LoginButton.IsEnabled = !busy;
        RegisterButton.IsEnabled = !busy;
        ActivateButton.IsEnabled = !busy;
        OpenButton.IsEnabled = !busy;
        Cursor = busy ? Cursors.Wait : Cursors.Arrow;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Application.Current.Shutdown();
}
