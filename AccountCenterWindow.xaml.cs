using SurgeApp.Models;
using SurgeApp.Services;
using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace SurgeApp;

public partial class AccountCenterWindow : Window
{
    private readonly AuthSession _session;
    private readonly AuthService _auth;
    public bool SignedOut { get; private set; }

    public AccountCenterWindow(AuthSession session, AuthService auth)
    {
        _session = session;
        _auth = auth;
        Owner = Application.Current.MainWindow;
        InitializeComponent();
        Render();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        AnimateWindowIn();
        Render();
    }

    private void AnimateWindowIn()
    {
        if (RootChrome == null) return;
        RootChrome.Opacity = 0;
        var sb = new Storyboard();
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(330))) { DecelerationRatio = 0.8 };
        Storyboard.SetTarget(fade, RootChrome); Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
        var slide = new DoubleAnimation(10, 0, new Duration(TimeSpan.FromMilliseconds(420))) { DecelerationRatio = 0.85 };
        Storyboard.SetTarget(slide, RootChrome); Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
        sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();
    }

    private void Render()
    {
        EmailText.Text = _session.User.Email;
        AccountSinceText.Text = "Member since " + _session.User.CreatedUtc.ToLocalTime().ToString("yyyy-MM-dd");
        DeviceNameText.Text = _session.Device.DisplayName;
        DeviceIdText.Text = _session.Device.Id;
        FirstSeenText.Text = _session.Device.FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        LastSeenText.Text = _session.Device.LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");

        var l = _session.ActiveLicense;
        if (l is null)
        {
            LicenseStatusText.Text = "INACTIVE";
            LicenseStatusText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(255,135,149));
            PlanText.Text = "No active license";
            LicenseIdText.Text = "No license bound to this device.";
            DevicesText.Text = "—";
            ExpiresText.Text = "—";
            MaskedKeyText.Text = "—";
            return;
        }

        var usable = l.ActivatedOnThisDevice && (l.ExpiresUtc is null || l.ExpiresUtc > DateTime.UtcNow);
        LicenseStatusText.Text = usable ? "ACTIVE" : "EXPIRED / INACTIVE";
        LicenseStatusText.Foreground = new System.Windows.Media.SolidColorBrush(usable ? System.Windows.Media.Color.FromRgb(88,220,175) : System.Windows.Media.Color.FromRgb(255,135,149));
        PlanText.Text = l.Plan;
        LicenseIdText.Text = "ID " + l.Id;
        DevicesText.Text = $"{l.ActiveDevices} / {l.MaxDevices}";
        ExpiresText.Text = l.ExpiresUtc is null ? "No expiry" : l.ExpiresUtc.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        MaskedKeyText.Text = l.LicenseKeyMasked;
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        SetBusy(true);
        try
        {
            await _auth.ValidateOnlineAsync(_session);
            Render();
            StatusText.Text = "Account and license validated online.";
        }
        catch (Exception ex) { StatusText.Text = ex.Message; }
        finally { SetBusy(false); }
    }

    private async void SignOut_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Sign out of this Surge account on this PC? The hardware binding is not released.",
            "Surge — Sign out", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes) return;

        SetBusy(true);
        try
        {
            await _auth.SignOutAsync(_session);
            SignedOut = true;
            DialogResult = true;
            Close();
        }
        catch (Exception ex)
        {
            StatusText.Text = ex.Message;
        }
        finally { SetBusy(false); }
    }

    private void SetBusy(bool busy)
    {
        RefreshButton.IsEnabled = !busy;
        SignOutButton.IsEnabled = !busy;
        Cursor = busy ? System.Windows.Input.Cursors.Wait : System.Windows.Input.Cursors.Arrow;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
