using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace Surge.AdminPanel;

public partial class MainWindow : Window
{
    /// <summary>
    /// Fallback endpoint when SURGE_API_URL is unset.
    ///
    /// Current production/field endpoint. The deployment intentionally uses Nginx on port 80
    /// and proxies to the loopback License Server. Admin credentials must never be logged.
    /// </summary>
    private const string DefaultApiUrl = "http://95.38.233.67/";

    private static string ApiUrl => NormalizeApiUrl(
#if DEBUG
        Environment.GetEnvironmentVariable("SURGE_API_URL")
#else
        null
#endif
    );

    private readonly HttpClient _http = CreateHttpClient();

    /// <summary>
    /// Normalizes the configured API endpoint. Plain HTTP is intentionally supported for the
    /// current deployment because the public endpoint is HTTP-only.
    /// </summary>
    private static string NormalizeApiUrl(string? configured)
    {
        var candidate = string.IsNullOrWhiteSpace(configured) ? DefaultApiUrl : configured.Trim();
        if (!candidate.EndsWith('/')) candidate += "/";

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
            throw new InvalidOperationException($"SURGE_API_URL is not a valid absolute URL: '{configured}'.");

        if (uri.Scheme == Uri.UriSchemeHttps) return uri.ToString();
        // HTTP is intentionally supported by the current deployment.
        if (uri.Scheme == Uri.UriSchemeHttp) return uri.ToString();

        throw new InvalidOperationException(
            $"Unsupported API URL scheme '{uri.Scheme}'. Use http:// or https://.");
    }

    private static HttpClient CreateHttpClient()
    {
        // Do not route through the Windows system proxy, which has returned misleading HTTP 503s
        // on hosts that are demonstrably reachable.
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            SslOptions = new SslClientAuthenticationOptions
            {
                // TLS 1.2 floor; no certificate-validation override anywhere in this client.
                // Revocation checking is disabled for the same reason as the desktop client:
                // the endpoint presents a 160-hour Let's Encrypt IP certificate, which is not
                // required to publish revocation data. Chain validation is untouched.
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }
        };

        return new HttpClient(handler)
        {
            BaseAddress = new Uri(ApiUrl),
            Timeout = TimeSpan.FromSeconds(20)
        };
    }
    private string? _token;
    /// <summary>Last result of GET /api/health. Independent of whether systemctl control works.</summary>
    private bool _serverHealthy;
    private readonly ConcurrentDictionary<string, string> _sessionLicenseKeys = new();


    public MainWindow()
    {
        InitializeComponent();
        AdminUserBox.Text = Environment.GetEnvironmentVariable("SURGE_ADMIN_USER") ?? "admin";
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
        Title = $"Surge Admin Panel v{version}";
        ApiUrlText.Text = $"API: {ApiUrl}";
        StatusText.Text = "Ready. Enter administrator credentials.";
        ServerStatusText.Text = "● Checking server";
    }

    private async void Login_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(AdminUserBox.Text))
        {
            ShowError("Login failed", new AdminPanelException("Username is empty."));
            return;
        }
        if (string.IsNullOrEmpty(AdminPasswordBox.Password))
        {
            ShowError("Login failed", new AdminPanelException("Password is empty."));
            return;
        }

        SetBusy(true, "Connecting to license server...");
        try
        {
            var loginUsername = AdminUserBox.Text.Trim();
            var loginPassword = AdminPasswordBox.Password.Trim();

            var result = await Post<LoginResult>("api/admin/login", new
            {
                username = loginUsername,
                password = loginPassword
            });

            if (string.IsNullOrWhiteSpace(result.AccessToken))
                throw new AdminPanelException("Server returned HTTP 200 but did not return an accessToken.");

            _token = result.AccessToken;
            StatusText.Text = "Login accepted. Loading dashboard...";

            // Keep the login overlay visible until the first authenticated request succeeds.
            await LoadDashboardAsync();
            LoginOverlay.Visibility = Visibility.Collapsed;
            StatusText.Text = $"Signed in as {loginUsername} • API: {ApiUrl}";
            await RefreshServerHealthAsync(false);
            await RefreshControlStatusAsync(false);
            // Dashboard is the safe initial landing page. Other sections refresh on tab selection.
            Tabs.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            _token = null;
            ShowError("Administrator login failed", ex);
            StatusText.Text = "Login failed. See the diagnostic message for details.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task<T> Post<T>(string path, object body)
    {
        try
        {
            using var response = await _http.PostAsJsonAsync(path, body);
            return await Read<T>(response, path);
        }
        catch (AdminPanelException) { throw; }
        catch (Exception ex)
        {
            throw new AdminPanelException($"Could not send POST request to {new Uri(_http.BaseAddress!, path)}.", ex);
        }
    }

    private async Task<T> Get<T>(string path)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            AddAuthorization(request);
            using var response = await _http.SendAsync(request);
            return await Read<T>(response, path);
        }
        catch (AdminPanelException) { throw; }
        catch (Exception ex)
        {
            throw new AdminPanelException($"Could not send GET request to {new Uri(_http.BaseAddress!, path)}.", ex);
        }
    }

    private async Task<T> Send<T>(string path, object body)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path);
            AddAuthorization(request);
            request.Content = JsonContent.Create(body);
            using var response = await _http.SendAsync(request);
            return await Read<T>(response, path);
        }
        catch (AdminPanelException) { throw; }
        catch (Exception ex)
        {
            throw new AdminPanelException($"Could not send POST request to {new Uri(_http.BaseAddress!, path)}.", ex);
        }
    }

    private void AddAuthorization(HttpRequestMessage request)
    {
        if (!string.IsNullOrWhiteSpace(_token))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
    }

    private static async Task<T> Read<T>(HttpResponseMessage response, string path)
    {
        var text = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
        {
            var serverMessage = ExtractServerMessage(text);
            var detail = string.IsNullOrWhiteSpace(serverMessage) ? text : serverMessage;
            if (string.IsNullOrWhiteSpace(detail)) detail = "Server returned an empty error response.";
            var headers = response.Headers.ToString();
            if (!string.IsNullOrWhiteSpace(response.Content.Headers.ToString()))
                headers += response.Content.Headers.ToString();

            throw new AdminPanelException(
                $"HTTP {(int)response.StatusCode} {response.ReasonPhrase} from {path}.\n" +
                $"Request URI: {response.RequestMessage?.RequestUri}\n" +
                $"Server message: {detail}\n" +
                $"Response headers:\n{headers}");
        }

        if (string.IsNullOrWhiteSpace(text))
            throw new AdminPanelException($"HTTP {(int)response.StatusCode} from {path}, but the response body was empty.");

        try
        {
            return JsonSerializer.Deserialize<T>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                   ?? throw new AdminPanelException($"Server returned JSON from {path}, but it could not be converted to {typeof(T).Name}.");
        }
        catch (AdminPanelException) { throw; }
        catch (JsonException ex)
        {
            throw new AdminPanelException(
                $"Invalid JSON received from {path}.\n\nRaw response:\n{text}", ex);
        }
    }

    private static string ExtractServerMessage(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var name in new[] { "message", "error", "detail", "title" })
                    if (doc.RootElement.TryGetProperty(name, out var value))
                        return value.ToString();
            }
        }
        catch { }
        return text.Trim();
    }

    private async Task LoadDashboardAsync()
    {
        var x = await Get<Dashboard>("api/admin/overview");
        Cards.Children.Clear();
        AddCard("Users", x.TotalUsers);
        AddCard("Licenses", x.TotalLicenses);
        AddCard("Active devices", x.ActiveDevices);
        AddCard("Expired", x.ExpiredLicenses);
    }

    private void AddCard(string title, int value) => Cards.Children.Add(new Border
    {
        Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 22, 34)),
        CornerRadius = new CornerRadius(14), Padding = new Thickness(24), Margin = new Thickness(5), Width = 220,
        Child = new StackPanel
        {
            Children =
            {
                new TextBlock { Text = title, Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(126, 138, 176)) },
                new TextBlock { Text = value.ToString(), FontSize = 32, Margin = new Thickness(0, 8, 0, 0) }
            }
        }
    });

    private async void Tabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (e.Source != Tabs || _token is null) return;
        try
        {
            switch (Tabs.SelectedIndex)
            {
                case 1: await Users_Click(); break;
                case 2: await Devices_Click(); break;
                case 3: await Licenses_Click(); break;
                case 4: await Logs_Click(); break;
                case 5: await Backups_Click(); break;
            }
        }
        catch (Exception ex) { ShowError("Could not load selected section", ex); }
    }

    private async void UsersRefresh_Click(object sender, RoutedEventArgs e) => await RunAction("Refresh users", Users_Click);
    private async void DevicesRefresh_Click(object sender, RoutedEventArgs e) => await RunAction("Refresh devices", Devices_Click);
    private async void LicensesRefresh_Click(object sender, RoutedEventArgs e) => await RunAction("Refresh licenses", Licenses_Click);
    private async void BackupsRefresh_Click(object sender, RoutedEventArgs e) => await RunAction("Refresh backups", Backups_Click);

    private void CopyUserId_Click(object sender, RoutedEventArgs e)
    {
        if (UsersGrid.SelectedItem is AdminUser user) CopyText(user.Id, "User ID copied.");
        else ShowError("Copy user ID", new AdminPanelException("Select a user first."));
    }

    private async void ResetUserPassword_Click(object sender, RoutedEventArgs e)
    {
        if (UsersGrid.SelectedItem is not AdminUser user)
        {
            ShowError("Reset password", new AdminPanelException("Select a user first."));
            return;
        }

        if (MessageBox.Show($"Reset the password for {user.Email}?\n\nThe current password cannot be recovered because the server stores only a password hash. A new temporary password will be generated and shown once.",
            "Confirm password reset", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        await RunAction("Reset user password", async () =>
        {
            var result = await Send<PasswordResetResult>("api/admin/users/reset-password", new { userId = user.Id });
            Clipboard.SetText(result.TemporaryPassword);
            MessageBox.Show($"Password reset successfully.\n\nEmail:\n{user.Email}\n\nNew temporary password:\n{result.TemporaryPassword}\n\nIt has also been copied to the clipboard.\n\nStore it securely; the server will not reveal it again.",
                "User password reset", MessageBoxButton.OK, MessageBoxImage.Information);
            StatusText.Text = $"Password reset for {user.Email}.";
            await Users_Click();
        });
    }

    private void CopyDeviceHwid_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is AdminDevice device) CopyText(device.HardwareId, "Hardware fingerprint copied.");
        else ShowError("Copy HWID", new AdminPanelException("Select a device first."));
    }

    private void CopyDeviceId_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is AdminDevice device) CopyText(device.Id, "Device ID copied.");
        else ShowError("Copy device ID", new AdminPanelException("Select a device first."));
    }

    private void CopySelectedLog_Click(object sender, RoutedEventArgs e)
    {
        if (LogsGrid.SelectedItem is AuditLog log)
        {
            var value = $"[{log.CreatedUtc:O}] {log.Admin} | {log.Action} | {log.TargetType}/{log.TargetId} | {log.IpAddress}";
            CopyText(value, "Audit event copied.");
        }
        else ShowError("Copy audit event", new AdminPanelException("Select an audit event first."));
    }

    private static void CopyText(string? text, string status)
    {
        try { Clipboard.SetText(text ?? string.Empty); } catch { }
    }

    private async Task Users_Click()
    {
        var data = await Get<List<AdminUser>>("api/admin/users?search=" + Uri.EscapeDataString(UserSearch.Text));
        UsersGrid.ItemsSource = data;
        StatusText.Text = $"Users loaded: {data.Count}";
    }
    private async void Users_Click(object? s, RoutedEventArgs e) => await RunAction("Users", Users_Click);

    private async Task Devices_Click()
    {
        var data = await Get<List<AdminDevice>>("api/admin/devices?search=" + Uri.EscapeDataString(DeviceSearch.Text));
        DevicesGrid.ItemsSource = data;
        StatusText.Text = $"Devices loaded: {data.Count}";
    }
    private async void Devices_Click(object? s, RoutedEventArgs e) => await RunAction("Devices", Devices_Click);

    private async Task Licenses_Click()
    {
        var data = await Get<List<AdminLicense>>("api/admin/licenses?search=" + Uri.EscapeDataString(LicenseSearch.Text));
        LicensesGrid.ItemsSource = data;
        StatusText.Text = $"Licenses loaded: {data.Count}";
        if (data.Count == 0) StatusText.Text += " • No matching licenses.";
    }
    private async void Licenses_Click(object? s, RoutedEventArgs e) => await RunAction("Licenses", Licenses_Click);

    private async Task Logs_Click()
    {
        var data = await Get<List<AuditLog>>("api/admin/logs");
        var q = LogSearch.Text.Trim();
        if (!string.IsNullOrWhiteSpace(q))
        {
            data = data.Where(x =>
                x.Admin.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                x.Action.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                x.TargetType.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                x.TargetId.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                (x.IpAddress?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
                .ToList();
        }
        LogsGrid.ItemsSource = data;
        StatusText.Text = $"Logs loaded: {data.Count}";
    }
    private async void Logs_Click(object? s, RoutedEventArgs e) => await RunAction("Logs", Logs_Click);

    private async Task Backups_Click()
    {
        var data = await Get<List<BackupInfo>>("api/admin/backups");
        BackupsGrid.ItemsSource = data;
        StatusText.Text = $"Backups loaded: {data.Count}";
    }
    private async void Backup_Click(object? s, RoutedEventArgs e) => await RunAction("Backup", async () =>
    {
        await Send<object>("api/admin/backup", new { });
        await Backups_Click();
        StatusText.Text = "Backup created.";
    });

    private async void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (BackupsGrid.SelectedItem is not BackupInfo file) return;
        if (MessageBox.Show("Restore selected backup? Current data will first be backed up.", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Restore backup", async () =>
        {
            await Send<object>("api/admin/restore", new { fileName = file.FileName });
            await LoadDashboardAsync();
            await Backups_Click();
            StatusText.Text = "Backup restored.";
        });
    }

    private async void ToggleUser_Click(object sender, RoutedEventArgs e)
    {
        if (UsersGrid.SelectedItem is not AdminUser user) return;
        await RunAction("Change user status", async () =>
        {
            await Send<object>("api/admin/users/status", new { userId = user.Id, active = !user.Active, reason = "Admin panel" });
            await Users_Click();
        });
    }

    private async void ToggleDevice_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is not AdminDevice device) return;
        await RunAction("Change device status", async () =>
        {
            await Send<object>("api/admin/devices/block", new { deviceId = device.Id, blocked = !device.Blocked });
            await Devices_Click();
        });
    }

    private async void ReleaseDevice_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesGrid.SelectedItem is not AdminDevice device) { ShowError("Release HWID", new AdminPanelException("Select a device first.")); return; }
        if (MessageBox.Show($"Release HWID for {device.DisplayName}?\n\nAll licenses locked to this device will be unbound.", "Confirm HWID release", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Release HWID", async () =>
        {
            await Send<object>("api/admin/devices/release", new { deviceId = device.Id });
            await Devices_Click();
            await Licenses_Click();
            StatusText.Text = "HWID released successfully.";
        });
    }

    private async void CreateLicense_Click(object sender, RoutedEventArgs e)
    {
        await RunAction("Create license", async () =>
        {
            var x = await Send<CreateResult>("api/admin/licenses", new { plan = "PRO", maxDevices = 1, expiresUtc = (DateTime?)null });
            if (!string.IsNullOrWhiteSpace(x.Id)) _sessionLicenseKeys[x.Id] = x.LicenseKey;
            var result = MessageBox.Show($"License created successfully.\n\n{x.LicenseKey}\n\nThis full key is available in the current admin session.\n\nCopy it to the clipboard?", "Surge License", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (result == MessageBoxResult.Yes) { Clipboard.SetText(x.LicenseKey); StatusText.Text = "License copied to clipboard."; }
            await Licenses_Click();
        });
    }

    private void CopyLicense_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Copy license", new AdminPanelException("Select a license first.")); return; }
        if (!_sessionLicenseKeys.TryGetValue(license.Id, out var key)) { ShowError("Copy license", new AdminPanelException("The full license key is not available in this session. The server intentionally stores and returns only the masked key after creation.")); return; }
        try { Clipboard.SetText(key); StatusText.Text = "License copied to clipboard."; } catch (Exception ex) { ShowError("Copy license", ex); }
    }

    private async void RefreshServer_Click(object sender, RoutedEventArgs e) => await RunAction("Refresh server status", async () =>
    {
        await RefreshServerHealthAsync(true);
        await RefreshControlStatusAsync(true);
    });

    private void SetServerOnlineVisual(bool running)
    {
        _serverHealthy = running;
        ServerStatusText.Text = running ? "● Server running" : "● Server stopped";
        ServerStatusText.Foreground = running ? System.Windows.Media.Brushes.LightGreen : System.Windows.Media.Brushes.OrangeRed;
        ServerStatusBadge.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(running ? (byte)32 : (byte)60, running ? (byte)53 : (byte)35, running ? (byte)47 : (byte)40));
    }

    private async Task RefreshServerHealthAsync(bool showError)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "api/health");
            using var response = await _http.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode) throw new AdminPanelException($"Server health returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.\n\n{text}");
            SetServerOnlineVisual(true);
            ServerControlHint.Text = "License server is accepting requests.";
        }
        catch (Exception ex)
        {
            SetServerOnlineVisual(false);
            ServerControlHint.Text = "License server health check failed.";
            StartServerButton.IsEnabled = false; StopServerButton.IsEnabled = false; RestartServerButton.IsEnabled = false;
            if (showError) ShowError("Server health", ex);
        }
    }

    private async Task RefreshControlStatusAsync(bool showError)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "api/admin/control/status");
            AddAuthorization(request);
            using var response = await _http.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode) throw new AdminPanelException($"Server control returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.\n\n{text}");
            var status = JsonSerializer.Deserialize<ServerControlStatus>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var running = status?.Running == true;
            if (_serverHealthy) SetServerOnlineVisual(true);
            StartServerButton.IsEnabled = !running; StopServerButton.IsEnabled = running; RestartServerButton.IsEnabled = running;
            ServerControlHint.Text = status?.Detail ?? (running ? "License server is accepting requests." : "License server is stopped.");
        }
        catch (Exception ex)
        {
            // Control availability is independent of server health: an unreachable control
            // service must not repaint a demonstrably healthy server as down. Keyed off the
            // recorded health result, not off the text currently in the badge.
            if (_serverHealthy) SetServerOnlineVisual(true);
            StartServerButton.IsEnabled = false; StopServerButton.IsEnabled = false; RestartServerButton.IsEnabled = false;
            ServerControlHint.Text = "Server is online. Control actions are temporarily unavailable.";
            if (showError) ShowError("Server control", ex);
        }
    }

    private async void StartServer_Click(object sender, RoutedEventArgs e) => await ServerAction("start");
    private async void StopServer_Click(object sender, RoutedEventArgs e) => await ServerAction("stop");
    private async void RestartServer_Click(object sender, RoutedEventArgs e) => await ServerAction("restart");

    private async Task ServerAction(string action)
    {
        var label = action switch { "start" => "Start server", "stop" => "Stop server", _ => "Restart server" };
        if (action != "start" && MessageBox.Show($"Are you sure you want to {action} the license server?", label, MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            SetServerBusy(true);
            using var request = new HttpRequestMessage(HttpMethod.Post, $"api/admin/control/{action}");
            AddAuthorization(request);
            using var response = await _http.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode) throw new AdminPanelException($"{label} failed with HTTP {(int)response.StatusCode} {response.ReasonPhrase}.\n\n{text}");
            StatusText.Text = $"{label} command accepted.";
            await Task.Delay(1200);
            await RefreshServerHealthAsync(false);
            await RefreshControlStatusAsync(false);
        }
        catch (Exception ex) { ShowError(label, ex); }
        finally { SetServerBusy(false); }
    }

    private void SetServerBusy(bool busy)
    {
        StartServerButton.IsEnabled = !busy; StopServerButton.IsEnabled = !busy; RestartServerButton.IsEnabled = !busy;
    }

    private async void Revoke_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Revoke license", new AdminPanelException("Select a license first.")); return; }
        if (MessageBox.Show($"Revoke license {license.KeyMasked}?\n\nThis permanently blocks activation until an admin extends/unblocks it.", "Confirm revoke", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Revoke license", async () => { await Send<object>("api/admin/licenses/revoke", new { licenseId = license.Id }); await Licenses_Click(); StatusText.Text = "License revoked."; });
    }

    private async void RestoreLicense_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Restore license", new AdminPanelException("Select a license first.")); return; }
        if (MessageBox.Show($"Remove the revoked state from {license.KeyMasked}?", "Confirm restore", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await RunAction("Restore license", async () => { await Send<object>("api/admin/licenses/restore", new { licenseId = license.Id }); await Licenses_Click(); StatusText.Text = "License restored."; });
    }

    private async void Expire_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Expire license", new AdminPanelException("Select a license first.")); return; }
        if (MessageBox.Show($"Expire license {license.KeyMasked} now?", "Confirm expire", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Expire license", async () => { await Send<object>("api/admin/licenses/expire", new { licenseId = license.Id }); await Licenses_Click(); StatusText.Text = "License expired."; });
    }

    private async void Extend_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Extend license", new AdminPanelException("Select a license first.")); return; }
        if (!int.TryParse(ExtendDaysBox.Text.Trim(), out var days) || days < 1 || days > 3650) { ShowError("Extend license", new AdminPanelException("Days must be between 1 and 3650.")); return; }
        await RunAction("Extend license", async () => { await Send<object>("api/admin/licenses/extend", new { licenseId = license.Id, days }); await Licenses_Click(); StatusText.Text = $"License extended by {days} days."; });
    }

    private async void ReleaseLicenseDevice_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Release device", new AdminPanelException("Select a license first.")); return; }
        if (MessageBox.Show($"Release the device lock from {license.KeyMasked}?", "Confirm release", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Release license device", async () => { await Send<object>("api/admin/licenses/release-device", new { licenseId = license.Id }); await Licenses_Click(); StatusText.Text = "License device binding released."; });
    }

    private async void RotateLicense_Click(object sender, RoutedEventArgs e)
    {
        if (LicensesGrid.SelectedItem is not AdminLicense license) { ShowError("Rotate key", new AdminPanelException("Select a license first.")); return; }
        if (MessageBox.Show($"Rotate the key for {license.KeyMasked}?\n\nThe old key will stop working immediately. The license binding remains on the same account/device.", "Confirm key rotation", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        await RunAction("Rotate license key", async () =>
        {
            var x = await Send<CreateResult>("api/admin/licenses/rotate-key", new { licenseId = license.Id });
            _sessionLicenseKeys[x.Id] = x.LicenseKey;
            await Licenses_Click();
            MessageBox.Show($"New license key:\n\n{x.LicenseKey}\n\nCopy it now?", "License key rotated", MessageBoxButton.YesNo, MessageBoxImage.Information);
            Clipboard.SetText(x.LicenseKey);
            StatusText.Text = "New license key copied to clipboard.";
        });
    }

    private void Logout_Click(object sender, RoutedEventArgs e)
    {
        _token = null;
        AdminPasswordBox.Clear();
        LoginOverlay.Visibility = Visibility.Visible;
        StatusText.Text = "Signed out.";
    }

    private async Task RunAction(string action, Func<Task> actionFunc)
    {
        try { await actionFunc(); }
        catch (Exception ex) { ShowError(action, ex); }
    }

    private void SetBusy(bool busy, string? status = null)
    {
        AdminUserBox.IsEnabled = !busy;
        AdminPasswordBox.IsEnabled = !busy;
        SignInButton.IsEnabled = !busy;
        if (status is not null) StatusText.Text = status;
    }

    private static void ShowError(string title, Exception ex)
    {
        // The log always receives the full exception including the stack trace; the dialog never
        // does in a Release build. Printing internals into a MessageBox on the admin client leaks
        // server-side namespaces and call paths to whoever is standing at the machine.
        WriteDiagnosticLog(title, ex.ToString());

        var logPath = DiagnosticLogPath();
        var details = BuildErrorDetails(ex);
        MessageBox.Show(
            details + $"\n\nDiagnostic log:\n{logPath}",
            "Surge Admin - Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private static string DiagnosticLogPath()
    {
        try
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Surge", "AdminPanel-errors.log");
        }
        catch { return "Could not resolve diagnostic log path."; }
    }

    /// <summary>
    /// Message text only, never <c>ex.ToString()</c> and never <c>ex.StackTrace</c>. Inner-exception
    /// messages are retained because they carry the useful part ("The remote name could not be
    /// resolved") without exposing any code layout.
    /// </summary>
    private static string BuildErrorDetails(Exception ex)
    {
        var sb = new StringBuilder();
        sb.AppendLine(ex.Message);
        var current = ex.InnerException;
        while (current is not null)
        {
            sb.AppendLine();
            sb.AppendLine("Inner error:");
            sb.AppendLine(current.Message);
            current = current.InnerException;
        }

        if (ex is HttpRequestException http && http.InnerException is not null)
        {
            sb.AppendLine();
            sb.AppendLine("Network detail:");
            sb.AppendLine(http.InnerException.Message);
        }
        return sb.ToString().Trim();
    }

    private static string WriteDiagnosticLog(string title, string details)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Surge");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "AdminPanel-errors.log");
            File.AppendAllText(path, $"[{DateTime.UtcNow:O}] {title}\r\n{details}\r\n\r\n");
            return path;
        }
        catch { return "Could not write diagnostic log."; }
    }

    private sealed class AdminPanelException : Exception
    {
        public AdminPanelException(string message) : base(message) { }
        public AdminPanelException(string message, Exception inner) : base(message, inner) { }
    }

}

// These DTOs are intentionally top-level public records. WPF DataGrid binding relies on
// reflection/TypeDescriptor and can silently produce blank cells for nested private types
// even when ItemsSource contains the correct number of objects.
public sealed record LoginResult(string AccessToken);
public sealed record PasswordResetResult(bool Ok, string UserId, string TemporaryPassword);
public sealed record Dashboard(int TotalUsers, int TotalLicenses, int ActiveDevices, int ExpiredLicenses);
public sealed record CreateResult(string Id, string LicenseKey);
public sealed record ServerControlStatus(bool Running, string? Detail);
public sealed record AdminUser(string Id, string Email, DateTime CreatedUtc, bool Active, DateTime? DisabledUtc, string? DisabledReason, int Devices, int Licenses);
public sealed record AdminDevice(string Id, string DisplayName, string UserId, string HardwareId, DateTime FirstSeenUtc, DateTime LastSeenUtc, bool Active, bool Blocked, string? Email);
public sealed record AdminLicense(string Id, string KeyMasked, string Plan, string? OwnerUserId, string? Owner, List<string> Devices, DateTime? ExpiresUtc, string Status, bool Banned, bool Locked, string? HardwareFingerprintHash)
{
    public int DeviceCount => Devices?.Count ?? 0;
}
public sealed record AuditLog(string Id, string Admin, string Action, string TargetType, string TargetId, DateTime CreatedUtc, string? IpAddress, object? Metadata);
public sealed record BackupInfo(string FileName, DateTime CreatedUtc, long SizeBytes);
