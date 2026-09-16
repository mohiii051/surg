using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace SurgeApp;

public partial class OperationLogWindow : Window
{
    private readonly ObservableCollection<Row> _rows = new();
    public OperationLogWindow()
    {
        InitializeComponent();
        LogGrid.ItemsSource = _rows;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var entries = SecureLogManager.ReadAllVerified<TweakLogEntry>();
            foreach (var item in entries.OrderByDescending(x => x.TimestampUtc))
                _rows.Add(new Row(item.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"), item.TweakTitle,
                    item.Action, item.Outcome, item.VerificationState, item.Message));
            EmptyText.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            IntegrityText.Text = "Integrity verified · " + _rows.Count + " recorded operation" + (_rows.Count == 1 ? "" : "s");
        }
        catch (Exception ex)
        {
            IntegrityText.Text = "Integrity check failed · " + ex.Message;
            ExportButton.IsEnabled = false;
        }

        Root.Opacity = 0;
        Root.RenderTransform = new TranslateTransform(0, 10);
        var sb = new Storyboard();
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(230))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        Storyboard.SetTarget(fade, Root); Storyboard.SetTargetProperty(fade, new PropertyPath("Opacity"));
        var slide = new DoubleAnimation(10, 0, new Duration(TimeSpan.FromMilliseconds(300))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        Storyboard.SetTarget(slide, Root); Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
        sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var destination = Path.Combine(Path.GetTempPath(), $"Surge-Operation-Report-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            TweakOperationLog.ExportReport(destination);
            Process.Start(new ProcessStartInfo { FileName = destination, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            SurgeApp.Services.ErrorReporter.Show("Surge — Operation Log",
                "Unable to export the protected operation log:", ex, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private record Row(string Time, string Title, string Action, string Result, string State, string Message);
}
