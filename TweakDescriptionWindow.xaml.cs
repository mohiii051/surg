using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace SurgeApp;

public partial class TweakDescriptionWindow : Window
{
    public TweakDescriptionWindow(string title, string category, string description, string technicalNotes)
    {
        InitializeComponent();
        TitleText.Text = title;
        CategoryText.Text = category.ToUpperInvariant();
        DescriptionText.Text = description;
        TechnicalText.Text = string.IsNullOrWhiteSpace(technicalNotes) ? "No additional technical notes." : technicalNotes;
    }
    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Root.Opacity = 0; Root.RenderTransform = new TranslateTransform(0, 8);
        var sb = new Storyboard();
        var fade = new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(190)));
        Storyboard.SetTarget(fade, Root); Storyboard.SetTargetProperty(fade, new PropertyPath("Opacity"));
        var slide = new DoubleAnimation(8, 0, new Duration(TimeSpan.FromMilliseconds(250))) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        Storyboard.SetTarget(slide, Root); Storyboard.SetTargetProperty(slide, new PropertyPath("RenderTransform.(TranslateTransform.Y)"));
        sb.Children.Add(fade); sb.Children.Add(slide); sb.Begin();
    }
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
