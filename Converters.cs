using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace SurgeApp
{
    public class StatusToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string status = value as string ?? "";
            return status switch
            {
                "APPLIED" => new SolidColorBrush(Color.FromRgb(0x16, 0x24, 0x1D)),
                "APPLIED*" => new SolidColorBrush(Color.FromRgb(0x22, 0x20, 0x35)),
                "UNKNOWN" => new SolidColorBrush(Color.FromRgb(0x24, 0x23, 0x2E)),
                "AUTO" => new SolidColorBrush(Color.FromRgb(0x1A, 0x20, 0x30)),
                "CHECKING" => new SolidColorBrush(Color.FromRgb(0x1C, 0x1D, 0x32)),
                "BACKUP" => new SolidColorBrush(Color.FromRgb(0x22, 0x23, 0x32)),
                "APPLYING" => new SolidColorBrush(Color.FromRgb(0x1E, 0x24, 0x35)),
                "VERIFYING" => new SolidColorBrush(Color.FromRgb(0x24, 0x22, 0x35)),
                "ROLLBACK" => new SolidColorBrush(Color.FromRgb(0x32, 0x26, 0x20)),
                "FAILED" => new SolidColorBrush(Color.FromRgb(0x2F, 0x1A, 0x21)),
                _ => new SolidColorBrush(Color.FromRgb(0x1B, 0x1C, 0x2A)),
            };
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class StatusToTextBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string status = value as string ?? "";
            return status switch
            {
                "APPLIED" => new SolidColorBrush(Color.FromRgb(0x3D, 0xDC, 0x84)),
                "APPLIED*" => new SolidColorBrush(Color.FromRgb(0xB7, 0xA8, 0xFF)),
                "UNKNOWN" => new SolidColorBrush(Color.FromRgb(0xB0, 0xA9, 0xBE)),
                "AUTO" => new SolidColorBrush(Color.FromRgb(0x5B, 0x8C, 0xFF)),
                "CHECKING" => new SolidColorBrush(Color.FromRgb(0x8A, 0x8E, 0xB7)),
                "BACKUP" => new SolidColorBrush(Color.FromRgb(0xA8, 0xAC, 0xC8)),
                "APPLYING" => new SolidColorBrush(Color.FromRgb(0x86, 0xB8, 0xFF)),
                "VERIFYING" => new SolidColorBrush(Color.FromRgb(0xB7, 0xA8, 0xFF)),
                "ROLLBACK" => new SolidColorBrush(Color.FromRgb(0xFF, 0xB2, 0x79)),
                "FAILED" => new SolidColorBrush(Color.FromRgb(0xFF, 0x7A, 0x91)),
                _ => new SolidColorBrush(Color.FromRgb(0x9A, 0x9D, 0xB0)),
            };
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class BoolToCardBorderConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool applied = value is bool b && b;
            return applied
                ? new SolidColorBrush(Color.FromRgb(0x4A, 0x52, 0xB8))
                : new SolidColorBrush(Color.FromRgb(0x23, 0x24, 0x37));
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class BoolToCardBgConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            bool applied = value is bool b && b;
            return applied
                ? new SolidColorBrush(Color.FromRgb(0x15, 0x17, 0x28))
                : new SolidColorBrush(Color.FromRgb(0x12, 0x13, 0x1F));
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }

    public class CountToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            int count = value is int i ? i : 0;
            return count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
    }
}
