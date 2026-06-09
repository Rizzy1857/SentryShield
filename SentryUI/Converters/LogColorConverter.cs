using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace SentryShield.UI.Converters
{
    public class LogColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string line)
            {
                if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || line.Contains("failed", StringComparison.OrdinalIgnoreCase))
                    return new SolidColorBrush(Color.FromRgb(0xFF, 0x4C, 0x4C)); // Red
                if (line.Contains("NVD", StringComparison.OrdinalIgnoreCase))
                    return new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x00)); // Yellow
                if (line.Contains("CERT-In", StringComparison.OrdinalIgnoreCase) || line.Contains("CERT-IN", StringComparison.OrdinalIgnoreCase))
                    return new SolidColorBrush(Color.FromRgb(0x00, 0xFF, 0x00)); // Green
                
                // Fallback for standard info messages
                return new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0)); // Gray
            }
            return new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0));
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}
