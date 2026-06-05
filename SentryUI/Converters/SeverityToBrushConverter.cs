using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace SentryShield.UI.Converters;

public class SeverityToBrushConverter : IValueConverter
{
    public static SeverityToBrushConverter Instance { get; } = new SeverityToBrushConverter();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value?.ToString() switch
        {
            "CRITICAL" => new SolidColorBrush(Color.FromRgb(0xFF, 0x4C, 0x4C)),
            "HIGH"     => new SolidColorBrush(Color.FromRgb(0xF7, 0x86, 0x66)),
            "MEDIUM"   => new SolidColorBrush(Color.FromRgb(0xE3, 0xB3, 0x41)),
            "LOW"      => new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50)),
            _          => new SolidColorBrush(Color.FromRgb(0x8B, 0x94, 0x9E))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}