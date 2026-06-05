using System.Globalization;
using System.Windows.Data;

namespace SentryShield.UI.Converters;

public class FileSizeConverter : IValueConverter
{
    public static FileSizeConverter Instance { get; } = new FileSizeConverter();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is long bytes)
        {
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:F1} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes} B";
        }
        return value?.ToString() ?? "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}