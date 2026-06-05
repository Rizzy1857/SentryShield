using System;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows.Data;

namespace SentryShield.UI.Converters
{
    public class SentenceNewlineConverter : IValueConverter
    {
        public static SentenceNewlineConverter Instance { get; } = new SentenceNewlineConverter();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string text && !string.IsNullOrWhiteSpace(text))
            {
                // Matches a period followed by space(s), but ONLY if preceded by at least 2 letters.
                // This ensures "1. " or "A. " doesn't trigger a newline, but "Do this. " does!
                return Regex.Replace(text, @"(?<=[a-zA-Z]{2,})\.\s+", ".\n\n").Trim();
            }
            return value ?? string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
