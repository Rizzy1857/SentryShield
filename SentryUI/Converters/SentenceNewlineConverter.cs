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
                // Prevent WPF word-wrap from breaking the line immediately after a list number (e.g. "1. ")
                // by replacing the space with a non-breaking space (\u00A0).
                text = Regex.Replace(text, @"(\b\d+\.)\s+", "$1\u00A0");

                // Force a new line after a full stop at the end of a sentence.
                // Matches a period preceded by at least 2 letters, followed by a space.
                return Regex.Replace(text, @"(?<=[a-zA-Z]{2,})\.\s+", ".\n").Trim();
            }
            return value ?? string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
