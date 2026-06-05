using System;
using System.Collections.ObjectModel;
using System.Windows.Threading;
using Microsoft.Extensions.Logging;

namespace SentryShield.UI.Utils
{
    public class ObservableLogger : ILogger, IDisposable
    {
        private readonly ObservableCollection<string> _logs;
        private readonly Dispatcher _dispatcher;

        public ObservableLogger(ObservableCollection<string> logs, Dispatcher dispatcher)
        {
            _logs = logs;
            _dispatcher = dispatcher;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => this;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var levelLabel = logLevel switch
            {
                LogLevel.Information => "INFO ",
                LogLevel.Warning => "WARN ",
                LogLevel.Error => "ERROR",
                LogLevel.Critical => "FATAL",
                _ => "DEBUG"
            };

            var logLine = $"[{timestamp}] [{levelLabel}] {message}";

            _dispatcher.InvokeAsync(() =>
            {
                _logs.Add(logLine);
            });
        }

        public void Dispose() { }
    }
}
