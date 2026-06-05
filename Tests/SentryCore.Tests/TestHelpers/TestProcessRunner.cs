using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using SentryShield.Core.IPC;

namespace SentryShield.Tests;

/// <summary>
/// Fake ProcessRunner that returns configurable YARA JSON without spawning Python.
/// </summary>
internal class TestProcessRunner : ProcessRunner
{
    private string _yaraResult = "[]";

    public TestProcessRunner()
        : base(NullLogger.Instance, "python", ".", 30.ToString()) { } // 30.ToString() is a placeholder, base takes strings? Wait, base takes string, string, string.

    public void SetYaraResult(string json) => _yaraResult = json;

    public override Task<string> RunYaraScanAsync(string path) => Task.FromResult(_yaraResult);
    public override Task<string> RunYaraScanFileAsync(string path) => Task.FromResult(_yaraResult);
}
