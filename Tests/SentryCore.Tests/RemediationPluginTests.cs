using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using SentryShield.Plugin.Abstractions;
using SentryShield.Plugins.Remediation;

namespace SentryCore.Tests
{
    [TestFixture]
    public class RemediationPluginTests
    {
        [Test]
        public async Task ExecuteAsync_WithIsolateAction_ReturnsResult()
        {
            var loggerMock = new Mock<ILogger>();
            var context = new PluginContext(loggerMock.Object, "dummy.db");

            var plugin = new RemediationPlugin();
            plugin.Initialize(context);

            var parameters = new Dictionary<string, object>
            {
                { "Action", "IsolateNetwork" },
                { "IsTest", true }
            };

            // Note: Since WFP APIs require running on Windows with elevated privileges, 
            // the P/Invoke call will likely return false in the test environment.
            // We just want to ensure it parses the command and doesn't crash.
            var results = await plugin.ExecuteAsync(parameters);

            Assert.That(results, Is.Not.Null);
            Assert.That(results.Count, Is.EqualTo(1));
            Assert.That(results[0].Severity, Is.EqualTo("CRITICAL"));
            Assert.That(results[0].Title, Does.Contain("Network Quarantine"));
        }

        [Test]
        public async Task ExecuteAsync_WithoutIsolateAction_ReturnsEmpty()
        {
            var loggerMock = new Mock<ILogger>();
            var context = new PluginContext(loggerMock.Object, "dummy.db");

            var plugin = new RemediationPlugin();
            plugin.Initialize(context);

            var parameters = new Dictionary<string, object>
            {
                { "Action", "SomeOtherAction" }
            };

            var results = await plugin.ExecuteAsync(parameters);

            Assert.That(results, Is.Not.Null);
            Assert.That(results.Count, Is.EqualTo(0));
        }
    }
}
