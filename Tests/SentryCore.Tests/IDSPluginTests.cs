using NUnit.Framework;
using Moq;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;
using SentryShield.Plugin.IDS;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Generic;

namespace SentryShield.Tests
{
    [TestFixture]
    public class IDSPluginTests
    {
        private IDSPlugin _plugin;
        private Mock<ILogger> _mockLogger;
        private List<string> _loggedAlerts;

        [SetUp]
        public void Setup()
        {
            _plugin = new IDSPlugin();
            _mockLogger = new Mock<ILogger>();
            _loggedAlerts = new List<string>();

            // Capture logged warnings to inspect alerts
            _mockLogger.Setup(x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<System.Exception>(),
                (System.Func<It.IsAnyType, System.Exception, string>)It.IsAny<object>()))
                .Callback(new InvocationAction(invocation =>
                {
                    var state = invocation.Arguments[2];
                    _loggedAlerts.Add(state.ToString());
                }));

            var context = new PluginContext(_mockLogger.Object, "dummy.db");
            // Note: LoadBadIps will fail gracefully since dummy.db doesn't exist or isn't a valid SQLite DB.
            _plugin.Initialize(context);
        }

        [Test]
        public void ProcessRawPacket_UnusualPort_ShouldTriggerAlert()
        {
            // Arrange
            var rawCapture = CreateMockPacket("192.168.100.50", "8.8.8.8", 6666); // 6666 is unusual port

            // Act
            _plugin.ProcessRawPacket(rawCapture);

            // Assert
            Assert.That(_loggedAlerts, Has.Some.Contains("[IDS ALERT] Unusual Port Usage"));
        }

        [Test]
        public void ProcessRawPacket_AllowedPort_ShouldNotTriggerAlert()
        {
            // Arrange
            var rawCapture = CreateMockPacket("192.168.100.50", "10.0.0.5", 502); // 502 is Modbus (Allowed)

            // Act
            _plugin.ProcessRawPacket(rawCapture);

            // Assert
            Assert.That(_loggedAlerts, Has.None.Contains("[IDS ALERT] Unusual Port Usage"));
        }

        [Test]
        public void ProcessRawPacket_HighPacketRate_ShouldTriggerFloodAlert()
        {
            // Arrange
            var rawCapture = CreateMockPacket("192.168.1.10", "10.0.0.5", 80);

            // Act
            for (int i = 0; i < 1000; i++)
            {
                _plugin.ProcessRawPacket(rawCapture);
            }

            // Assert
            Assert.That(_loggedAlerts, Has.Some.Contains("[IDS ALERT] High Packet Rate"));
        }

        private RawCapture CreateMockPacket(string srcIp, string dstIp, ushort dstPort)
        {
            var ethernetPacket = new EthernetPacket(PhysicalAddress.Parse("001122334455"), PhysicalAddress.Parse("66778899AABB"), EthernetType.IPv4);
            var ipV4Packet = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
            var tcpPacket = new TcpPacket(12345, dstPort);
            
            ipV4Packet.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipV4Packet;
            ethernetPacket.UpdateCalculatedValues();

            var rawBytes = ethernetPacket.Bytes;
            return new RawCapture(LinkLayers.Ethernet, new PosixTimeval(0, 0), rawBytes);
        }
    }
}
