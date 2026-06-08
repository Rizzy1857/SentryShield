using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Core
{
    public class PluginLoader
    {
        private readonly ILogger _logger;
        private readonly PluginContext _context;
        private readonly List<IDetectionPlugin> _plugins = new();

        public PluginLoader(ILogger logger, string globalDatabasePath)
        {
            _logger = logger;
            _context = new PluginContext(logger, globalDatabasePath);
        }

        public void LoadPlugins(string pluginsDirectory)
        {
            if (!Directory.Exists(pluginsDirectory))
            {
                _logger.LogWarning("Plugin directory not found: {Dir}", pluginsDirectory);
                return;
            }

            var dllFiles = Directory.GetFiles(pluginsDirectory, "*.dll");
            foreach (var file in dllFiles)
            {
                try
                {
                    // Basic check to not load random system DLLs or the abstractions DLL again
                    if (Path.GetFileName(file).Equals("SentryPlugin.Abstractions.dll", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Enforce Authenticode signature check unless explicitly disabled via environment for dev
                    bool requireSignature = Environment.GetEnvironmentVariable("SENTRYSHIELD_REQUIRE_SIGNED_PLUGINS") != "false";
                    
                    if (requireSignature && !IsSignatureValid(file))
                    {
                        _logger.LogCritical("SECURITY ALERT: Unsigned or tampered plugin blocked from loading: {File}", file);
                        continue;
                    }
                    else if (!requireSignature && !IsSignatureValid(file))
                    {
                        _logger.LogWarning("SECURITY OVERRIDE: Loading unsigned plugin {File} because SENTRYSHIELD_REQUIRE_SIGNED_PLUGINS=false", file);
                    }

                    var assembly = Assembly.LoadFrom(file);
                    var pluginTypes = assembly.GetTypes()
                        .Where(t => typeof(IDetectionPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract);

                    foreach (var type in pluginTypes)
                    {
                        if (Activator.CreateInstance(type) is IDetectionPlugin plugin)
                        {
                            plugin.Initialize(_context);
                            _plugins.Add(plugin);
                            _logger.LogInformation("Loaded plugin: {Name} v{Version}", plugin.Name, plugin.Version);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load plugin from {File}", file);
                }
            }
        }

        public IReadOnlyList<IDetectionPlugin> GetPlugins() => _plugins;

        // Hook for unit testing to bypass directory scanning
        public void AddPlugin(IDetectionPlugin plugin) => _plugins.Add(plugin);

        private bool IsSignatureValid(string filePath)
        {
            try
            {
#if NET8_0_OR_GREATER
                var cert = X509CertificateLoader.LoadCertificateFromFile(filePath);
#else
                var signer = X509Certificate.CreateFromSignedFile(filePath);
                var cert = new X509Certificate2(signer);
#endif
                // Verify against corporate CA or known thumbprint. 
                // For demonstration, we just check if it's signed and the chain builds.
                return cert.Verify();
            }
            catch
            {
                return false; // Unsigned or invalid
            }
        }
    }
}
