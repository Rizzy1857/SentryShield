using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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
    }
}
