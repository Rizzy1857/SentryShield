using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;
#if !NET48
using System.Runtime.Loader;
#endif

namespace SentryShield.Core
{
    /// <summary>
    /// Loads IDetectionPlugin implementations from a directory of plugin DLLs.
    /// 
    /// KEY DESIGN: Each plugin DLL is loaded into its own PluginLoadContext, but
    /// SentryPlugin.Abstractions is always resolved from the host's already-loaded copy.
    /// This prevents the "two copies of IDetectionPlugin" problem that causes
    /// IsAssignableFrom() to silently return false and swallow every plugin.
    /// </summary>
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
                _logger.LogWarning("[PluginLoader] Plugin directory not found: {Dir}", pluginsDirectory);
                return;
            }

            var dllFiles = Directory.GetFiles(pluginsDirectory, "*.dll");
            _logger.LogInformation("[PluginLoader] Scanning {Count} DLL(s) in {Dir}", dllFiles.Length, pluginsDirectory);

            foreach (var file in dllFiles)
            {
                try
                {
                    var fileName = Path.GetFileName(file);

                    // Never re-load the shared contract assembly — it's already in the host context.
                    if (fileName.Equals("SentryPlugin.Abstractions.dll", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // HARD ENFORCEMENT: All plugins must be Authenticode signed
                    if (!IsSignatureValid(file))
                    {
                        _logger.LogCritical("[PluginLoader] SECURITY ALERT: Unsigned plugin blocked: {File}", file);
                        continue;
                    }

                    LoadPluginAssembly(file);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[PluginLoader] Failed to load plugin from {File}", file);
                }
            }

            _logger.LogInformation("[PluginLoader] Loaded {Count} plugin(s) total.", _plugins.Count);
        }

        private void LoadPluginAssembly(string pluginPath)
        {
#if NET48
            // .NET 4.8 does not have AssemblyLoadContext — use the simple LoadFrom path.
            // Signature validation + IsAssignableFrom works correctly here because all
            // assemblies share the same AppDomain and SentryPlugin.Abstractions is already loaded.
            Assembly pluginAssembly;
            try
            {
                pluginAssembly = Assembly.LoadFrom(pluginPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PluginLoader] Could not load assembly: {File}", pluginPath);
                return;
            }
#else
            // Each plugin gets its own isolated load context.
            // Crucially, the context is seeded to resolve SentryPlugin.Abstractions
            // from the host's already-loaded copy — not a second one bundled with the plugin DLL.
            var loadContext = new PluginLoadContext(pluginPath);

            Assembly pluginAssembly;
            try
            {
                pluginAssembly = loadContext.LoadFromAssemblyPath(pluginPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PluginLoader] Could not load assembly: {File}", pluginPath);
                return;
            }
#endif

            // Use the host-side IDetectionPlugin type for the assignability check.
            var contractType = typeof(IDetectionPlugin);

            Type[] types;
            try
            {
                types = pluginAssembly.GetTypes();
            }
            catch (ReflectionTypeLoadException rtle)
            {
                // Some types failed to load (e.g. missing optional deps). Log and continue with the ones that did load.
                _logger.LogWarning("[PluginLoader] Partial type load for {File}: {Errors}",
                    pluginPath, string.Join("; ", rtle.LoaderExceptions.Where(e => e != null).Select(e => e!.Message)));
                types = rtle.Types.Where(t => t != null).ToArray()!;
            }

            var pluginTypes = types.Where(t =>
                t != null &&
                !t.IsInterface &&
                !t.IsAbstract &&
                contractType.IsAssignableFrom(t));

            foreach (var type in pluginTypes)
            {
                try
                {
                    if (Activator.CreateInstance(type) is IDetectionPlugin plugin)
                    {
                        plugin.Initialize(_context);
                        _plugins.Add(plugin);
                        _logger.LogInformation("[PluginLoader] ✓ Loaded: {Name} v{Version}", plugin.Name, plugin.Version);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[PluginLoader] Could not instantiate plugin type {Type}", type.FullName);
                }
            }
        }

        public IReadOnlyList<IDetectionPlugin> GetPlugins() => _plugins;

        /// <summary>Hook for unit testing — bypasses directory scanning.</summary>
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
                return cert.Verify();
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Isolated AssemblyLoadContext per plugin.
    /// Falls back to the DEFAULT context (host) for the shared contract assembly,
    /// preventing the "duplicate IDetectionPlugin identity" type mismatch.
    /// </summary>
#if !NET48
    internal sealed class PluginLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;

        // Names of assemblies that MUST be resolved from the host, not the plugin bundle.
        private static readonly HashSet<string> HostOwnedAssemblies = new(StringComparer.OrdinalIgnoreCase)
        {
            "SentryPlugin.Abstractions",
            "Microsoft.Extensions.Logging.Abstractions",
            "Microsoft.Extensions.Logging",
        };

        public PluginLoadContext(string pluginPath) : base(isCollectible: true)
        {
            _resolver = new AssemblyDependencyResolver(pluginPath);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            // For host-owned assemblies, return null → the runtime will fall back
            // to the default context and resolve the host's already-loaded copy.
            if (assemblyName.Name != null && HostOwnedAssemblies.Contains(assemblyName.Name))
                return null;

            var resolvedPath = _resolver.ResolveAssemblyToPath(assemblyName);
            if (resolvedPath != null)
                return LoadFromAssemblyPath(resolvedPath);

            // For anything else (e.g. BCL types), fall back to default.
            return null;
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            var resolvedPath = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            return resolvedPath != null ? LoadUnmanagedDllFromPath(resolvedPath) : IntPtr.Zero;
        }
    }
#endif
}
