# SentryPlugin.Template

This is the official boilerplate for building a new SentryShield detection plugin.

## How to use this template

1. **Copy this folder** and rename it to your plugin name:
   ```
   cp -r Templates/SentryPlugin.Template SentryPlugin.MyPlugin
   ```

2. **Rename the project and namespace:**
   - Rename `SentryPlugin.Template.csproj` → `SentryPlugin.MyPlugin.csproj`
   - In `TemplatePlugin.cs`, change `namespace SentryShield.Plugin.Template` → `namespace SentryShield.Plugin.MyPlugin`
   - Rename `TemplatePlugin.cs` → `MyPlugin.cs`

3. **Update the plugin metadata** in your new class:
   ```csharp
   public string Name => "My Plugin";      // used in logs and UI
   public string Version => "1.0.0";
   ```

4. **Implement `ExecuteAsync`** — this is where your detection logic lives. Return a `List<DetectionResult>`, empty if nothing was found.

5. **Add your project to the solution:**
   ```
   dotnet sln SentryShield.sln add SentryPlugin.MyPlugin/SentryPlugin.MyPlugin.csproj
   ```

6. **Add a `CopyPlugin` target** to `SentryService.csproj` and `SentryUI.csproj` so your compiled DLL lands in the `Plugins/` output folder automatically. Copy the existing pattern from the Firmware or USB plugin targets.

## Rules

- **Never reference `SentryCore`, `SentryService`, or `SentryDatabase`** from your plugin. This breaks isolation.
- **Only reference `SentryPlugin.Abstractions`** for contracts, and NuGet packages for functionality.
- The `PluginLoader` enforces that **all plugin DLLs must be Authenticode signed** before they are loaded in production. During development, sign your DLL with a local dev certificate.
- Always honor the `cancellationToken` parameter in `ExecuteAsync`. The engine kills plugins that exceed **5 minutes**.
- Never return `null` from `ExecuteAsync` — always return at least `new List<DetectionResult>()`.

## Interface contract quick reference

```csharp
// IDetectionPlugin
string Name { get; }
string Version { get; }
void Initialize(PluginContext context);
Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters);

// PluginContext (injected at Initialize time)
ILogger Logger
string GlobalDatabasePath

// DetectionResult (your findings)
string Title       // required
string Severity    // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
string Description
string Remediation
string Target
Dictionary<string, string> AdditionalData
```

## Test your plugin

Write your unit tests in `Tests/SentryCore.Tests/` following the patterns in `USBMonitorTests.cs`.
Run the full suite before raising a PR:
```
dotnet test Tests/SentryCore.Tests/ --framework net10.0-windows
```
