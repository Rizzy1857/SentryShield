# Contributing to SentryShield

Thank you for contributing! This document explains how to build, test, and extend SentryShield. Read it once before opening a PR.

---

## Build Commands

```powershell
# Restore all packages
dotnet restore

# Build everything
dotnet build --configuration Release

# Or use the provided build script (handles .NET 4.8 / .NET 10 cross-compilation):
.\build_and_run.ps1
```

---

## Test Commands

```powershell
# Run all tests (must be on Windows)
dotnet test Tests/SentryCore.Tests/ --framework net10.0-windows --logger "console;verbosity=detailed"
```

> **Rule: All tests must pass before merging into `main` or `develop`.** The GitHub Actions CI pipeline runs the full suite automatically on every push and PR. Do not merge a PR with a failing build.

---

## Adding a New Plugin

1. **Copy the template folder:**
   ```
   cp -r Templates/SentryPlugin.Template SentryPlugin.YourPlugin
   ```

2. **Follow the steps in [`Templates/SentryPlugin.Template/README.md`](Templates/SentryPlugin.Template/README.md).**

3. **Add your project to the solution:**
   ```
   dotnet sln SentryShield.sln add SentryPlugin.YourPlugin/SentryPlugin.YourPlugin.csproj
   ```

4. **Add a `CopyPlugin` target** to `SentryService/SentryService.csproj` and `SentryUI/SentryUI.csproj` so your compiled DLL is automatically copied to the `Plugins/` output directory on build. Follow the pattern used for the Firmware or USB plugin.

5. **Sign your DLL** before testing on a production service instance. The `PluginLoader` enforces Authenticode signatures on all dynamically loaded plugins. For development, use a local self-signed certificate via `signtool.exe`.

---

## Plugin Rules (Non-Negotiable)

- **Never reference `SentryCore`, `SentryService`, or `SentryDatabase`** from a plugin project. This breaks the `AssemblyLoadContext` isolation and will throw at load time.
- **Only depend on `SentryPlugin.Abstractions`** for host contracts. All other functionality must come from NuGet packages or your plugin's own code.
- **Always honor the cancellation token** in `ExecuteAsync`. The engine hard-kills plugins that run longer than 5 minutes.
- **Never return `null`** from `ExecuteAsync`. Return `new List<DetectionResult>()` when there are no findings.

---

## Where the Plugin Loader Looks for DLLs

At runtime, `SentryCore.PluginLoader` scans:
```
<ServiceExecutableDirectory>\Plugins\*.dll
```

In a development build, the `Plugins/` directory is placed alongside the build output:
- `SentryService\bin\Debug\net10.0-windows\Plugins\`
- `SentryUI\bin\Debug\net10.0-windows\Plugins\`

The `CopyPlugin` MSBuild targets in the service and UI project files handle this automatically after each build.

---

## How `PluginContext` is Constructed

The `PluginLoader` creates a `PluginContext` for each loaded plugin at initialization time:

```csharp
var context = new PluginContext(
    logger: loggerFactory.CreateLogger(plugin.Name),  // scoped to the plugin's name
    globalDatabasePath: options.GlobalDatabasePath    // from appsettings.json
);
plugin.Initialize(context);
```

| Property | Type | Source |
|---|---|---|
| `Logger` | `ILogger` | Scoped to the plugin's `Name` property |
| `GlobalDatabasePath` | `string` | `appsettings.json` → `Paths:GlobalDatabasePath` |

---

## Interface Contracts (Frozen)

The three files in `SentryPlugin.Abstractions/` are frozen. Do not add, remove, or rename members without a team discussion and a versioning plan.

- [`IDetectionPlugin.cs`](SentryPlugin.Abstractions/IDetectionPlugin.cs) — the plugin contract
- [`PluginContext.cs`](SentryPlugin.Abstractions/PluginContext.cs) — services the host provides
- [`DetectionResult.cs`](SentryPlugin.Abstractions/DetectionResult.cs) — the unified finding model

---

## Git Workflow

- Branch off `develop` for all new work.
- Name branches descriptively: `feature/mesh-plugin`, `fix/toctou-race`, `chore/ci-update`.
- Squash-merge into `develop` after CI passes and a review is complete.
- `main` receives tagged releases only.
