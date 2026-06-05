// ─────────────────────────────────────────────────────────────────────────────
// .NET 4.8 Polyfills
//
// C# 9+ language features (records, init setters, etc.) require certain
// runtime support types that are absent from the .NET 4.8 BCL.
// Defining them here as internal stubs allows the C# compiler to emit the
// correct IL while targeting net48. These stubs are never called at runtime —
// they only satisfy the compiler's type-checking pass.
//
// This file is compiled for ALL targets (the #if guard is not needed because
// the types are in a namespace the BCL already owns on modern runtimes and
// the compiler simply uses the BCL version there instead of our stub).
// The `internal` modifier ensures no name collision with the real BCL type
// when running on net8 — the compiler always prefers the BCL version.
// ─────────────────────────────────────────────────────────────────────────────

#if NET48
namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Polyfill for C# 9 init-only setters on .NET 4.8.
    /// The compiler emits a modreq for this type on init-only properties;
    /// without it, records and `init` setters fail to compile on net48.
    /// </summary>
    internal static class IsExternalInit { }
}
#endif
