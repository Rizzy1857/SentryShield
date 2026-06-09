using System;
using System.IO;
class Program {
    static void Main() {
        var baseDir = "/Users/rizzy/Documents/GitHub/SentryShield/Tests/SentryCore.Tests/bin/Debug/net10.0-windows/";
        Console.WriteLine(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..")));
        Console.WriteLine(Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..")));
    }
}
