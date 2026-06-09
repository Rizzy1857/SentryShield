using System;
using System.Text.RegularExpressions;
class Program {
    static void Main() {
        string text = "1. Do not transfer this file to the OT network. 2. Request the supplier to transmit again.";
        string result = Regex.Replace(text, @"(?<=[a-zA-Z]{2,})\.\s+", ".\n\n").Trim();
        Console.WriteLine(result);
    }
}
