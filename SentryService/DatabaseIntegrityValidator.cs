using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace SentryShield.Service
{
    /// <summary>
    /// Validates SQLite database files against baseline SHA-256 hashes stored
    /// securely in the HKLM Registry to detect offline tampering.
    /// </summary>
    public class DatabaseIntegrityValidator
    {
        private readonly ILogger _logger;
        private readonly string _registryKeyPath = @"SOFTWARE\SentryShield";

        public DatabaseIntegrityValidator(ILogger logger)
        {
            _logger = logger;
        }

        public bool ValidateDatabases(string iocDbPath, string vulnDbPath)
        {
            bool iocValid = ValidateOrInitialize(iocDbPath, "IOCDbHash");
            bool vulnValid = ValidateOrInitialize(vulnDbPath, "VulnDbHash");

            return iocValid && vulnValid;
        }

        private bool ValidateOrInitialize(string dbPath, string registryValueName)
        {
            if (!File.Exists(dbPath)) return true; // Nothing to check yet

            string currentHash = ComputeSHA256(dbPath);

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(_registryKeyPath, writable: true)
                                ?? Registry.LocalMachine.CreateSubKey(_registryKeyPath);

                var storedHash = key.GetValue(registryValueName) as string;

                if (string.IsNullOrEmpty(storedHash))
                {
                    _logger.LogInformation("[DB Integrity] Initializing baseline hash for {Db} in Registry.", Path.GetFileName(dbPath));
                    key.SetValue(registryValueName, currentHash);
                    return true;
                }

                if (!string.Equals(currentHash, storedHash, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogCritical("[DB Integrity] SECURITY ALERT: Database hash mismatch for {Db}!", Path.GetFileName(dbPath));
                    _logger.LogCritical("Stored:  {Stored}", storedHash);
                    _logger.LogCritical("Current: {Current}", currentHash);
                    return false;
                }

                _logger.LogInformation("[DB Integrity] Validated checksum for {Db}.", Path.GetFileName(dbPath));
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                _logger.LogWarning("[DB Integrity] Access denied to HKLM Registry. Cannot verify database integrity.");
                return true; // Soft-fail in non-admin dev mode
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[DB Integrity] Failed to validate checksum for {Db}", Path.GetFileName(dbPath));
                return true; // Soft-fail on other OS errors
            }
        }

        public void UpdateHash(string dbPath, string registryValueName)
        {
            if (!File.Exists(dbPath)) return;
            string currentHash = ComputeSHA256(dbPath);
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(_registryKeyPath);
                key.SetValue(registryValueName, currentHash);
                _logger.LogInformation("[DB Integrity] Updated baseline hash for {Db} after sync.", Path.GetFileName(dbPath));
            }
            catch { /* Soft-fail */ }
        }

        private static string ComputeSHA256(string filePath)
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
        }
    }
}
