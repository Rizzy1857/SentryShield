using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace SentryShield.Database;

/// <summary>
/// Data access layer for the IOC (Indicators of Compromise) table.
/// Stores known malware file hashes for fast lookup during USB scanning
/// and gateway validation.
/// </summary>
public class IOCDb : IDisposable
{
    private readonly string _dbPath;
    private readonly ILogger _logger;
    private SqliteConnection? _conn;

    public IOCDb(ILogger logger, string dbPath)
    {
        _logger = logger;
        _dbPath = dbPath;
    }

    private SqliteConnection Connection
    {
        get
        {
            if (_conn == null || _conn.State != System.Data.ConnectionState.Open)
            {
                _conn = new SqliteConnection($"Data Source={_dbPath}");
                _conn.Open();
            }
            return _conn;
        }
    }

    // -------------------------------------------------------------------------
    // Lookups
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns true if the given SHA-256 hash matches a known malware IOC.
    /// Indexed lookup — should be fast even with 100k+ entries.
    /// </summary>
    public virtual async Task<bool> IsKnownBadHashAsync(string sha256Hash)
    {
        if (string.IsNullOrWhiteSpace(sha256Hash)) return false;

        try
        {
            const string sql = "SELECT COUNT(*) FROM iocs WHERE file_hash = @hash LIMIT 1";
            using var cmd = new SqliteCommand(sql, Connection);
            cmd.Parameters.AddWithValue("@hash", sha256Hash.ToLower());

            var count = Convert.ToInt64(await cmd.ExecuteScalarAsync());
            return count > 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[IOCDb] Hash lookup failed: {Hash}", sha256Hash.Substring(0, Math.Min(8, sha256Hash.Length)));
            return false; // Fail open — don't block on DB error
        }
    }

    /// <summary>
    /// Retrieves full IOC record for a matching hash (for detailed alert info).
    /// </summary>
    public async Task<IOCRecord?> GetByHashAsync(string sha256Hash)
    {
        try
        {
            const string sql = @"
                SELECT file_hash, malware_name, malware_family, confidence, source, detection_date
                FROM iocs WHERE file_hash = @hash LIMIT 1";

            using var cmd = new SqliteCommand(sql, Connection);
            cmd.Parameters.AddWithValue("@hash", sha256Hash.ToLower());

            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new IOCRecord
                {
                    FileHash = reader.GetString(0),
                    MalwareName = reader.IsDBNull(1) ? "Unknown" : reader.GetString(1),
                    MalwareFamily = reader.IsDBNull(2) ? "Unknown" : reader.GetString(2),
                    Confidence = reader.IsDBNull(3) ? 100 : reader.GetInt32(3),
                    Source = reader.IsDBNull(4) ? "CURATED" : reader.GetString(4),
                    DetectionDate = reader.IsDBNull(5) ? "" : reader.GetString(5)
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[IOCDb] GetByHash failed");
        }

        return null;
    }

    public int GetTotalCount()
    {
        using var cmd = new SqliteCommand("SELECT COUNT(*) FROM iocs", Connection);
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    // -------------------------------------------------------------------------
    // Inserts
    // -------------------------------------------------------------------------

    /// <summary>
    /// Bulk insert IOC records. Skips duplicates (INSERT OR IGNORE).
    /// </summary>
    public async Task<int> BulkInsertAsync(IEnumerable<IOCRecord> records)
    {
        int count = 0;

        using var txn = Connection.BeginTransaction();
        try
        {
            const string sql = @"
                INSERT OR IGNORE INTO iocs
                    (file_hash, malware_name, malware_family, confidence, source, detection_date)
                VALUES
                    (@hash, @name, @family, @confidence, @source, @date)";

            using var cmd = new SqliteCommand(sql, Connection, txn);

            foreach (var record in records)
            {
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("@hash", record.FileHash.ToLower());
                cmd.Parameters.AddWithValue("@name", record.MalwareName);
                cmd.Parameters.AddWithValue("@family", record.MalwareFamily);
                cmd.Parameters.AddWithValue("@confidence", record.Confidence);
                cmd.Parameters.AddWithValue("@source", record.Source);
                cmd.Parameters.AddWithValue("@date", record.DetectionDate);

                await cmd.ExecuteNonQueryAsync();
                count++;
            }

            txn.Commit();
            _logger.LogInformation("[IOCDb] Inserted {Count} IOC records", count);
        }
        catch (Exception ex)
        {
            txn.Rollback();
            _logger.LogError(ex, "[IOCDb] Bulk insert failed");
        }

        return count;
    }

    public void Dispose()
    {
        _conn?.Close();
        _conn?.Dispose();
    }
}

public class IOCRecord
{
    public string FileHash { get; set; } = string.Empty;
    public string MalwareName { get; set; } = string.Empty;
    public string MalwareFamily { get; set; } = string.Empty;
    public int Confidence { get; set; } = 100;
    public string Source { get; set; } = "CURATED";
    public string DetectionDate { get; set; } = string.Empty;
}
