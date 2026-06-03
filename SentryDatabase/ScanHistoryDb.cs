using System.Data.SQLite;
using Microsoft.Extensions.Logging;
using SentryShield.Core.Models;

namespace SentryShield.Database;

/// <summary>
/// Data access layer for scan history, findings, and gateway file records.
/// Used by the dashboard to display current state and history.
/// </summary>
public class ScanHistoryDb : IDisposable
{
    private readonly string _dbPath;
    private readonly ILogger _logger;
    private SQLiteConnection? _conn;

    public ScanHistoryDb(ILogger logger, string dbPath)
    {
        _logger = logger;
        _dbPath = dbPath;
    }

    private SQLiteConnection Connection
    {
        get
        {
            if (_conn == null || _conn.State != System.Data.ConnectionState.Open)
            {
                _conn = new SQLiteConnection($"Data Source={_dbPath};Version=3;");
                _conn.Open();
            }
            return _conn;
        }
    }

    // -------------------------------------------------------------------------
    // Findings
    // -------------------------------------------------------------------------

    public async Task SaveFindingsAsync(IEnumerable<Finding> findings)
    {
        using var txn = Connection.BeginTransaction();
        try
        {
            const string sql = @"
                INSERT OR REPLACE INTO findings
                    (id, machine_name, finding_type, severity, title, description,
                     affected_component, remediation, detection_timestamp, acknowledged, notes)
                VALUES
                    (@id, @machine, @type, @severity, @title, @desc,
                     @component, @remediation, @timestamp, @ack, @notes)";

            using var cmd = new SQLiteCommand(sql, Connection, txn);

            foreach (var f in findings)
            {
                cmd.Parameters.Clear();
                cmd.Parameters.AddWithValue("@id", f.Id);
                cmd.Parameters.AddWithValue("@machine", f.MachineName);
                cmd.Parameters.AddWithValue("@type", f.FindingType);
                cmd.Parameters.AddWithValue("@severity", f.Severity);
                cmd.Parameters.AddWithValue("@title", f.Title);
                cmd.Parameters.AddWithValue("@desc", f.Description);
                cmd.Parameters.AddWithValue("@component", f.AffectedComponent);
                cmd.Parameters.AddWithValue("@remediation", f.Remediation);
                cmd.Parameters.AddWithValue("@timestamp", f.DetectionTimestamp.ToString("o"));
                cmd.Parameters.AddWithValue("@ack", f.Acknowledged ? 1 : 0);
                cmd.Parameters.AddWithValue("@notes", f.Notes ?? (object)DBNull.Value);
                await cmd.ExecuteNonQueryAsync();
            }

            txn.Commit();
        }
        catch (Exception ex)
        {
            txn.Rollback();
            _logger.LogError(ex, "[ScanHistoryDb] SaveFindings failed");
        }
    }

    /// <summary>
    /// Returns all unacknowledged findings, newest first.
    /// Used by dashboard to populate the findings grid.
    /// </summary>
    public List<Finding> GetActiveFindings(int limit = 500)
    {
        var results = new List<Finding>();
        try
        {
            const string sql = @"
                SELECT id, machine_name, finding_type, severity, title, description,
                       affected_component, remediation, detection_timestamp, acknowledged, notes
                FROM findings
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        ELSE 4
                    END,
                    detection_timestamp DESC
                LIMIT @limit";

            using var cmd = new SQLiteCommand(sql, Connection);
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new Finding
                {
                    Id = reader.GetString(0),
                    MachineName = reader.GetString(1),
                    FindingType = reader.GetString(2),
                    Severity = reader.GetString(3),
                    Title = reader.GetString(4),
                    Description = reader.IsDBNull(5) ? "" : reader.GetString(5),
                    AffectedComponent = reader.IsDBNull(6) ? "" : reader.GetString(6),
                    Remediation = reader.IsDBNull(7) ? "" : reader.GetString(7),
                    DetectionTimestamp = DateTime.TryParse(reader.GetString(8), out var dt)
                        ? dt : DateTime.UtcNow,
                    Acknowledged = reader.GetInt32(9) == 1,
                    Notes = reader.IsDBNull(10) ? null : reader.GetString(10)
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ScanHistoryDb] GetActiveFindings failed");
        }
        return results;
    }

    /// <summary>
    /// Returns finding counts by severity — for dashboard summary tiles.
    /// </summary>
    public (int Critical, int High, int Medium, int Low) GetFindingCounts()
    {
        try
        {
            const string sql = @"
                SELECT
                    SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity='MEDIUM'   THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity='LOW'      THEN 1 ELSE 0 END)
                FROM findings
                WHERE acknowledged = 0";

            using var cmd = new SQLiteCommand(sql, Connection);
            using var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                return (
                    reader.IsDBNull(0) ? 0 : reader.GetInt32(0),
                    reader.IsDBNull(1) ? 0 : reader.GetInt32(1),
                    reader.IsDBNull(2) ? 0 : reader.GetInt32(2),
                    reader.IsDBNull(3) ? 0 : reader.GetInt32(3)
                );
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ScanHistoryDb] GetFindingCounts failed");
        }
        return (0, 0, 0, 0);
    }

    public async Task AcknowledgeFindingAsync(string findingId, string? notes = null)
    {
        const string sql = @"
            UPDATE findings
            SET acknowledged = 1, notes = @notes
            WHERE id = @id";

        using var cmd = new SQLiteCommand(sql, Connection);
        cmd.Parameters.AddWithValue("@id", findingId);
        cmd.Parameters.AddWithValue("@notes", notes ?? (object)DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    // -------------------------------------------------------------------------
    // Scan history
    // -------------------------------------------------------------------------

    public async Task RecordScanAsync(string scanType, int findingsCount,
        int criticalCount, int highCount, int mediumCount, int durationSeconds)
    {
        const string sql = @"
            INSERT INTO scan_results
                (scan_type, scan_timestamp, findings_count, critical_count,
                 high_count, medium_count, scan_duration_seconds)
            VALUES (@type, CURRENT_TIMESTAMP, @total, @critical, @high, @medium, @duration)";

        using var cmd = new SQLiteCommand(sql, Connection);
        cmd.Parameters.AddWithValue("@type", scanType);
        cmd.Parameters.AddWithValue("@total", findingsCount);
        cmd.Parameters.AddWithValue("@critical", criticalCount);
        cmd.Parameters.AddWithValue("@high", highCount);
        cmd.Parameters.AddWithValue("@medium", mediumCount);
        cmd.Parameters.AddWithValue("@duration", durationSeconds);
        await cmd.ExecuteNonQueryAsync();
    }

    public DateTime? GetLastScanTime(string scanType)
    {
        const string sql = @"
            SELECT MAX(scan_timestamp) FROM scan_results WHERE scan_type = @type";

        using var cmd = new SQLiteCommand(sql, Connection);
        cmd.Parameters.AddWithValue("@type", scanType);
        var result = cmd.ExecuteScalar()?.ToString();

        return DateTime.TryParse(result, out var dt) ? dt : null;
    }

    // -------------------------------------------------------------------------
    // Gateway files
    // -------------------------------------------------------------------------

    public async Task RecordGatewayFileAsync(GatewayFile file)
    {
        const string sql = @"
            INSERT INTO gateway_files
                (filename, supplier_name, file_hash, file_size, received_timestamp,
                 validation_status, block_reason, validation_timestamp, transferred_to_ot)
            VALUES
                (@filename, @supplier, @hash, @size, @received,
                 @status, @reason, @validated, @transferred)";

        using var cmd = new SQLiteCommand(sql, Connection);
        cmd.Parameters.AddWithValue("@filename", file.Filename);
        cmd.Parameters.AddWithValue("@supplier", file.SupplierName);
        cmd.Parameters.AddWithValue("@hash", file.FileHash);
        cmd.Parameters.AddWithValue("@size", file.FileSize);
        cmd.Parameters.AddWithValue("@received", file.ReceivedTimestamp.ToString("o"));
        cmd.Parameters.AddWithValue("@status", file.ValidationStatus);
        cmd.Parameters.AddWithValue("@reason", file.BlockReason ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@validated",
            file.ValidationTimestamp?.ToString("o") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("@transferred", file.TransferredToOT ? 1 : 0);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Returns recent gateway activity for the Gateway panel in the dashboard.
    /// </summary>
    public List<GatewayFile> GetRecentGatewayFiles(int limit = 100)
    {
        var results = new List<GatewayFile>();
        try
        {
            const string sql = @"
                SELECT id, filename, supplier_name, file_hash, file_size,
                       received_timestamp, validation_status, block_reason,
                       validation_timestamp, transferred_to_ot
                FROM gateway_files
                ORDER BY received_timestamp DESC
                LIMIT @limit";

            using var cmd = new SQLiteCommand(sql, Connection);
            cmd.Parameters.AddWithValue("@limit", limit);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new GatewayFile
                {
                    Id = reader.GetInt32(0),
                    Filename = reader.GetString(1),
                    SupplierName = reader.GetString(2),
                    FileHash = reader.IsDBNull(3) ? "" : reader.GetString(3),
                    FileSize = reader.IsDBNull(4) ? 0 : reader.GetInt64(4),
                    ReceivedTimestamp = DateTime.TryParse(reader.GetString(5), out var r)
                        ? r : DateTime.UtcNow,
                    ValidationStatus = reader.GetString(6),
                    BlockReason = reader.IsDBNull(7) ? null : reader.GetString(7),
                    ValidationTimestamp = reader.IsDBNull(8) ? null :
                        DateTime.TryParse(reader.GetString(8), out var v) ? v : null,
                    TransferredToOT = reader.GetInt32(9) == 1
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ScanHistoryDb] GetRecentGatewayFiles failed");
        }
        return results;
    }

    public void Dispose()
    {
        _conn?.Close();
        _conn?.Dispose();
    }
}
