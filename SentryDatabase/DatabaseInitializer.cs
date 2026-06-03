using System.Data.SQLite;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SentryShield.Database;

/// <summary>
/// Initializes the SQLite database on first startup.
/// Runs init.sql (embedded resource) against the configured DB path.
/// Idempotent — uses CREATE TABLE IF NOT EXISTS throughout.
/// </summary>
public class DatabaseInitializer
{
    private readonly ILogger<DatabaseInitializer> _logger;
    private readonly string _dbPath;

    public DatabaseInitializer(ILogger<DatabaseInitializer> logger, IOptions<Service.DatabaseOptions> options)
    {
        _logger = logger;
        _dbPath = options.Value.Path;
    }

    // Allow direct path injection (for tests)
    public DatabaseInitializer(ILogger<DatabaseInitializer> logger, string dbPath)
    {
        _logger = logger;
        _dbPath = dbPath;
    }

    public async Task InitializeAsync()
    {
        try
        {
            // Ensure directory exists
            var dir = Path.GetDirectoryName(_dbPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
                _logger.LogInformation("[DB] Created directory: {Dir}", dir);
            }

            // Load init.sql from embedded resources
            var sql = LoadInitSql();
            if (string.IsNullOrWhiteSpace(sql))
            {
                _logger.LogError("[DB] Could not load init.sql from embedded resources");
                return;
            }

            using var conn = new SQLiteConnection($"Data Source={_dbPath};Version=3;");
            await conn.OpenAsync();

            // Execute schema (idempotent — IF NOT EXISTS everywhere)
            using var cmd = new SQLiteCommand(sql, conn);
            await cmd.ExecuteNonQueryAsync();

            _logger.LogInformation("[DB] Database initialized: {Path}", _dbPath);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[DB] Failed to initialize database: {Path}", _dbPath);
            throw;
        }
    }

    private static string LoadInitSql()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = "SentryDatabase.Schema.init.sql";

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null) return string.Empty;

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
