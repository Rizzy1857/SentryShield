using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SentryUpdate
{
    public class UpdateServer : BackgroundService
    {
        private readonly ILogger<UpdateServer> _logger;
        private readonly IConfiguration _config;
        private HttpListener? _listener;
        private readonly string _dbPath;
        private readonly string _rulesDir;

        public UpdateServer(ILogger<UpdateServer> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
            
            string baseDir = AppContext.BaseDirectory;
            _dbPath = _config["Database:Path"] ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentryShield", "vulnerability.db");
            _rulesDir = _config["Yara:RulesPath"] ?? Path.Combine(baseDir, "rules");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                int port = _config.GetValue<int>("UpdateServer:Port", 8743);
                string lanIp = GetLocalIPv4();

                _listener = new HttpListener();
                
                // Explicitly bind to the LAN interface IPv4 address, never 0.0.0.0
                string prefix = $"http://{lanIp}:{port}/";
                _listener.Prefixes.Add(prefix);
                _listener.Start();

                _logger.LogInformation($"[SentryUpdate] Server started securely on {prefix} (LAN only)");
                _logger.LogWarning("[SentryUpdate] NOTE: Running without authentication (Known limitation documented for v3.0).");

                while (!stoppingToken.IsCancellationRequested)
                {
                    try
                    {
                        var context = await _listener.GetContextAsync().WaitAsync(stoppingToken);
                        
                        // Fire and forget handling to unblock the listener loop
                        _ = Task.Run(() => HandleRequestAsync(context), stoppingToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (HttpListenerException)
                    {
                        break; // Listener stopped or disposed
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[SentryUpdate] Critical server failure.");
            }
            finally
            {
                if (_listener != null && _listener.IsListening)
                {
                    _listener.Stop();
                    _listener.Close();
                }
            }
        }

        private async Task HandleRequestAsync(HttpListenerContext context)
        {
            try
            {
                var request = context.Request;
                var response = context.Response;

                string path = request.Url?.AbsolutePath?.ToLowerInvariant() ?? "";
                
                byte[] responseBytes = Array.Empty<byte>();
                string contentType = "application/json";

                if (request.HttpMethod != "GET")
                {
                    response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                }
                else if (path == "/api/version")
                {
                    responseBytes = GetVersionEndpoint();
                }
                else if (path == "/api/yara")
                {
                    responseBytes = GetYaraEndpoint();
                    if (responseBytes.Length == 0)
                    {
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                    }
                    else
                    {
                        contentType = "application/octet-stream";
                    }
                }
                else if (path == "/api/cvedelta")
                {
                    string? since = request.QueryString["since"];
                    responseBytes = GetCveDeltaEndpoint(since ?? string.Empty);
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                }

                if (response.StatusCode == 200 && responseBytes.Length > 0)
                {
                    // Compute Content-SHA256 so clients can verify integrity over the unreliable factory LAN
                    using (var sha256 = SHA256.Create())
                    {
                        byte[] hash = sha256.ComputeHash(responseBytes);
                        string hashHex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                        response.Headers.Add("Content-SHA256", hashHex);
                    }

                    response.ContentType = contentType;
                    response.ContentLength64 = responseBytes.Length;
                    await response.OutputStream.WriteAsync(responseBytes, 0, responseBytes.Length);
                }

                response.OutputStream.Close();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[SentryUpdate] Error handling HTTP request");
                try
                {
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    context.Response.OutputStream.Close();
                }
                catch { }
            }
        }

        private byte[] GetVersionEndpoint()
        {
            string yaraVersion = "unknown";
            string yaraPath = Path.Combine(_rulesDir, "malware.yar");
            if (File.Exists(yaraPath))
            {
                yaraVersion = File.GetLastWriteTimeUtc(yaraPath).ToString("o");
            }

            string dbVersion = "unknown";
            if (File.Exists(_dbPath))
            {
                try
                {
                    using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
                    {
                        conn.Open();
                        using (var cmd = conn.CreateCommand())
                        {
                            cmd.CommandText = "SELECT MAX(last_updated) FROM vulnerabilities;";
                            object? res = cmd.ExecuteScalar();
                            if (res != DBNull.Value && res != null)
                            {
                                dbVersion = res.ToString();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SentryUpdate] Failed to read database version");
                }
            }

            var info = new
            {
                yara_version = yaraVersion,
                db_version = dbVersion,
                timestamp = DateTime.UtcNow.ToString("o")
            };

            return JsonSerializer.SerializeToUtf8Bytes(info);
        }

        private byte[] GetYaraEndpoint()
        {
            string yaraPath = Path.Combine(_rulesDir, "malware.yar");
            if (File.Exists(yaraPath))
            {
                try
                {
                    return File.ReadAllBytes(yaraPath);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SentryUpdate] Failed to read YARA rules file");
                }
            }
            return Array.Empty<byte>();
        }

        private byte[] GetCveDeltaEndpoint(string sinceIso8601)
        {
            if (string.IsNullOrEmpty(sinceIso8601))
            {
                return JsonSerializer.SerializeToUtf8Bytes(new object[0]);
            }

            var records = new List<Dictionary<string, object?>>();

            if (File.Exists(_dbPath))
            {
                try
                {
                    using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
                    {
                        conn.Open();
                        using (var cmd = conn.CreateCommand())
                        {
                            cmd.CommandText = @"
                                SELECT id, product_name, affected_versions, cvss_score, severity, description, remediation, source, first_seen, last_updated 
                                FROM vulnerabilities 
                                WHERE last_updated > @since;";
                            cmd.Parameters.AddWithValue("@since", sinceIso8601);

                            using (var reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    var row = new Dictionary<string, object?>();
                                    for (int i = 0; i < reader.FieldCount; i++)
                                    {
                                        row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
                                    }
                                    records.Add(row);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[SentryUpdate] Failed to query CVE delta");
                }
            }

            return JsonSerializer.SerializeToUtf8Bytes(records);
        }

        private string GetLocalIPv4()
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up && 
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return ip.Address.ToString();
                        }
                    }
                }
            }
            // Fallback if no LAN interface is found
            return "127.0.0.1";
        }
    }
}
