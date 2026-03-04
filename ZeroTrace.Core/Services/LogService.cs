using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace ZeroTrace.Core.Services;

public sealed class LogService : ILogService, IDisposable
{
    private readonly object _syncRoot = new();
    private readonly StreamWriter _writer;
    private bool _disposed;

    public event EventHandler<string>? MessageLogged;

    public LogService()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var logRoot = Path.Combine(programData, "ZeroTrace", "Logs");
        Directory.CreateDirectory(logRoot);

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var logPath = Path.Combine(logRoot, $"ZeroTrace_{timestamp}.log");

        _writer = new StreamWriter(new FileStream(logPath, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
            NewLine = Environment.NewLine
        };

        Info($"ZeroTrace log started at {DateTime.Now:G}");
    }

    public void Info(string message) => Write("INFO", message);

    public void Warn(string message) => Write("WARN", message);

    public void Error(string message) => Write("ERROR", message);

    private void Write(string level, string message)
    {
        if (_disposed)
        {
            return;
        }

        var line = $"{DateTime.Now:O} [{level}] {message}";

        lock (_syncRoot)
        {
            _writer.WriteLine(line);
        }

        MessageLogged?.Invoke(this, line);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        lock (_syncRoot)
        {
            _writer.Dispose();
            _disposed = true;
        }
    }
}

