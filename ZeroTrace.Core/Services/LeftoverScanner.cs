using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

public sealed class LeftoverScanner
{
    private readonly ILogService _log;

    public LeftoverScanner(ILogService log)
    {
        _log = log;
    }

    public Task<IReadOnlyList<LeftoverItem>> ScanAsync(InstalledApplication app, CancellationToken cancellationToken)
    {
        return Task.Run<IReadOnlyList<LeftoverItem>>(() =>
        {
            var items = new List<LeftoverItem>();

            try
            {
                _log.Info($"Scanning for leftovers for '{app.DisplayName}'...");

                ScanInstallLocation(app, items);
                ScanAppData(app, items);
                ScanProgramData(app, items);
                ScanStartMenu(app, items);
                ScanRegistry(app, items);
                ScanSteamSpecific(app, items);

                _log.Info($"Leftover scan complete. Found {items.Count} candidate items.");
            }
            catch (Exception ex)
            {
                _log.Error($"Leftover scan failed: {ex.Message}");
            }

            return (IReadOnlyList<LeftoverItem>)items;
        }, cancellationToken);
    }

    private void ScanInstallLocation(InstalledApplication app, IList<LeftoverItem> items)
    {
        if (string.IsNullOrWhiteSpace(app.InstallLocation))
        {
            return;
        }

        var path = app.InstallLocation;
        if (Directory.Exists(path))
        {
            items.Add(new LeftoverItem
            {
                Path = path,
                Type = LeftoverItemType.Folder,
                SizeBytes = TryGetDirectorySize(path)
            });
        }
    }

    private void ScanAppData(InstalledApplication app, IList<LeftoverItem> items)
    {
        var appName = app.DisplayName;
        if (string.IsNullOrWhiteSpace(appName))
        {
            return;
        }

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        AddIfDirectoryExists(Path.Combine(roaming, appName), items);
        AddIfDirectoryExists(Path.Combine(local, appName), items);
    }

    private void ScanProgramData(InstalledApplication app, IList<LeftoverItem> items)
    {
        var appName = app.DisplayName;
        if (string.IsNullOrWhiteSpace(appName))
        {
            return;
        }

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        AddIfDirectoryExists(Path.Combine(programData, appName), items);

        if (!string.IsNullOrWhiteSpace(app.Publisher))
        {
            var publisherDir = Path.Combine(programData, app.Publisher);
            AddIfDirectoryExists(Path.Combine(publisherDir, appName), items);
        }
    }

    private void ScanStartMenu(InstalledApplication app, IList<LeftoverItem> items)
    {
        var appName = app.DisplayName;
        if (string.IsNullOrWhiteSpace(appName))
        {
            return;
        }

        var userStartMenu = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Start Menu", "Programs");

        var commonStartMenu = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows", "Start Menu", "Programs");

        ScanShortcutsInFolder(userStartMenu, appName, items);
        ScanShortcutsInFolder(commonStartMenu, appName, items);
    }

    private void ScanRegistry(InstalledApplication app, IList<LeftoverItem> items)
    {
        if (string.IsNullOrWhiteSpace(app.Publisher) || string.IsNullOrWhiteSpace(app.DisplayName))
        {
            return;
        }

        var publisher = app.Publisher;
        var name = app.DisplayName;

        AddRegistryIfExists(RegistryHive.CurrentUser, RegistryView.Default, $@"Software\{publisher}\{name}", items);
        AddRegistryIfExists(RegistryHive.LocalMachine, RegistryView.Registry64, $@"Software\{publisher}\{name}", items);
    }

    private void ScanSteamSpecific(InstalledApplication app, IList<LeftoverItem> items)
    {
        if (!app.IsSteam)
        {
            return;
        }

        var appName = app.DisplayName;
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var myGames = Path.Combine(documents, "My Games", appName);
        AddIfDirectoryExists(myGames, items);

        var localLow = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "AppData", "LocalLow", appName);
        AddIfDirectoryExists(localLow, items);

        // Any leftover directories in Steam libraries that still match the game name
        if (!string.IsNullOrWhiteSpace(app.SteamLibraryRoot))
        {
            try
            {
                var common = Path.Combine(app.SteamLibraryRoot, "steamapps", "common");
                if (Directory.Exists(common))
                {
                    foreach (var dir in Directory.EnumerateDirectories(common))
                    {
                        var dirName = Path.GetFileName(dir);
                        if (!string.IsNullOrEmpty(dirName) &&
                            dirName.Contains(appName, StringComparison.OrdinalIgnoreCase))
                        {
                            AddIfDirectoryExists(dir, items);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Warn($"Failed to scan Steam common directories for leftovers: {ex.Message}");
            }
        }
    }

    private void AddIfDirectoryExists(string path, IList<LeftoverItem> items)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            {
                items.Add(new LeftoverItem
                {
                    Path = path,
                    Type = LeftoverItemType.Folder,
                    SizeBytes = TryGetDirectorySize(path)
                });
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to add directory '{path}' as leftover: {ex.Message}");
        }
    }

    private void ScanShortcutsInFolder(string folder, string appName, IList<LeftoverItem> items)
    {
        try
        {
            if (!Directory.Exists(folder))
            {
                return;
            }

            foreach (var shortcut in Directory.EnumerateFiles(folder, "*.lnk", SearchOption.AllDirectories))
            {
                var fileName = Path.GetFileNameWithoutExtension(shortcut);
                if (!string.IsNullOrEmpty(fileName) &&
                    fileName.Contains(appName, StringComparison.OrdinalIgnoreCase))
                {
                    items.Add(new LeftoverItem
                    {
                        Path = shortcut,
                        Type = LeftoverItemType.Shortcut,
                        SizeBytes = TryGetFileSize(shortcut)
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to scan Start Menu shortcuts in '{folder}': {ex.Message}");
        }
    }

    private void AddRegistryIfExists(RegistryHive hive, RegistryView view, string subKey, IList<LeftoverItem> items)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subKey);
            if (key is not null)
            {
                var fullPath = $"{hive}\\{subKey}";
                items.Add(new LeftoverItem
                {
                    Path = fullPath,
                    Type = LeftoverItemType.RegistryKey,
                    SizeBytes = null
                });
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to check registry key '{hive}\\{subKey}' for leftovers: {ex.Message}");
        }
    }

    private static long? TryGetDirectorySize(string path)
    {
        try
        {
            long total = 0;
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                total += TryGetFileSize(file) ?? 0;
            }

            return total;
        }
        catch
        {
            return null;
        }
    }

    private static long? TryGetFileSize(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? info.Length : null;
        }
        catch
        {
            return null;
        }
    }
}

