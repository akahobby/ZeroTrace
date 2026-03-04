using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

public sealed class SteamApplicationProvider
{
    private static readonly Regex LibraryFolderRegex =
        new("\"(?<key>\\d+)\"\\s*\"(?<path>.+?)\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex AppManifestFieldRegex =
        new("\"(?<key>[^\"]+)\"\\s*\"(?<value>.+?)\"", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly ILogService _log;

    public SteamApplicationProvider(ILogService log)
    {
        _log = log;
    }

    public IReadOnlyList<InstalledApplication> GetSteamApplications()
    {
        var result = new List<InstalledApplication>();

        try
        {
            var steamInfo = FindSteamLibraries();
            if (steamInfo is null)
            {
                _log.Info("Steam installation not found. Skipping Steam game enumeration.");
                return result;
            }

            foreach (var libraryFolder in steamInfo.LibraryFolders)
            {
                var steamApps = Path.Combine(libraryFolder, "steamapps");
                if (!Directory.Exists(steamApps))
                {
                    continue;
                }

                foreach (var manifestPath in Directory.EnumerateFiles(steamApps, "appmanifest_*.acf"))
                {
                    try
                    {
                        var app = ParseAppManifest(manifestPath, libraryFolder, steamApps);
                        if (app is not null)
                        {
                            result.Add(app);
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Warn($"Failed to parse Steam manifest '{manifestPath}': {ex.Message}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to enumerate Steam applications: {ex.Message}");
        }

        _log.Info($"Detected {result.Count} Steam applications.");

        return result;
    }

    private SteamLibraryInfo? FindSteamLibraries()
    {
        string? steamPath = null;

        try
        {
            using var keyCu = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            steamPath = keyCu?.GetValue("SteamPath") as string;
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to read HKCU SteamPath: {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(steamPath))
        {
            try
            {
                using var keyLm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)
                    .OpenSubKey(@"Software\Valve\Steam");
                steamPath = keyLm?.GetValue("InstallPath") as string ?? keyLm?.GetValue("SteamPath") as string;
            }
            catch (Exception ex)
            {
                _log.Warn($"Failed to read HKLM SteamPath: {ex.Message}");
            }
        }

        if (string.IsNullOrWhiteSpace(steamPath) || !Directory.Exists(steamPath))
        {
            return null;
        }

        var steamApps = Path.Combine(steamPath, "steamapps");
        var libraryFile = Path.Combine(steamApps, "libraryfolders.vdf");
        var libraries = new List<string> { steamPath };

        if (File.Exists(libraryFile))
        {
            try
            {
                var text = File.ReadAllText(libraryFile);
                foreach (Match match in LibraryFolderRegex.Matches(text))
                {
                    var path = match.Groups["path"].Value;
                    if (string.IsNullOrWhiteSpace(path))
                    {
                        continue;
                    }

                    var normalized = path.Replace(@"\\", @"\");
                    if (Directory.Exists(normalized))
                    {
                        libraries.Add(normalized);
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Warn($"Failed to parse Steam libraryfolders.vdf: {ex.Message}");
            }
        }

        return new SteamLibraryInfo
        {
            SteamRoot = steamPath,
            SteamAppsPath = steamApps,
            LibraryFolders = libraries
        };
    }

    private InstalledApplication? ParseAppManifest(string manifestPath, string libraryFolder, string steamAppsFolder)
    {
        var text = File.ReadAllText(manifestPath);
        int? appId = null;
        string? name = null;
        string? installDir = null;
        long? lastUpdated = null;

        foreach (Match match in AppManifestFieldRegex.Matches(text))
        {
            var key = match.Groups["key"].Value.ToLowerInvariant();
            var value = match.Groups["value"].Value;

            switch (key)
            {
                case "appid":
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
                    {
                        appId = id;
                    }
                    break;
                case "name":
                    name = value;
                    break;
                case "installdir":
                    installDir = value;
                    break;
                case "lastupdated":
                    if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ts))
                    {
                        lastUpdated = ts;
                    }
                    break;
            }
        }

        if (appId is null || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(installDir))
        {
            return null;
        }

        DateTime? installDate = null;
        if (lastUpdated is > 0)
        {
            try
            {
                long seconds = lastUpdated.Value >= 1_000_000_000_000L ? lastUpdated.Value / 1000L : lastUpdated.Value;
                var d = DateTimeOffset.FromUnixTimeSeconds(seconds).LocalDateTime;
                installDate = IsPlausibleInstallDate(d) ? d : null;
            }
            catch
            {
                // ignore
            }
        }

        if (installDate is null && File.Exists(manifestPath))
        {
            try
            {
                var d = File.GetLastWriteTime(manifestPath);
                installDate = IsPlausibleInstallDate(d) ? d : null;
            }
            catch
            {
                // ignore
            }
        }

        var gameFolder = Path.Combine(libraryFolder, "steamapps", "common", installDir);

        return new InstalledApplication
        {
            DisplayName = name!,
            Publisher = "Steam",
            DisplayVersion = null,
            InstallLocation = gameFolder,
            UninstallString = null,
            QuietUninstallString = null,
            DisplayIconPath = null,
            RegistryKeyPath = null,
            IsSteam = true,
            SteamAppId = appId,
            SteamLibraryRoot = libraryFolder,
            SteamAppManifestPath = manifestPath,
            InstallDate = installDate
        };
    }

    private static bool IsPlausibleInstallDate(DateTime date)
    {
        var min = new DateTime(1990, 1, 1);
        var max = DateTime.Today.AddYears(1);
        return date >= min && date <= max;
    }
}

