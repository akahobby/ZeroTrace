using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

public sealed class RegistryApplicationProvider
{
    private readonly ILogService _log;

    public RegistryApplicationProvider(ILogService log)
    {
        _log = log;
    }

    public IReadOnlyList<InstalledApplication> GetInstalledApplications()
    {
        var apps = new List<InstalledApplication>();

        TryEnumerateHive(RegistryHive.LocalMachine, RegistryView.Registry64,
            @"Software\Microsoft\Windows\CurrentVersion\Uninstall", apps, "HKLM 64-bit");

        TryEnumerateHive(RegistryHive.LocalMachine, RegistryView.Registry32,
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", apps, "HKLM WOW6432Node");

        TryEnumerateHive(RegistryHive.CurrentUser, RegistryView.Default,
            @"Software\Microsoft\Windows\CurrentVersion\Uninstall", apps, "HKCU");

        _log.Info($"Detected {apps.Count} installed applications from registry.");

        return apps;
    }

    private void TryEnumerateHive(
        RegistryHive hive,
        RegistryView view,
        string subKeyPath,
        IList<InstalledApplication> target,
        string description)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var uninstallKey = baseKey.OpenSubKey(subKeyPath);
            if (uninstallKey is null)
            {
                _log.Warn($"Registry path not found: {hive} {view} {subKeyPath}");
                return;
            }

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                try
                {
                    using var appKey = uninstallKey.OpenSubKey(subKeyName);
                    if (appKey is null)
                    {
                        continue;
                    }

                    var displayName = appKey.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(displayName))
                    {
                        continue;
                    }

                    var publisher = appKey.GetValue("Publisher") as string;
                    var version = appKey.GetValue("DisplayVersion") as string;
                    var installLocation = appKey.GetValue("InstallLocation") as string;
                    var uninstallString = appKey.GetValue("UninstallString") as string;
                    var quietUninstallString = appKey.GetValue("QuietUninstallString") as string;
                    var displayIcon = appKey.GetValue("DisplayIcon") as string;

                    long? estimatedSizeBytes = null;
                    var estimatedSizeValue = appKey.GetValue("EstimatedSize");
                    if (estimatedSizeValue is int estimatedSizeInt)
                    {
                        // EstimatedSize is usually in KB
                        estimatedSizeBytes = (long)estimatedSizeInt * 1024L;
                    }
                    else if (estimatedSizeValue is string estimatedSizeString &&
                             int.TryParse(estimatedSizeString, NumberStyles.Integer, CultureInfo.InvariantCulture,
                                 out var estimatedSizeParsed))
                    {
                        estimatedSizeBytes = (long)estimatedSizeParsed * 1024L;
                    }

                    DateTime? installDate = null;
                    var installDateValue = appKey.GetValue("InstallDate");
                    if (installDateValue is string installDateString && !string.IsNullOrWhiteSpace(installDateString))
                    {
                        installDate = ParseInstallDate(installDateString);
                    }
                    else if (installDateValue is long unixValue && unixValue > 0)
                    {
                        try
                        {
                            long seconds = unixValue >= 1_000_000_000_000L ? unixValue / 1000L : unixValue;
                            var d = DateTimeOffset.FromUnixTimeSeconds(seconds).LocalDateTime;
                            installDate = IsPlausibleInstallDate(d) ? d : null;
                        }
                        catch
                        {
                            // ignore
                        }
                    }

                    var fullKeyPath = $"{hive}\\{subKeyPath}\\{subKeyName}";

                    target.Add(new InstalledApplication
                    {
                        DisplayName = displayName!,
                        Publisher = publisher,
                        DisplayVersion = version,
                        InstallLocation = string.IsNullOrWhiteSpace(installLocation) ? null : installLocation,
                        UninstallString = string.IsNullOrWhiteSpace(uninstallString) ? null : uninstallString,
                        QuietUninstallString = string.IsNullOrWhiteSpace(quietUninstallString) ? null : quietUninstallString,
                        DisplayIconPath = string.IsNullOrWhiteSpace(displayIcon) ? null : displayIcon,
                        RegistryKeyPath = fullKeyPath,
                        EstimatedSizeBytes = estimatedSizeBytes,
                        InstallDate = installDate
                    });
                }
                catch (Exception ex)
                {
                    _log.Warn($"Failed to read registry application entry under {description}, key '{subKeyName}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"Failed to enumerate registry applications for {description}: {ex.Message}");
        }
    }

    private static DateTime? ParseInstallDate(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        DateTime? parsed = null;

        // yyyyMMdd (most common in Uninstall key)
        if (DateTime.TryParseExact(value, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d1))
            parsed = d1;
        // yyyy-MM-dd
        else if (DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d2))
            parsed = d2;
        // Unix timestamp (string) - may be in seconds or milliseconds
        else if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix))
        {
            try
            {
                if (unix > 0)
                {
                    long seconds = unix >= 1_000_000_000_000L ? unix / 1000L : unix;
                    parsed = DateTimeOffset.FromUnixTimeSeconds(seconds).LocalDateTime;
                }
            }
            catch
            {
                // ignore
            }
        }
        // Loose parse for other formats
        else if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d3))
            parsed = d3;

        if (parsed is null)
            return null;

        return IsPlausibleInstallDate(parsed.Value) ? parsed : null;
    }

    private static bool IsPlausibleInstallDate(DateTime date)
    {
        var min = new DateTime(1990, 1, 1);
        var max = DateTime.Today.AddYears(1);
        return date >= min && date <= max;
    }
}

