using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

public sealed class LeftoverDeletionService
{
    private readonly ILogService _log;
    private readonly IReadOnlyCollection<string> _dangerousRoots;

    public LeftoverDeletionService(ILogService log, IEnumerable<string>? steamRoots = null)
    {
        _log = log;

        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\"
        };

        steamRoots ??= DetectSteamRoots();

        if (steamRoots != null)
        {
            roots.AddRange(steamRoots);
        }

        _dangerousRoots = roots
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(NormalizePath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public Task DeleteAsync(InstalledApplication app, IEnumerable<LeftoverItem> items, CancellationToken cancellationToken)
    {
        return Task.Run(() =>
        {
            foreach (var item in items)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    _log.Warn("Deletion cancelled by user.");
                    break;
                }

                try
                {
                    if (!IsSafePath(app, item))
                    {
                        _log.Warn($"Skipping potentially unsafe deletion target: {item.Path}");
                        continue;
                    }

                    switch (item.Type)
                    {
                        case LeftoverItemType.Folder:
                            DeleteDirectory(item.Path);
                            break;
                        case LeftoverItemType.File:
                        case LeftoverItemType.Shortcut:
                            DeleteFile(item.Path);
                            break;
                        case LeftoverItemType.RegistryKey:
                            DeleteRegistryKey(item.Path);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    _log.Error($"Failed to delete leftover '{item.Path}': {ex.Message}");
                }
            }
        }, cancellationToken);
    }

    private bool IsSafePath(InstalledApplication app, LeftoverItem item)
    {
        var path = item.Path;
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (item.Type == LeftoverItemType.RegistryKey)
        {
            // For registry keys, only allow vendor/app-specific locations
            if (string.IsNullOrWhiteSpace(app.Publisher) || string.IsNullOrWhiteSpace(app.DisplayName))
            {
                return false;
            }

            var publisher = app.Publisher;
            var name = app.DisplayName;
            return path.Contains(publisher, StringComparison.OrdinalIgnoreCase) &&
                   path.Contains(name, StringComparison.OrdinalIgnoreCase);
        }

        var fullPath = NormalizePath(path);

        // Prevent deletion of core system and very generic roots.
        foreach (var dangerous in _dangerousRoots)
        {
            if (string.Equals(fullPath, dangerous, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // Do not allow deleting Program Files or Users root subtrees unless path clearly contains the app name.
        if (!string.IsNullOrWhiteSpace(app.DisplayName))
        {
            if (!fullPath.Contains(app.DisplayName, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(app.Publisher) ||
                 !fullPath.Contains(app.Publisher, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
        }

        return true;
    }

    private static IEnumerable<string>? DetectSteamRoots()
    {
        try
        {
            using var keyCu = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            var steamPath = keyCu?.GetValue("SteamPath") as string;

            if (string.IsNullOrWhiteSpace(steamPath))
            {
                using var keyLm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)
                    .OpenSubKey(@"Software\Valve\Steam");
                steamPath = keyLm?.GetValue("InstallPath") as string ?? keyLm?.GetValue("SteamPath") as string;
            }

            if (string.IsNullOrWhiteSpace(steamPath))
            {
                return null;
            }

            return new[] { steamPath };
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizePath(string path)
    {
        try
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch
        {
            return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }

    private void DeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        _log.Info($"Deleting directory: {path}");
        Directory.Delete(path, recursive: true);
    }

    private void DeleteFile(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }

        _log.Info($"Deleting file: {path}");
        File.Delete(path);
    }

    private void DeleteRegistryKey(string fullPath)
    {
        try
        {
            var firstBackslash = fullPath.IndexOf('\\');
            if (firstBackslash < 0)
            {
                return;
            }

            var hiveName = fullPath[..firstBackslash];
            var subKey = fullPath[(firstBackslash + 1)..];

            var hive = hiveName.ToUpperInvariant() switch
            {
                "HKLM" or "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
                "HKCU" or "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
                _ => (RegistryHive?)null
            };

            if (hive is null)
            {
                return;
            }

            using var baseKey = RegistryKey.OpenBaseKey(hive.Value, RegistryView.Default);
            _log.Info($"Deleting registry key: {fullPath}");
            baseKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        }
        catch (Exception ex)
        {
            _log.Error($"Failed to delete registry key '{fullPath}': {ex.Message}");
        }
    }
}

