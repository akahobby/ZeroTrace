using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Utilities;

namespace ZeroTrace.Core.Services;

public sealed class UninstallCoordinator
{
    private readonly ILogService _log;

    public UninstallCoordinator(ILogService log)
    {
        _log = log;
    }

    public async Task<bool> UninstallAsync(InstalledApplication app, CancellationToken cancellationToken)
    {
        if (app.IsSteam && app.SteamAppId is not null)
        {
            return await UninstallSteamAsync(app, cancellationToken).ConfigureAwait(false);
        }

        return await UninstallTraditionalAsync(app, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> UninstallSteamAsync(InstalledApplication app, CancellationToken token)
    {
        if (app.SteamAppId is null)
        {
            _log.Warn($"Cannot uninstall Steam application '{app.DisplayName}' because AppID is missing.");
            return false;
        }

        var uri = $"steam://uninstall/{app.SteamAppId.Value}";
        _log.Info($"Launching Steam uninstall for '{app.DisplayName}' ({uri}).");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = uri,
                UseShellExecute = true
            };
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            _log.Error($"Failed to launch Steam uninstall URI for '{app.DisplayName}': {ex.Message}");
            return false;
        }

        var manifestPath = app.SteamAppManifestPath;
        if (string.IsNullOrWhiteSpace(manifestPath) && app.SteamLibraryRoot is not null && app.SteamAppId is not null)
        {
            var steamApps = Path.Combine(app.SteamLibraryRoot, "steamapps");
            manifestPath = Path.Combine(steamApps, $"appmanifest_{app.SteamAppId.Value}.acf");
        }

        string? installFolder = app.InstallLocation;

        _log.Info("Waiting for Steam to complete uninstall...");

        while (!token.IsCancellationRequested)
        {
            var manifestGone = string.IsNullOrWhiteSpace(manifestPath) || !File.Exists(manifestPath);
            var gameFolderGone = string.IsNullOrWhiteSpace(installFolder) ||
                                 !Directory.Exists(installFolder) ||
                                 IsDirectoryEmptySafe(installFolder);

            if (manifestGone && gameFolderGone)
            {
                _log.Info($"Steam uninstall appears complete for '{app.DisplayName}'.");
                return true;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), token).ConfigureAwait(false);
        }

        _log.Warn($"Steam uninstall monitoring cancelled for '{app.DisplayName}'.");
        return false;
    }

    private static bool IsDirectoryEmptySafe(string path)
    {
        try
        {
            return Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).GetEnumerator().MoveNext();
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> UninstallTraditionalAsync(InstalledApplication app, CancellationToken token)
    {
        var commandLine = !string.IsNullOrWhiteSpace(app.QuietUninstallString)
            ? app.QuietUninstallString
            : app.UninstallString;

        if (string.IsNullOrWhiteSpace(commandLine))
        {
            _log.Warn($"Application '{app.DisplayName}' does not provide an uninstall command.");
            return false;
        }

        _log.Info($"Launching uninstall for '{app.DisplayName}'.");

        var parsed = CommandLineParser.TryParse(commandLine);
        if (parsed is null)
        {
            _log.Error($"Failed to parse uninstall command for '{app.DisplayName}': '{commandLine}'.");
            return false;
        }

        var fileName = parsed.FileName;
        var arguments = parsed.Arguments;

        if (fileName.Contains("msiexec", StringComparison.OrdinalIgnoreCase))
        {
            arguments = NormalizeMsiArguments(arguments);
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false
            };

            using var process = Process.Start(psi);
            if (process is null)
            {
                _log.Error($"Failed to start uninstall process for '{app.DisplayName}'.");
                return false;
            }

            _log.Info("Waiting for uninstall process to exit...");
            await process.WaitForExitAsync(token).ConfigureAwait(false);
            _log.Info($"Uninstall process exited with code {process.ExitCode} for '{app.DisplayName}'.");
        }
        catch (OperationCanceledException)
        {
            _log.Warn($"Uninstall cancelled for '{app.DisplayName}'.");
            return false;
        }
        catch (Exception ex)
        {
            _log.Error($"Uninstall failed for '{app.DisplayName}': {ex.Message}");
            return false;
        }

        // Additionally wait for the registry entry to disappear if we know where it is.
        if (!string.IsNullOrWhiteSpace(app.RegistryKeyPath))
        {
            _log.Info("Waiting for registry uninstall entry to be removed...");

            var timeout = TimeSpan.FromMinutes(5);
            var start = DateTime.UtcNow;

            while (!token.IsCancellationRequested && DateTime.UtcNow - start < timeout)
            {
                if (!RegistryKeyExists(app.RegistryKeyPath!))
                {
                    _log.Info("Registry uninstall entry removed.");
                    return true;
                }

                await Task.Delay(TimeSpan.FromSeconds(1), token).ConfigureAwait(false);
            }

            if (RegistryKeyExists(app.RegistryKeyPath!))
            {
                _log.Warn("Registry uninstall entry still present after timeout.");
            }
            else
            {
                _log.Info("Registry uninstall entry removed after waiting.");
                return true;
            }
        }

        return true;
    }

    private static string NormalizeMsiArguments(string arguments)
    {
        if (string.IsNullOrWhiteSpace(arguments))
        {
            return arguments;
        }

        // Replace /I with /X to uninstall
        return Regex.Replace(arguments, @"\b/I\b", "/X", RegexOptions.IgnoreCase);
    }

    private static bool RegistryKeyExists(string fullPath)
    {
        try
        {
            var firstBackslash = fullPath.IndexOf('\\');
            if (firstBackslash < 0)
            {
                return false;
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
                return false;
            }

            using var baseKey = RegistryKey.OpenBaseKey(hive.Value, RegistryView.Default);
            using var key = baseKey.OpenSubKey(subKey);
            return key is not null;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

