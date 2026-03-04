using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

public sealed class ApplicationService
{
    private readonly RegistryApplicationProvider _registryProvider;
    private readonly SteamApplicationProvider _steamProvider;
    private readonly ILogService _log;

    public ApplicationService(RegistryApplicationProvider registryProvider, SteamApplicationProvider steamProvider, ILogService log)
    {
        _registryProvider = registryProvider;
        _steamProvider = steamProvider;
        _log = log;
    }

    public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync()
    {
        return Task.Run<IReadOnlyList<InstalledApplication>>(() =>
        {
            var registryApps = _registryProvider.GetInstalledApplications().ToList();
            var steamApps = _steamProvider.GetSteamApplications().ToList();

            // If a Steam game exists for a given display name, hide any matching
            // registry-based entries so Steam games are represented only once and
            // disappear from the list when their Steam manifest is removed.
            var steamNames = new HashSet<string>(
                steamApps
                    .Where(a => !string.IsNullOrWhiteSpace(a.DisplayName))
                    .Select(a => a.DisplayName.Trim()),
                StringComparer.OrdinalIgnoreCase);

            registryApps.RemoveAll(a =>
                !string.IsNullOrWhiteSpace(a.DisplayName) &&
                steamNames.Contains(a.DisplayName.Trim()));

            var all = registryApps
                .Concat(steamApps)
                .Where(a => !string.IsNullOrWhiteSpace(a.DisplayName))
                .ToList();

            // Deduplicate primarily by DisplayName, falling back to publisher when needed.
            var grouped = all
                .GroupBy(
                    a => a.DisplayName.Trim(),
                    StringComparer.OrdinalIgnoreCase)
                .Select(g => ChooseBest(g.ToList()))
                .OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            _log.Info($"Final application list contains {grouped.Count} entries after deduplication.");

            return (IReadOnlyList<InstalledApplication>)grouped;
        });
    }

    private InstalledApplication ChooseBest(IReadOnlyList<InstalledApplication> group)
    {
        if (group.Count == 1)
        {
            return group[0];
        }

        // Prefer Steam entries for Steam apps so that uninstall works correctly
        var steam = group.FirstOrDefault(a => a.IsSteam);
        if (steam is not null)
        {
            return steam;
        }

        // Otherwise prefer entries that have uninstall information
        var withUninstall = group.FirstOrDefault(a => !string.IsNullOrWhiteSpace(a.UninstallString) ||
                                                      !string.IsNullOrWhiteSpace(a.QuietUninstallString));
        return withUninstall ?? group[0];
    }
}

