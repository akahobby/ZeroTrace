using System;

namespace ZeroTrace.Core.Models;

public sealed class InstalledApplication
{
    public Guid Id { get; } = Guid.NewGuid();

    public string DisplayName { get; init; } = string.Empty;
    public string? Publisher { get; init; }
    public string? DisplayVersion { get; init; }
    public string? InstallLocation { get; init; }
    public string? UninstallString { get; init; }
    public string? QuietUninstallString { get; init; }
    public string? DisplayIconPath { get; init; }
    public string? RegistryKeyPath { get; init; }

    public bool IsSteam { get; init; }
    public int? SteamAppId { get; init; }
    public string? SteamLibraryRoot { get; init; }
    public string? SteamAppManifestPath { get; init; }

    public long? EstimatedSizeBytes { get; init; }
    public DateTime? InstallDate { get; init; }

    public override string ToString() => DisplayName;
}

