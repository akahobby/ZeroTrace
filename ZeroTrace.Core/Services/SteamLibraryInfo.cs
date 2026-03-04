using System.Collections.Generic;

namespace ZeroTrace.Core.Services;

internal sealed class SteamLibraryInfo
{
    public required string SteamRoot { get; init; }
    public required string SteamAppsPath { get; init; }
    public required IReadOnlyList<string> LibraryFolders { get; init; }
}

