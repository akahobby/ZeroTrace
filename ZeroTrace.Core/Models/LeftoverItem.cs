using System;

namespace ZeroTrace.Core.Models;

public sealed class LeftoverItem
{
    public string Path { get; init; } = string.Empty;
    public LeftoverItemType Type { get; init; }
    public long? SizeBytes { get; init; }

    // UI can use this as default selection flag
    public bool IsSelected { get; set; } = true;

    public override string ToString() => $"{Type}: {Path}";
}

