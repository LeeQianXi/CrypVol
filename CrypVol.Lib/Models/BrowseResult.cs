namespace CrypVol.Lib.Models;

public sealed record BrowseFileEntry
{
    public required string Path { get; init; }
    public long Size { get; init; }
    public int FragmentCount { get; init; }
    public List<int> Volumes { get; init; } = [];
}

public sealed record BrowseResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public List<BrowseFileEntry> Files { get; init; } = [];
    public int VolumeCount { get; init; }
}