namespace Company.Security.FileUpload.Core.Models;

public sealed record FileSizes
{
    public long MaxFileSizeBytes { get; init; } = 10 * 1024 * 1024;

    public long MinFileSizeBytes { get; init; }

    public int TempFileThresholdBytes { get; init; } = 10 * 1024 * 1024;

    public string? TempDirectory { get; init; }
}