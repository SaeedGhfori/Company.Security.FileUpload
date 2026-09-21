namespace Company.Security.FileUpload.Core.Models;

public sealed record Structures
{
    public bool RequireStructureValidation { get; init; } = true;

    public int StructureReadLimitBytes { get; init; } = 64 * 1024;

    public int MaxImageWidth { get; init; } = 0;

    public int MaxImageHeight { get; init; } = 0;

    public long MaxPixelCount { get; init; } = 0;

    public int ArchiveMaxEntries { get; init; } = 1000;

    public int ArchiveMaxDepth { get; init; } = 5;

    public long ArchiveMaxExtractedSize { get; init; } = 0;

    public bool AllowMacroEnabledOfficeDocuments { get; init; }
}