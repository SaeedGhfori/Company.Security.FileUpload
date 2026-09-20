using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Models;

public sealed record FileUploadPolicy
{
    public string PolicyName { get; init; } = "Default";

    public FileTypeCategory AllowedCategories { get; init; } = FileTypeCategory.All;

    public IReadOnlyList<string> AllowedExtensions { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowedMimeTypes { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowListedFormats { get; init; } = Array.Empty<string>();

    public long MaxFileSizeBytes { get; init; } = 10 * 1024 * 1024;

    public long MinFileSizeBytes { get; init; }

    public long MaxMemoryFileSizeBytes { get; init; } = int.MaxValue;

    public int TempFileThresholdBytes { get; init; } = 10 * 1024 * 1024;

    public bool RequireStructureValidation { get; init; } = true;

    public bool RequireMalwareScan { get; init; }

    public UnknownFilePolicy UnknownFilePolicy { get; init; } = UnknownFilePolicy.Reject;

    public ExtensionMismatchPolicy ExtensionMismatchPolicy { get; init; } = ExtensionMismatchPolicy.Reject;

    public int MaxImageWidth { get; init; } = 0;

    public int MaxImageHeight { get; init; } = 0;

    public long MaxPixelCount { get; init; } = 0;

    public int ArchiveMaxEntries { get; init; } = 1000;

    public int ArchiveMaxDepth { get; init; } = 5;

    public long ArchiveMaxExtractedSize { get; init; } = 0;

    public bool VideoEnableDeepValidation { get; init; }

    public bool AllowMacroEnabledOfficeDocuments { get; init; }

    public bool AllowMultipleExtensions { get; init; }

    public bool AllowFileWithoutExtension { get; init; }

    public bool RejectIfMalwareScanUnavailable { get; init; } = true;

    public MalwareScanErrorPolicy MalwareScanErrorPolicy { get; init; } = MalwareScanErrorPolicy.Reject;

    public MalwareScanErrorPolicy MalwareScanUnknownPolicy { get; init; } = MalwareScanErrorPolicy.Reject;

    public int MaxFileNameLength { get; init; } = 255;

    public int SignatureReadLimitBytes { get; init; } = 8 * 1024;

    public int StructureReadLimitBytes { get; init; } = 256 * 1024;

    public int MaxConcurrentUploads { get; init; } = 10;
}
