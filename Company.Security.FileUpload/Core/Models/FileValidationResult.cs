using Company.Security.FileUpload.Core.Enums;
using System.Collections.ObjectModel;

namespace Company.Security.FileUpload.Core.Models;

public sealed record FileValidationResult
{
    public bool IsValid { get; init; }

    public FileTypeInfo? DetectedFileType { get; init; }

    public IReadOnlyList<FileValidationError> Errors { get; init; }
        = Array.Empty<FileValidationError>();

    public IReadOnlyList<string> Warnings { get; init; }
        = Array.Empty<string>();

    public long FileSizeBytes { get; init; }

    public MalwareScanStatus? MalwareScanResult { get; init; }

    public DateTimeOffset ValidatedAt { get; init; } = DateTimeOffset.UtcNow;

    public TimeSpan ValidationDuration { get; init; }

    public IReadOnlyDictionary<string, object> Metadata { get; init; }
        = new ReadOnlyDictionary<string, object>(new Dictionary<string, object>());

    public static FileValidationResult Success(FileTypeInfo detectedType, long fileSizeBytes)
        => new()
        {
            IsValid = true,
            DetectedFileType = detectedType,
            FileSizeBytes = fileSizeBytes,
            ValidatedAt = DateTimeOffset.UtcNow
        };

    public static FileValidationResult Failure(params FileValidationError[] errors)
        => new()
        {
            IsValid = false,
            Errors = errors,
            ValidatedAt = DateTimeOffset.UtcNow
        };

    public static FileValidationResult Failure(IEnumerable<FileValidationError> errors)
        => new()
        {
            IsValid = false,
            Errors = errors.ToArray(),
            ValidatedAt = DateTimeOffset.UtcNow
        };

    public FileValidationResult AddError(FileValidationError error)
    {
        var errors = new List<FileValidationError>(Errors) { error };
        return this with { IsValid = false, Errors = errors };
    }

    public FileValidationResult AddWarning(string warning)
    {
        var warnings = new List<string>(Warnings) { warning };
        return this with { Warnings = warnings };
    }
}