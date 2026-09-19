using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Models;

public sealed class FileUploadRequest
{
    public required Stream FileStream { get; init; }

    public required string OriginalFileName { get; init; }

    public string? DeclaredMimeType { get; init; }

    public long? DeclaredFileSize { get; init; }

    public FileUploadPolicy? Policy { get; init; }

    public CancellationToken CancellationToken { get; init; }
}
