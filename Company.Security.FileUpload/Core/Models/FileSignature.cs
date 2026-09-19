using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Models;

public sealed class FileSignature
{
    public required string FormatName { get; init; }

    public required FileTypeCategory Category { get; init; }

    public required string Extension { get; init; }

    public required string MimeType { get; init; }

    public byte[] Signature { get; init; } = Array.Empty<byte>();

    public int Offset { get; init; }

    public string? TextPattern { get; init; }

    public byte[]? TextPatternBytes { get; init; }

    public int TextPatternSearchEnd { get; init; }

    public bool IsRequired { get; init; } = true;

    public int Priority { get; init; }
}