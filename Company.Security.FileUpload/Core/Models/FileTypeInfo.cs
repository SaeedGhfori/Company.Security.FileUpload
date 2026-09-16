using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Models;

public sealed record FileTypeInfo
{
    public string DetectedExtension { get; init; } = string.Empty;

    public string DetectedMimeType { get; init; } = string.Empty;

    public FileTypeCategory Category { get; init; }

    public string FormatName { get; init; } = string.Empty;

    public bool HasValidSignature { get; init; }

    public string DeclaredExtension { get; init; } = string.Empty;

    public string DeclaredMimeType { get; init; } = string.Empty;

    public bool ExtensionMatchesSignature { get; init; }

    public bool IsKnownFormat { get; init; }

    public int MatchedSignatureOffset { get; init; }

    public byte[]? MatchedSignatureBytes { get; init; }
}
