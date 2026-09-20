using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Models;

public sealed record FileKinds
{
    public FileTypeCategory AllowedCategories { get; init; } = FileTypeCategory.All;

    public IReadOnlyList<string> AllowedExtensions { get; init; } = [];

    public IReadOnlyList<string> AllowedMimeTypes { get; init; } = [];

    public IReadOnlyList<string> AllowListedFormats { get; init; } = [];

    public UnknownFilePolicy UnknownFilePolicy { get; init; } = UnknownFilePolicy.Reject;

    public ExtensionMismatchPolicy ExtensionMismatchPolicy { get; init; } = ExtensionMismatchPolicy.Reject;
}