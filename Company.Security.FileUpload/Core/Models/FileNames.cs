namespace Company.Security.FileUpload.Core.Models;

public sealed record FileNames
{
    public int MaxFileNameLength { get; init; } = 255;

    public bool AllowFileWithoutExtension { get; init; }

    public bool AllowMultipleExtensions { get; init; }
}