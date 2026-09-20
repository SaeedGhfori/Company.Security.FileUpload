namespace Company.Security.FileUpload.Core.Models;

public sealed record FileUploadPolicy
{
    public string PolicyName { get; init; } = "Default";

    public FileKinds FileKinds { get; init; } = new();

    public FileSizes FileSizes { get; init; } = new();

    public FileNames FileNames { get; init; } = new();

    public Structures Structures { get; init; } = new();

    public MalwareScanning MalwareScanning { get; init; } = new();
}