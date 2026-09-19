using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Pipeline;

namespace Company.Security.FileUpload.Tests;

internal static class TestPolicy
{
    public static FileUploadPolicy Default { get; } = new()
    {
        PolicyName = "TestDefault",
        AllowedCategories = FileTypeCategory.All,
        AllowedExtensions = new[]
        {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff",
            ".pdf", ".txt", ".csv", ".xml", ".json",
            ".zip", ".7z", ".gz", ".tar", ".rar",
            ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
            ".mp4", ".mov", ".avi", ".mkv", ".webm",
            ".mp3", ".wav", ".ogg", ".flac",
            ".exe"
        },
        MaxFileSizeBytes = 10 * 1024 * 1024,
        RequireStructureValidation = true
    };

    public static FileUploadPolicy AllowExtensions(params string[] extensions)
    {
        return Default with
        {
            AllowedExtensions = extensions.Select(e => e.StartsWith('.') ? e : "." + e).ToArray(),
            AllowFileWithoutExtension = false,
            AllowMultipleExtensions = false,
            ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject
        };
    }

    public static IFileUploadPipeline BuildPipeline(IMalwareScanner? scanner = null)
    {
        var builder = new FileUploadPipelineBuilder()
            .UseDefaultDetection()
            .WithDefaultValidators();

        if (scanner is not null)
            builder.UseMalwareScanner(scanner);

        return builder.Build();
    }
}