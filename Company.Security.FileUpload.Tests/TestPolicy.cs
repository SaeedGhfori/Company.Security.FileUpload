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
        FileKinds = new FileKinds
        {
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
            }
        },
        FileSizes = new FileSizes { MaxFileSizeBytes = 10 * 1024 * 1024 },
        Structures = new Structures { RequireStructureValidation = true }
    };

    public static FileUploadPolicy AllowExtensions(params string[] extensions)
    {
        return Default with
        {
            FileKinds = Default.FileKinds with
            {
                AllowedExtensions = extensions.Select(e => e.StartsWith('.') ? e : "." + e).ToArray(),
                ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject
            },
            FileNames = new FileNames
            {
                AllowFileWithoutExtension = false,
                AllowMultipleExtensions = false
            }
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