using Company.Security.FileUpload;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Core.Policies;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FileUploadApi.Controllers;

/// <summary>
/// مدیریت آپلود و اعتبارسنجی فایل‌ها
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class FilesController : ControllerBase
{
    private readonly FileUploadPipeline _pipeline;

    public FilesController(FileUploadPipeline pipeline)
    {
        _pipeline = pipeline;
    }

    private static readonly FileUploadPolicy ImagePolicy = new()
    {
        PolicyName = "ImageUpload",
        AllowedCategories = FileTypeCategory.Image,
        AllowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".tiff" },
        MaxFileSizeBytes = 10 * 1024 * 1024,
        MaxImageWidth = 4000,
        MaxImageHeight = 4000,
        MaxPixelCount = 16_000_000,
        ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject,
        UnknownFilePolicy = UnknownFilePolicy.Reject,
        RequireStructureValidation = true,
        AllowMultipleExtensions = false,
        AllowFileWithoutExtension = false
    };

    private static readonly FileUploadPolicy ArchivePolicy = new()
    {
        PolicyName = "ArchiveUpload",
        AllowedCategories = FileTypeCategory.Archive,
        AllowedExtensions = new[] { ".zip", ".rar", ".7z", ".gz", ".tar", ".tgz" },
        MaxFileSizeBytes = 100 * 1024 * 1024,
        ArchiveMaxEntries = 1000,
        ArchiveMaxDepth = 5,
        ArchiveMaxExtractedSize = 500 * 1024 * 1024,
        ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject,
        UnknownFilePolicy = UnknownFilePolicy.Reject,
        RequireStructureValidation = true,
        AllowMultipleExtensions = false,
        AllowFileWithoutExtension = false
    };

    private static readonly FileUploadPolicy DocumentPolicy = new()
    {
        PolicyName = "DocumentUpload",
        AllowedCategories = FileTypeCategory.Document | FileTypeCategory.Office,
        AllowedExtensions = new[] { ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt" },
        MaxFileSizeBytes = 50 * 1024 * 1024,
        ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject,
        UnknownFilePolicy = UnknownFilePolicy.Reject,
        RequireStructureValidation = true,
        AllowMultipleExtensions = false,
        AllowFileWithoutExtension = false
    };

    /// <summary>
    /// آپلود تصویر با بررسی امن
    /// </summary>
    [HttpPost("upload/image")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UploadImage(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        if (!file.ContentType!.StartsWith("image/"))
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.ExtensionNotAllowed, "فرمت فایل باید تصویر باشد") }
            });

        var request = new FileUploadRequest
        {
            FileStream = file.OpenReadStream(),
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = ImagePolicy
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

    /// <summary>
    /// آپلود فایل با پالیسی مستند
    /// </summary>
    [HttpPost("upload/document")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UploadDocument(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        var request = new FileUploadRequest
        {
            FileStream = file.OpenReadStream(),
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = DocumentPolicy
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

    /// <summary>
    /// آپلود آرشیو با بررسی امنیتی
    /// </summary>
    [HttpPost("upload/archive")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UploadArchive(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!ArchivePolicy.AllowedExtensions.Contains(extension))
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.ExtensionNotAllowed, "پسوند باید zip یا rar باشد") }
            });

        var request = new FileUploadRequest
        {
            FileStream = file.OpenReadStream(),
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = ArchivePolicy
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

    /// <summary>
    /// آپلود با حجم بیش از حد مجاز
    /// </summary>
    [HttpPost("upload/large")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UploadLargeFile(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        const long maxSize = 1 * 1024 * 1024;

        if (file.Length > maxSize)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileTooLarge, $"حجم فایل ({file.Length} بایت) بیش از حد مجاز ({maxSize} بایت) است") }
            });

        var request = new FileUploadRequest
        {
            FileStream = file.OpenReadStream(),
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = DocumentPolicy
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }
}
