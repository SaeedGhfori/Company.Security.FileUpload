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

    /// <summary>
    /// آپلود تصویر با بررسی امن
    /// </summary>
    /// <param name="file">فایل آپلود شده (Image only)</param>
    /// <returns>نتیجه اعتبارسنجی فایل</returns>
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
            Policy = new FileUploadPolicy()
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

    /// <summary>
    /// آپلود فایل با تغییر پسوند
    /// </summary>
    /// <param name="file">فایل آپلود شده</param>
    /// <param name="newExtension">پسوند جدید (اختیاری)</param>
    /// <returns>نتیجه اعتبارسنجی بعد از تغییر extensión</returns>
    [HttpPost("upload/rename-extension")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> UploadWithRenamedExtension(IFormFile file, [FromQuery] string? newExtension)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        var originalExtension = Path.GetExtension(file.FileName);
        var modifiedFileName = newExtension != null
            ? $"{Path.GetFileNameWithoutExtension(file.FileName)}{newExtension}"
            : file.FileName;

        var stream = file.OpenReadStream();
        var mimeType = file.ContentType;

        // اگر پسوند تغییر کرد، mime type را نیز rekonstruye می‌کنیم
        if (newExtension != null && !string.IsNullOrEmpty(originalExtension))
        {
            mimeType = MimeTypes.GetMimeType(newExtension);
        }

        var request = new FileUploadRequest
        {
            FileStream = stream,
            OriginalFileName = modifiedFileName,
            DeclaredMimeType = mimeType,
            DeclaredFileSize = file.Length,
            Policy = new FileUploadPolicy()
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

/// <summary>
    /// بررسی mime type و پسوند فایل
    /// </summary>
    /// <param name="file">فایل آپلود شده</param>
    /// <returns>اطلاعاتmtp و اعتبارسنجی</returns>
    [HttpPost("upload/check-mime")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult CheckMimeType(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        var originalExtension = Path.GetExtension(file.FileName);
        var declaredMime = file.ContentType;
        var hasMimeType = !string.IsNullOrEmpty(declaredMime);

        return Ok(new
        {
            FileName = file.FileName,
            OriginalExtension = originalExtension,
            DeclaredMimeType = declaredMime,
            HasDeclaredMimeType = hasMimeType,
            MimeTypeStatus = hasMimeType ? "mime type موجود است" : "mime type مشخص نشده"
        });
    }

    /// <summary>
    /// آپلود و بررسی تغییرات پسوند و mime (سی나리오 komple)
    /// </summary>
    /// <param name="file">فایل آپلود شده</param>
    /// <param name="newExtension">پسوند جدید برای تست</param>
    /// <returns>نتیجه کامل بررسی</returns>
    [HttpPost("upload/full-scenario")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> FullScenarioUpload(IFormFile file, [FromQuery] string newExtension)
    {
        if (file == null || file.Length == 0)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileEmpty, "فایل انتخاب نشده است") }
            });

        var originalFileName = file.FileName;
        var originalExtension = Path.GetExtension(originalFileName);
        var nameWithoutExt = Path.GetFileNameWithoutExtension(originalFileName);

        // ساخت نام جدید با extensión تغییر یافته
        var newFileName = $"{nameWithoutExt}{newExtension}";
        var newMimeType = MimeTypes.GetMimeType(newExtension);

        var stream = file.OpenReadStream();
        var originalMime = file.ContentType;

        var request = new FileUploadRequest
        {
            FileStream = stream,
            OriginalFileName = newFileName,
            DeclaredMimeType = newMimeType,
            DeclaredFileSize = file.Length,
            Policy = new FileUploadPolicy()
        };

        var result = await _pipeline.ProcessAsync(request);

        return Ok(new
        {
            OriginalFileName = originalFileName,
            OriginalExtension = originalExtension,
            NewFileName = newFileName,
            NewExtension = newExtension,
            OriginalMimeType = originalMime,
            NewMimeType = newMimeType,
            PipelineResult = result
        });
    }

    /// <summary>
    /// آپلود آرشیو (zip/rar) با بررسی امنیتی
    /// </summary>
    /// <param name="file">آرشیو آپلود شده</param>
    /// <returns>نتیجه اعتبارسنجی آرشیو</returns>
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
        if (extension != ".zip" && extension != ".rar")
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.ExtensionNotAllowed, "پسوند باید zip یا rar باشد") }
            });

        var stream = file.OpenReadStream();
        var request = new FileUploadRequest
        {
            FileStream = stream,
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = new FileUploadPolicy()
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }

    /// <summary>
    /// آپلود با حجم بیش از حد مجاز
    /// </summary>
    /// <param name="file">فایل huge</param>
    /// <returns>خطا اگر حجم بیش از حد باشد</returns>
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

        const long maxSize = 1 * 1024 * 1024; // 1MB

        if (file.Length > maxSize)
            return BadRequest(new FileValidationResult
            {
                IsValid = false,
                Errors = new[] { new FileValidationError(FileValidationErrorCode.FileTooLarge, $"حجم فایل ({file.Length} بایت) بیش از حد مجاز ({maxSize} بایت) است") }
            });

        var stream = file.OpenReadStream();
        var request = new FileUploadRequest
        {
            FileStream = stream,
            OriginalFileName = file.FileName,
            DeclaredMimeType = file.ContentType,
            DeclaredFileSize = file.Length,
            Policy = new FileUploadPolicy()
        };

        var result = await _pipeline.ProcessAsync(request);

        if (!result.IsValid)
            return BadRequest(result);

        return Ok(result);
    }
}