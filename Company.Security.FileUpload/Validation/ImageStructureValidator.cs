using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class ImageStructureValidator : IFileValidator
{
    private const int JpegMaxScanBytes = 65536;
    private static readonly HashSet<string> ImageFormats = new(StringComparer.OrdinalIgnoreCase)
    {
        "JPEG", "PNG", "GIF", "BMP", "WEBP", "TIFF"
    };

    public string Name => nameof(ImageStructureValidator);

    public async Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        if (!policy.RequireStructureValidation || detectedType.Category != FileTypeCategory.Image)
        {
            return FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream));
        }

        if (!ImageFormats.Contains(detectedType.FormatName))
        {
            return FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream));
        }

        var readLimit = Math.Max(policy.StructureReadLimitBytes, 512);
        var prefix = await StreamHelper.ReadPrefixAsync(stream, readLimit, cancellationToken);
        var errors = new List<FileValidationError>();

        var dimensions = ImageDimensionParser.Parse(detectedType.FormatName, prefix);
        if (!dimensions.HasValue)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.StructureImageInvalid,
                $"Could not parse a valid image header for format {detectedType.FormatName}. The image structure appears corrupted."));
            return FileValidationResult.Failure(errors);
        }

        if (policy.MaxImageWidth > 0 && dimensions.Width > policy.MaxImageWidth)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.StructureImageDimensionExceeded,
                $"The image width of {dimensions.Width} pixels exceeds the allowed maximum of {policy.MaxImageWidth}."));
        }

        if (policy.MaxImageHeight > 0 && dimensions.Height > policy.MaxImageHeight)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.StructureImageDimensionExceeded,
                $"The image height of {dimensions.Height} pixels exceeds the allowed maximum of {policy.MaxImageHeight}."));
        }

        if (policy.MaxPixelCount > 0 && dimensions.PixelCount > policy.MaxPixelCount)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.StructureImagePixelCountExceeded,
                $"The image pixel count of {dimensions.PixelCount} exceeds the allowed maximum of {policy.MaxPixelCount}."));
        }

        return errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors);
    }
}