using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Extensions;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Validation;

public sealed class FileExtensionValidator : IFileValidator
{
    public string Name => nameof(FileExtensionValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();
        var declaredExtension = ExtensionResolver.Normalize(request.OriginalFileName);

        var effectiveAllowed = FileExtensionRegistry.ResolveEffectiveAllowed(detectedType.Category, policy.FileKinds.AllowedExtensions);

        if (string.IsNullOrEmpty(declaredExtension))
        {
            if (!policy.FileNames.AllowFileWithoutExtension)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.ExtensionMissing,
                    "The file has no extension and the policy does not allow it."));
            }
        }
        else if (!FileExtensionRegistry.ContainsExtension(effectiveAllowed, declaredExtension))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.ExtensionNotAllowed,
                $"The extension '{(declaredExtension.Length > 0 ? "." + declaredExtension : string.Empty)}' is not allowed."));
        }

        if (!ExtensionResolver.IsValidExtension(declaredExtension))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.ExtensionUnknown,
                "The extension is not a valid extension."));
        }

        return Task.FromResult(errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors));
    }
}