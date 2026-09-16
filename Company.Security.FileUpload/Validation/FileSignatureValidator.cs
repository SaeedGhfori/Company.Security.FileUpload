using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Validation;

public sealed class FileSignatureValidator : IFileValidator
{
    public string Name => nameof(FileSignatureValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();

        if (!detectedType.HasValidSignature)
        {
            switch (policy.UnknownFilePolicy)
            {
                case UnknownFilePolicy.Reject:
                case UnknownFilePolicy.Quarantine:
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.SignatureNotDetected,
                        "No known file signature was detected for this file."));
                    break;
            }
        }
        else if (detectedType.IsKnownFormat)
        {
            if (policy.AllowedExtensions.Count > 0 &&
                !policy.AllowedExtensions.Contains(detectedType.DetectedExtension, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.SignatureNotAllowed,
                    $"The detected signature corresponds to format '{detectedType.FormatName}' which is not allowed by policy."));
            }

            var declaredExtension = ExtensionResolver.Normalize(request.OriginalFileName);
            if (!string.IsNullOrEmpty(declaredExtension) && !detectedType.ExtensionMatchesSignature)
            {
                switch (policy.ExtensionMismatchPolicy)
                {
                    case ExtensionMismatchPolicy.Reject:
                        errors.Add(new FileValidationError(
                            FileValidationErrorCode.ExtensionMismatch,
                            $"The file extension '.{declaredExtension}' does not match the detected signature ({detectedType.FormatName})."));
                        break;
                }
            }
        }

        return Task.FromResult(errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors));
    }
}