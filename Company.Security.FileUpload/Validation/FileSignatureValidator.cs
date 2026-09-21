using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Extensions;
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
            switch (policy.FileKinds.UnknownFilePolicy)
            {
                case UnknownFilePolicy.Reject:
                case UnknownFilePolicy.Quarantine:
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.SignatureNotDetected,
                        "No known file signature was detected for this file."));
                    break;
                case UnknownFilePolicy.Allow:
                    break;
            }
        }
        else if (detectedType.IsKnownFormat)
        {
            // Resolve the effective allowlist. When the configured list is non-empty, the detected
            // signature's extension must be in it; when empty, every registered extension for the
            // detected category is allowed.
            var effectiveAllowed = FileExtensionRegistry.ResolveEffectiveAllowed(detectedType.Category, policy.FileKinds.AllowedExtensions);

            if (!FileExtensionRegistry.ContainsExtension(effectiveAllowed, detectedType.DetectedExtension))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.SignatureNotAllowed,
                    $"The detected signature corresponds to format '{detectedType.FormatName}' which is not allowed by policy."));
            }

            var declaredExtension = ExtensionResolver.Normalize(request.OriginalFileName);
            if (!string.IsNullOrEmpty(declaredExtension))
            {
                // The declared extension must also be within the (possibly per-call) allowlist.
                if (!FileExtensionRegistry.ContainsExtension(effectiveAllowed, declaredExtension))
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.ExtensionNotAllowed,
                        $"The extension '.{declaredExtension}' is not allowed by policy."));
                }

                if (!detectedType.ExtensionMatchesSignature)
                {
                    switch (policy.FileKinds.ExtensionMismatchPolicy)
                    {
                        case ExtensionMismatchPolicy.Reject:
                            errors.Add(new FileValidationError(
                                FileValidationErrorCode.ExtensionMismatch,
                                $"The file extension '.{declaredExtension}' does not match the detected signature ({detectedType.FormatName})."));
                            break;
                    }
                }
            }
        }

        return Task.FromResult(errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors));
    }
}