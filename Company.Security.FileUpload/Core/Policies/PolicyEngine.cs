using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Core.Policies;

public static class PolicyEngine
{
    public static FileValidationResult Evaluate(FileTypeInfo detectedType, long fileSizeBytes, FileUploadPolicy policy, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var errors = new List<FileValidationError>();
        var warnings = new List<string>();

        if (policy is null)
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.PolicyViolation, "No policy provided."));
            return FileValidationResult.Failure(errors);
        }

        if (!detectedType.IsKnownFormat)
        {
            switch (policy.UnknownFilePolicy)
            {
                case UnknownFilePolicy.Reject:
                case UnknownFilePolicy.Quarantine:
                    errors.Add(new FileValidationError(FileValidationErrorCode.FileTypeUnknown, "Unable to determine the file type."));
                    break;
            }
        }
        else
        {
            if ((policy.AllowedCategories & detectedType.Category) == 0)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.FileTypeNotAllowed,
                    $"File category '{detectedType.Category}' is not allowed by policy."));
            }

            if (policy.AllowedExtensions.Count > 0 &&
                !policy.AllowedExtensions.Contains(detectedType.DetectedExtension, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.ExtensionNotAllowed,
                    $"Detected extension '{detectedType.DetectedExtension}' is not allowed by policy."));
            }

            if (policy.AllowedMimeTypes.Count > 0 &&
                !policy.AllowedMimeTypes.Contains(detectedType.DetectedMimeType, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.MimeNotAllowed,
                    $"Detected MIME type '{detectedType.DetectedMimeType}' is not allowed by policy."));
            }

            if (policy.AllowListedFormats.Count > 0 &&
                !policy.AllowListedFormats.Contains(detectedType.FormatName, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.FileTypeNotAllowed,
                    $"Detected format '{detectedType.FormatName}' is not allowed by policy."));
            }

            if (!ExtensionResolver.IsEquivalentExtension(detectedType.DetectedExtension, detectedType.DeclaredExtension) &&
                !string.IsNullOrEmpty(detectedType.DeclaredExtension))
            {
                switch (policy.ExtensionMismatchPolicy)
                {
                    case ExtensionMismatchPolicy.Reject:
                        errors.Add(new FileValidationError(
                            FileValidationErrorCode.ExtensionMismatch,
                            $"File extension '{Dotted(detectedType.DeclaredExtension)}' does not match the actual type '{detectedType.DetectedExtension}'."));
                        break;
                    case ExtensionMismatchPolicy.Warn:
                        warnings.Add($"File extension '{Dotted(detectedType.DeclaredExtension)}' does not match the detected type '{detectedType.DetectedExtension}'.");
                        break;
                }
            }
        }

        if (fileSizeBytes > policy.MaxFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"File size exceeds the allowed limit of {policy.MaxFileSizeBytes} bytes."));
        }

        if (fileSizeBytes < policy.MinFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooSmall,
                $"File size is below the minimum of {policy.MinFileSizeBytes} bytes."));
        }

        var result = errors.Count == 0
            ? FileValidationResult.Success(detectedType, fileSizeBytes)
            : FileValidationResult.Failure(errors);

        foreach (var warning in warnings)
        {
            result = result.AddWarning(warning);
        }

        return result;
    }

    private static string Dotted(string extension)
        => extension.StartsWith('.') ? extension : "." + extension;
}
