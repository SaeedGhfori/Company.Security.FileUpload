using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Extensions;
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
            switch (policy.FileKinds.UnknownFilePolicy)
            {
                case UnknownFilePolicy.Reject:
                case UnknownFilePolicy.Quarantine:
                    errors.Add(new FileValidationError(FileValidationErrorCode.FileTypeUnknown, "Unable to determine the file type."));
                    break;
                case UnknownFilePolicy.Allow:
                    break;
            }
        }
        else
        {
            if ((policy.FileKinds.AllowedCategories & detectedType.Category) == 0)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.FileTypeNotAllowed,
                    $"File category '{detectedType.Category}' is not allowed by policy."));
            }

            var effectiveAllowed = FileExtensionRegistry.ResolveEffectiveAllowed(detectedType.Category, policy.FileKinds.AllowedExtensions);

            if (!FileExtensionRegistry.ContainsExtension(effectiveAllowed, detectedType.DetectedExtension))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.ExtensionNotAllowed,
                    $"Detected extension '{detectedType.DetectedExtension}' is not allowed by policy."));
            }

            if (!string.IsNullOrEmpty(detectedType.DeclaredExtension) &&
                !FileExtensionRegistry.ContainsExtension(effectiveAllowed, detectedType.DeclaredExtension))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.ExtensionNotAllowed,
                    $"Declared extension '{Dotted(detectedType.DeclaredExtension)}' is not allowed by policy."));
            }

            if (policy.FileKinds.AllowedMimeTypes.Count > 0 &&
                !policy.FileKinds.AllowedMimeTypes.Contains(detectedType.DetectedMimeType, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.MimeNotAllowed,
                    $"Detected MIME type '{detectedType.DetectedMimeType}' is not allowed by policy."));
            }

            if (policy.FileKinds.AllowListedFormats.Count > 0 &&
                !policy.FileKinds.AllowListedFormats.Contains(detectedType.FormatName, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.FileTypeNotAllowed,
                    $"Detected format '{detectedType.FormatName}' is not allowed by policy."));
            }

            if (!ExtensionResolver.IsEquivalentExtension(detectedType.DetectedExtension, detectedType.DeclaredExtension) &&
                !string.IsNullOrEmpty(detectedType.DeclaredExtension))
            {
                switch (policy.FileKinds.ExtensionMismatchPolicy)
                {
                    case ExtensionMismatchPolicy.Reject:
                        errors.Add(new FileValidationError(
                            FileValidationErrorCode.ExtensionMismatch,
                            $"File extension '{Dotted(detectedType.DeclaredExtension)}' does not match the actual type '{detectedType.DetectedExtension}'."));
                        break;
                    case ExtensionMismatchPolicy.Warn:
                        warnings.Add($"File extension '{Dotted(detectedType.DeclaredExtension)}' does not match the detected type '{detectedType.DetectedExtension}'.");
                        break;
                    case ExtensionMismatchPolicy.Allow:
                        break;
                }
            }
        }

        if (fileSizeBytes > policy.FileSizes.MaxFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"File size exceeds the allowed limit of {policy.FileSizes.MaxFileSizeBytes} bytes."));
        }

        if (fileSizeBytes < policy.FileSizes.MinFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooSmall,
                $"File size is below the minimum of {policy.FileSizes.MinFileSizeBytes} bytes."));
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
