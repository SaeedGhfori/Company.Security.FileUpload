using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Validation;

public sealed class FileNameValidator : IFileValidator
{
    public string Name => nameof(FileNameValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();
        var warnings = new List<string>();
        var fileName = request.OriginalFileName ?? string.Empty;
        var decodedFileName = ExtensionResolver.DecodeUrlEncoding(fileName);

        if (string.IsNullOrWhiteSpace(fileName))
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.FileNameEmpty, "The file name is empty."));
            return Task.FromResult(FileValidationResult.Failure(errors));
        }

        var (nameOnly, _) = SplitNameAndExtension(fileName);

        if (nameOnly.Length > policy.MaxFileNameLength)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileNameTooLong,
                $"The file name exceeds the maximum length of {policy.MaxFileNameLength} characters."));
        }

        if (ExtensionResolver.LooksLikePathTraversal(fileName)
            || ExtensionResolver.LooksLikePathTraversal(decodedFileName))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileNamePathTraversalDetected,
                "The file name contains path traversal patterns."));
        }

        if (ExtensionResolver.IsReservedFileName(nameOnly))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileNameReserved,
                "The file name uses a reserved system name."));
        }

        if (fileName.Contains('\0') || decodedFileName.Contains('\0'))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileNameContainsNullBytes,
                "The file name contains a null character."));
        }

        if (ContainsInvalidChars(nameOnly))
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileNameContainsInvalidCharacters,
                "The file name contains invalid characters."));
        }

        var hasExtension = ExtensionResolver.Normalize(fileName).Length > 0
            || ExtensionResolver.Normalize(decodedFileName).Length > 0;
        if (!hasExtension && !policy.AllowFileWithoutExtension)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.ExtensionMissing,
                "The file has no extension and the policy does not allow files without an extension."));
        }

        if (ExtensionResolver.HasMultipleExtensions(fileName) && !policy.AllowMultipleExtensions)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.ExtensionMultipleDetected,
                "The file has multiple extensions which is not allowed by policy."));
        }

        if (ExtensionResolver.HasMultipleExtensions(decodedFileName) && !policy.AllowMultipleExtensions)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.ExtensionMultipleDetected,
                "The file has multiple extensions which is not allowed by policy."));
        }

        if (errors.Count == 0)
        {
            return Task.FromResult(FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream)));
        }

        var result = FileValidationResult.Failure(errors);
        foreach (var warning in warnings)
            result = result.AddWarning(warning);
        return Task.FromResult(result);
    }

    private static (string Name, string Extension) SplitNameAndExtension(string fileName)
    {
        var lastDot = fileName.LastIndexOf('.');
        if (lastDot <= 0)
            return (fileName, string.Empty);

        return (fileName[..lastDot], fileName[(lastDot + 1)..]);
    }

    private static bool ContainsInvalidChars(string name)
    {
        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return true;

        return name.Any(char.IsControl);
    }
}
