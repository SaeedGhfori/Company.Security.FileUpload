using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Validation;

public sealed class FileContentValidator : IFileValidator
{
    public string Name => nameof(FileContentValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();
        var warnings = new List<string>();

        if (!string.IsNullOrWhiteSpace(request.DeclaredMimeType) && detectedType.IsKnownFormat)
        {
            var suspect = MimeDetector.IsSuspectMime(request.DeclaredMimeType, detectedType.DetectedMimeType);
            if (suspect)
            {
                string message = $"The declared MIME type '{request.DeclaredMimeType}' does not match the detected content.";

                if (policy.ExtensionMismatchPolicy == ExtensionMismatchPolicy.Reject)
                    errors.Add(new FileValidationError(FileValidationErrorCode.MimeMismatchWithSignature, message));
                else
                    warnings.Add(message);
            }
        }

        if (request.DeclaredFileSize is > 0 && stream.CanSeek)
        {
            var actual = StreamHelper.GetLength(stream);
            if (actual >= 0 && actual != request.DeclaredFileSize.Value)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.FileTooLarge,
                    "The actual file size does not match the declared size."));
            }
        }

        var result = errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors);

        foreach (var warning in warnings)
            result = result.AddWarning(warning);

        return Task.FromResult(result);
    }
}