using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class FileSizeValidator : IFileValidator
{
    public string Name => nameof(FileSizeValidator);

    public async Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();

        var (size, exact) = await MeasureLengthAsync(stream, policy.MaxFileSizeBytes + 1, cancellationToken);

        if (!exact && size == policy.MaxFileSizeBytes + 1)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"The file exceeds the maximum allowed size of {policy.MaxFileSizeBytes} bytes."));
            return FileValidationResult.Failure(errors);
        }

        if (size == 0)
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.FileEmpty, "The file is empty."));
            return FileValidationResult.Failure(errors);
        }

        if (size > policy.MaxFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"The file size of {size} bytes exceeds the maximum of {policy.MaxFileSizeBytes} bytes."));
        }

        if (size < policy.MinFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooSmall,
                $"The file size of {size} bytes is below the minimum of {policy.MinFileSizeBytes} bytes."));
        }

        return errors.Count == 0
            ? FileValidationResult.Success(detectedType, size)
            : FileValidationResult.Failure(errors);
    }

    private static async Task<(long Size, bool Exact)> MeasureLengthAsync(Stream stream, long limitPlusOne, CancellationToken cancellationToken)
    {
        if (stream.CanSeek && stream.Length >= 0)
        {
            return (stream.Length, true);
        }

        var bytesRead = 0L;
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            bytesRead += read;
            if (bytesRead > limitPlusOne)
                return (bytesRead, false);
        }

        return (bytesRead, true);
    }
}