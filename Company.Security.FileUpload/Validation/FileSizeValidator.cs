using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using System.Buffers;

namespace Company.Security.FileUpload.Validation;

public sealed class FileSizeValidator : IFileValidator
{
    public string Name => nameof(FileSizeValidator);

    public async Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var errors = new List<FileValidationError>();

        var (size, exact) = await MeasureLengthAsync(stream, policy.FileSizes.MaxFileSizeBytes + 1, cancellationToken);

        if (!exact && size == policy.FileSizes.MaxFileSizeBytes + 1)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"The file exceeds the maximum allowed size of {policy.FileSizes.MaxFileSizeBytes} bytes."));
            return FileValidationResult.Failure(errors);
        }

        if (size == 0)
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.FileEmpty, "The file is empty."));
            return FileValidationResult.Failure(errors);
        }

        if (size > policy.FileSizes.MaxFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooLarge,
                $"The file size of {size} bytes exceeds the maximum of {policy.FileSizes.MaxFileSizeBytes} bytes."));
        }

        if (size < policy.FileSizes.MinFileSizeBytes)
        {
            errors.Add(new FileValidationError(
                FileValidationErrorCode.FileTooSmall,
                $"The file size of {size} bytes is below the minimum of {policy.FileSizes.MinFileSizeBytes} bytes."));
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
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        var bufferSize = Math.Min(buffer.Length, 8192);
        int read;
        try
        {
            while ((read = await stream.ReadAsync(new Memory<byte>(buffer, 0, bufferSize), cancellationToken)) > 0)
            {
                bytesRead += read;
                if (bytesRead > limitPlusOne)
                    return (bytesRead, false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return (bytesRead, true);
    }
}
