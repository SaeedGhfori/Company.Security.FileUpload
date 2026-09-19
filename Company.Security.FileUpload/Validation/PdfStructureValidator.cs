using System.Buffers;
using System.Text;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class PdfStructureValidator : IFileValidator
{
    public string Name => nameof(PdfStructureValidator);

    public async Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        if (!policy.RequireStructureValidation || !string.Equals(detectedType.FormatName, "PDF", StringComparison.OrdinalIgnoreCase))
        {
            return FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream));
        }

        var errors = new List<FileValidationError>();
        var prefix = await StreamHelper.ReadPrefixAsync(stream, Math.Max(policy.StructureReadLimitBytes, 256), cancellationToken);

        if (prefix.Length < 5)
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.StructurePdfInvalid, "The PDF file is too short to contain a valid header."));
            return FileValidationResult.Failure(errors);
        }

        var headerText = Encoding.ASCII.GetString(prefix, 0, Math.Min(prefix.Length, 16));

        if (!headerText.StartsWith("%PDF-", StringComparison.Ordinal))
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.StructurePdfInvalid, "The file does not start with a valid PDF header."));
            return FileValidationResult.Failure(errors);
        }

        var versionPart = headerText.Substring(5);
        var versionOk = versionPart.StartsWith("1.", StringComparison.Ordinal)
            || versionPart.StartsWith("2.", StringComparison.Ordinal);

        if (!versionOk)
        {
            errors.Add(new FileValidationError(FileValidationErrorCode.StructurePdfInvalid, "The PDF header declares an invalid version."));
        }

        if (stream.CanSeek)
        {
            var tail = await ReadTailAsync(stream, 2048, cancellationToken);
            var tailText = Encoding.ASCII.GetString(tail);
            if (!tailText.Contains("%%EOF", StringComparison.Ordinal))
            {
                errors.Add(new FileValidationError(FileValidationErrorCode.StructurePdfInvalid, "The PDF does not contain an end-of-file marker (%%EOF)."));
            }
        }

        return errors.Count == 0
            ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
            : FileValidationResult.Failure(errors);
    }

    private static async Task<byte[]> ReadTailAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var length = stream.Length;
        var startOffset = Math.Max(0, length - maxBytes);
        var originalPosition = stream.Position;
        stream.Position = startOffset;

        var buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(maxBytes, length));
        var bufferLength = (int)Math.Min(maxBytes, length);
        var total = 0;
        try
        {
            while (total < bufferLength)
            {
                var read = await stream.ReadAsync(new Memory<byte>(buffer, total, bufferLength - total), cancellationToken);
                if (read == 0)
                    break;
                total += read;
            }
        }
        finally
        {
            stream.Position = originalPosition;
        }

        var result = new byte[total];
        buffer.AsSpan(0, total).CopyTo(result);
        ArrayPool<byte>.Shared.Return(buffer);
        return result;
    }
}
