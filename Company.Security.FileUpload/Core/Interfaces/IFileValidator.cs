using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Core.Interfaces;

public interface IFileValidator
{
    string Name { get; }

    Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default);
}
