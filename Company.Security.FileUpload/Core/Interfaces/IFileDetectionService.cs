using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Core.Interfaces;

public interface IFileDetectionService
{
    Task<FileTypeInfo> DetectAsync(Stream stream, string? declaredExtension = null, string? declaredMimeType = null, CancellationToken cancellationToken = default);
}
