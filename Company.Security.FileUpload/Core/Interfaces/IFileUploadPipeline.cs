using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Core.Interfaces;

public interface IFileUploadPipeline
{
    Task<FileValidationResult> ProcessAsync(FileUploadRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates an upload using a per-call subset of allowed extensions.
    /// When <paramref name="allowedExtensions"/> is null or empty, every registered
    /// extension for the detected <see cref="Company.Security.FileUpload.Core.Enums.FileTypeCategory"/>
    /// is allowed. When provided, only that subset is allowed, and both the declared
    /// (file name) and detected (real bytes) extensions must be in it.
    /// </summary>
    Task<FileValidationResult> ProcessAsync(
        FileUploadRequest request,
        IEnumerable<string>? allowedExtensions,
        CancellationToken cancellationToken = default);
}

public interface IFileUploadPipelineBuilder
{
    IFileUploadPipelineBuilder UseDefaultDetection();
    IFileUploadPipelineBuilder WithDefaultValidators();
    IFileUploadPipelineBuilder AddValidator(IFileValidator validator);
    IFileUploadPipelineBuilder UseMalwareScanner(IMalwareScanner? scanner);
    IFileUploadPipelineBuilder SetMaxConcurrentValidations(int count);
    IFileUploadPipelineBuilder SetMaxQueuedValidations(int count);
    IFileUploadPipeline Build();
}
