using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Core.Interfaces;

public interface IFileUploadPipeline
{
    Task<FileValidationResult> ProcessAsync(FileUploadRequest request, CancellationToken cancellationToken = default);
}

public interface IFileUploadPipelineBuilder
{
    IFileUploadPipelineBuilder UseDefaultDetection();
    IFileUploadPipelineBuilder WithDefaultValidators();
    IFileUploadPipelineBuilder AddValidator(IFileValidator validator);
    IFileUploadPipelineBuilder UseMalwareScanner(IMalwareScanner? scanner);
    IFileUploadPipeline Build();
}
