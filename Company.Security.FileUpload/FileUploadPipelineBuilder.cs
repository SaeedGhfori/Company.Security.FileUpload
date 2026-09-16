using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Validation;

namespace Company.Security.FileUpload;

public sealed class FileUploadPipelineBuilder
{
    private readonly List<IFileValidator> _validators = new();
    private IFileDetectionService? _detectionService;
    private IMalwareScanner? _malwareScanner;

    public FileUploadPipelineBuilder UseDetection(IFileDetectionService detectionService)
    {
        _detectionService = detectionService;
        return this;
    }

    public FileUploadPipelineBuilder UseDefaultDetection()
    {
        _detectionService = new FileTypeResolver();
        return this;
    }

    public FileUploadPipelineBuilder UseMalwareScanner(IMalwareScanner scanner)
    {
        _malwareScanner = scanner;
        return this;
    }

    public FileUploadPipelineBuilder AddValidator(IFileValidator validator)
    {
        _validators.Add(validator);
        return this;
    }

    public FileUploadPipelineBuilder WithDefaultValidators()
    {
        _validators.Clear();
        _validators.Add(new FileNameValidator());
        _validators.Add(new FileExtensionValidator());
        _validators.Add(new FileSizeValidator());
        _validators.Add(new FileSignatureValidator());
        _validators.Add(new FileContentValidator());
        _validators.Add(new ImageStructureValidator());
        _validators.Add(new PdfStructureValidator());
        _validators.Add(new ArchiveStructureValidator());
        _validators.Add(new OfficeStructureValidator());
        return this;
    }

    public FileUploadPipeline Build()
    {
        var detection = _detectionService ?? new FileTypeResolver();

        if (_validators.Count == 0)
            WithDefaultValidators();

        return new FileUploadPipeline(detection, _validators, _malwareScanner);
    }
}