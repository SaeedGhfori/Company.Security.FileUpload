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

    private static readonly FileNameValidator FileNameValidator = new();
    private static readonly FileExtensionValidator FileExtensionValidator = new();
    private static readonly FileSizeValidator FileSizeValidator = new();
    private static readonly FileSignatureValidator FileSignatureValidator = new();
    private static readonly FileContentValidator FileContentValidator = new();
    private static readonly ImageStructureValidator ImageStructureValidator = new();
    private static readonly PdfStructureValidator PdfStructureValidator = new();
    private static readonly ArchiveStructureValidator ArchiveStructureValidator = new();
    private static readonly OfficeStructureValidator OfficeStructureValidator = new();

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
        _validators.Add(FileNameValidator);
        _validators.Add(FileExtensionValidator);
        _validators.Add(FileSizeValidator);
        _validators.Add(FileSignatureValidator);
        _validators.Add(FileContentValidator);
        _validators.Add(ImageStructureValidator);
        _validators.Add(PdfStructureValidator);
        _validators.Add(ArchiveStructureValidator);
        _validators.Add(OfficeStructureValidator);
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