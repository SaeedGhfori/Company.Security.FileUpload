using System.Buffers;
using System.Diagnostics;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Core.Policies;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Pipeline;

public sealed class FileUploadPipeline
{
    private readonly IFileDetectionService _detectionService;
    private readonly IReadOnlyList<IFileValidator> _validators;
    private readonly IMalwareScanner? _malwareScanner;

    public FileUploadPipeline(
        IFileDetectionService detectionService,
        IEnumerable<IFileValidator> validators,
        IMalwareScanner? malwareScanner = null)
    {
        ArgumentNullException.ThrowIfNull(detectionService);
        ArgumentNullException.ThrowIfNull(validators);

        _detectionService = detectionService;
        _validators = validators.ToArray();
        _malwareScanner = malwareScanner;
    }

    public async Task<FileValidationResult> ProcessAsync(FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.FileStream);

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        var stopwatch = Stopwatch.StartNew();

        var stream = await EnsureSeekableAsync(request.FileStream, policy, cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        stream.Position = 0;

        var detectedType = await _detectionService.DetectAsync(
            stream,
            declaredExtension: ExtensionResolver.Normalize(request.OriginalFileName),
            declaredMimeType: request.DeclaredMimeType,
            cancellationToken);

        var errors = new List<FileValidationError>();

        foreach (var validator in _validators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var validatorResult = await validator.ValidateAsync(stream, detectedType, request, cancellationToken);
            errors.AddRange(validatorResult.Errors);
        }

        var fileSize = GetSize(stream, policy);
        var policyResult = PolicyEngine.Evaluate(detectedType, fileSize, policy, cancellationToken);
        errors.AddRange(policyResult.Errors);

        var finalResult = errors.Count == 0
            ? FileValidationResult.Success(detectedType, fileSize)
            : FileValidationResult.Failure(errors);

        foreach (var warning in policyResult.Warnings)
            finalResult = finalResult.AddWarning(warning);

        if (finalResult.IsValid && policy.RequireMalwareScan)
        {
            var (scanBlocked, scanRecord) = await RunMalwareScanAsync(stream, policy, finalResult, cancellationToken);
            if (scanBlocked is not null)
            {
                finalResult = scanBlocked;
            }

            if (scanRecord is not null)
            {
                finalResult = finalResult with { MalwareScanResult = scanRecord.Status };
            }
        }

        finalResult = finalResult with
        {
            ValidationDuration = stopwatch.Elapsed
        };

        return finalResult;
    }

    private async Task<(FileValidationResult? Blocked, MalwareScanResult? ScanRecord)> RunMalwareScanAsync(Stream stream, FileUploadPolicy policy, FileValidationResult current, CancellationToken cancellationToken)
    {
        if (_malwareScanner is null)
        {
            if (policy.RejectIfMalwareScanUnavailable)
            {
                return (current.AddError(new FileValidationError(
                    FileValidationErrorCode.MalwareScanRequired,
                    "Malware scanning is required by policy but no scanner is configured.")), null);
            }

            return (null, null);
        }

        cancellationToken.ThrowIfCancellationRequested();

        stream.Position = 0;
        var scanResult = await _malwareScanner.ScanAsync(stream, cancellationToken);

        switch (scanResult.Status)
        {
            case MalwareScanStatus.Clean:
            case MalwareScanStatus.NotSupported when policy.MalwareScanUnknownPolicy == MalwareScanErrorPolicy.Allow:
                return (null, scanResult);

            case MalwareScanStatus.Infected:
                return (current.AddError(new FileValidationError(
                    FileValidationErrorCode.MalwareScanInfected,
                    scanResult.ThreatName is null
                        ? "Malware scanning detected a threat in the file."
                        : $"Malware scanning detected a threat: {scanResult.ThreatName}")), scanResult);

            case MalwareScanStatus.Error:
                if (policy.MalwareScanErrorPolicy == MalwareScanErrorPolicy.Reject)
                {
                    return (current.AddError(new FileValidationError(
                        FileValidationErrorCode.MalwareScanError,
                        "The malware scanner failed to scan the file.")), scanResult);
                }
                return (null, scanResult);

            case MalwareScanStatus.Unknown:
            case MalwareScanStatus.NotSupported:
                if (policy.MalwareScanUnknownPolicy == MalwareScanErrorPolicy.Reject)
                {
                    return (current.AddError(new FileValidationError(
                        FileValidationErrorCode.MalwareScanError,
                        "The malware scanner returned an inconclusive result.")), scanResult);
                }
                return (null, scanResult);

            default:
                return (null, scanResult);
        }
    }

    private static long GetSize(Stream stream, FileUploadPolicy policy)
    {
        if (stream.CanSeek)
            return stream.Length;

        return stream.Position;
    }

    private static async Task<Stream> EnsureSeekableAsync(Stream source, FileUploadPolicy policy, CancellationToken cancellationToken)
    {
        if (source.CanSeek)
            return source;

        var buffer = new MemoryStream();
        var chunk = ArrayPool<byte>.Shared.Rent(8192);
        var chunkSize = Math.Min(chunk.Length, 8192);
        var total = 0L;
        var limit = policy.MaxFileSizeBytes + 1;

        try
        {
            while (total <= limit)
            {
                var read = await source.ReadAsync(new Memory<byte>(chunk, 0, (int)Math.Min(chunkSize, limit - total)), cancellationToken);
                if (read == 0)
                    break;
                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
                total += read;
            }
        }
        finally
        {
            if (source.CanSeek)
                source.Position = 0;
            ArrayPool<byte>.Shared.Return(chunk);
        }

        if (total > policy.MaxFileSizeBytes)
        {
            buffer.Position = 0;
            return buffer;
        }

        buffer.Position = 0;
        return buffer;
    }
}
