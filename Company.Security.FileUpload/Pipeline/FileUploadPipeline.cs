using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Core.Policies;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Pipeline;

public sealed class FileUploadPipeline : IFileUploadPipeline
{
    private readonly SemaphoreSlim _concurrencySemaphore;
    private readonly SemaphoreSlim _validationSemaphore;
    private readonly int _maxConcurrentValidations;
    private readonly int _maxQueuedValidations;
    private readonly IFileDetectionService _detectionService;
    private readonly IReadOnlyList<IFileValidator> _validators;
    private readonly IMalwareScanner? _malwareScanner;
    private readonly ILogger? _logger;

    public FileUploadPipeline(
        IFileDetectionService detectionService,
        IEnumerable<IFileValidator> validators,
        IMalwareScanner? malwareScanner = null,
        ILogger? logger = null,
        int maxConcurrentUploads = 10,
        int maxConcurrentValidations = 32,
        int maxQueuedValidations = 32)
    {
        ArgumentNullException.ThrowIfNull(detectionService);
        ArgumentNullException.ThrowIfNull(validators);

        _detectionService = detectionService;
        _validators = validators.ToArray();
        _malwareScanner = malwareScanner;
        _logger = logger;
        _concurrencySemaphore = new SemaphoreSlim(maxConcurrentUploads, maxConcurrentUploads);
        _maxConcurrentValidations = maxConcurrentValidations;
        _maxQueuedValidations = maxQueuedValidations;
        _validationSemaphore = new SemaphoreSlim(maxQueuedValidations + maxConcurrentValidations, maxQueuedValidations + maxConcurrentValidations);
    }

    public Task<FileValidationResult> ProcessAsync(FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.FileStream);

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");

        var effectiveToken = cancellationToken.CanBeCanceled
            ? cancellationToken
            : request.CancellationToken;

        return ProcessCoreAsync(request, policy, effectiveToken);
    }

    private async Task<FileValidationResult> ProcessCoreAsync(
        FileUploadRequest request,
        FileUploadPolicy policy,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();

        await _concurrencySemaphore.WaitAsync(cancellationToken);
        try
        {
            await _validationSemaphore.WaitAsync(cancellationToken);
            try
            {
                var (stream, shouldDispose) = await EnsureSeekableAsync(request.FileStream, policy, cancellationToken);

                try
                {
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

                    if (finalResult.IsValid && policy.MalwareScanning.RequireMalwareScan)
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
                finally
                {
                    _validationSemaphore.Release();

                    if (shouldDispose)
                    {
                        try { stream.Dispose(); }
                        catch { /* ignore dispose errors */ }
                    }
                }
            }
            finally
            {
                _concurrencySemaphore.Release();
            }
        }
        catch (OperationCanceledException)
        {
            try { _validationSemaphore.Release(); } catch { }
            try { _concurrencySemaphore.Release(); } catch { }
            throw;
        }
    }

    private async Task<(FileValidationResult? Blocked, MalwareScanResult? ScanRecord)> RunMalwareScanAsync(Stream stream, FileUploadPolicy policy, FileValidationResult current, CancellationToken cancellationToken)
    {
        if (_malwareScanner is null)
        {
            if (policy.MalwareScanning.RejectIfMalwareScanUnavailable)
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
            case MalwareScanStatus.NotSupported when policy.MalwareScanning.MalwareScanUnknownPolicy == MalwareScanErrorPolicy.Allow:
                return (null, scanResult);

            case MalwareScanStatus.Infected:
                return (current.AddError(new FileValidationError(
                    FileValidationErrorCode.MalwareScanInfected,
                    scanResult.ThreatName is null
                        ? "Malware scanning detected a threat in the file."
                        : $"Malware scanning detected a threat: {scanResult.ThreatName}")), scanResult);

            case MalwareScanStatus.Error:
                if (policy.MalwareScanning.MalwareScanErrorPolicy == MalwareScanErrorPolicy.Reject)
                {
                    return (current.AddError(new FileValidationError(
                        FileValidationErrorCode.MalwareScanError,
                        "The malware scanner failed to scan the file.")), scanResult);
                }
                return (null, scanResult);

            case MalwareScanStatus.Unknown:
            case MalwareScanStatus.NotSupported:
                if (policy.MalwareScanning.MalwareScanUnknownPolicy == MalwareScanErrorPolicy.Reject)
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

    private static async Task<(Stream Stream, bool ShouldDispose)> EnsureSeekableAsync(Stream source, FileUploadPolicy policy, CancellationToken cancellationToken)
    {
        if (source.CanSeek)
            return (source, false);

        // Non-seekable streams always buffer to a temp file we own, never fully
        // into RAM. A large upload or a slow producer must not inflate the heap;
        // the temp file is deleted by us on dispose (not left to the OS).
        return await BufferToTempFileAsync(source, policy, cancellationToken);
    }

    private static async Task<(Stream Stream, bool ShouldDispose)> BufferToTempFileAsync(Stream source, FileUploadPolicy policy, CancellationToken cancellationToken)
    {
        string? tempFilePath = null;
        FileStream? tempStream = null;

        try
        {
            var tempDir = string.IsNullOrWhiteSpace(policy.FileSizes.TempDirectory)
                ? Path.GetTempPath()
                : policy.FileSizes.TempDirectory;

            if (!Directory.Exists(tempDir))
                Directory.CreateDirectory(tempDir);

            tempFilePath = Path.Combine(tempDir, $"{Guid.NewGuid():N}.tmp");
            tempStream = new FileStream(tempFilePath, FileMode.CreateNew, FileAccess.ReadWrite,
                FileShare.None, 4096);

            var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            var chunkSize = Math.Min(buffer.Length, 64 * 1024);
            var total = 0L;
            var limit = policy.FileSizes.MaxFileSizeBytes + 1;

            try
            {
                while (total < limit)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var read = await source.ReadAsync(new Memory<byte>(buffer, 0, (int)Math.Min(chunkSize, limit - total)), cancellationToken);
                    if (read == 0)
                        break;
                    await tempStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    total += read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            tempStream.Position = 0;
            return (new ManagedTempFileStream(tempStream, tempFilePath), true);
        }
        catch
        {
            try { tempStream?.Dispose(); } catch { }
            try { if (tempFilePath is not null) File.Delete(tempFilePath); } catch { }
            throw;
        }
    }
}
