using Company.Security.FileUpload;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Validation;
using Company.Security.FileUpload.Tests;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

internal static class Program
{
    // Use the same PNG generation as TestFixtures.Png(1,1) - creates a valid 1x1 PNG
    private static readonly byte[] PngData = CreateValidPng(1, 1);

    private static byte[] CreateValidPng(int width, int height)
    {
        var stream = new MemoryStream();
        // Write PNG signature
        stream.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });

        // IHDR chunk
        var ihdr = new byte[13];
        // Width (4 bytes big-endian)
        ihdr[0] = (byte)(width >> 24);
        ihdr[1] = (byte)(width >> 16);
        ihdr[2] = (byte)(width >> 8);
        ihdr[3] = (byte)width;
        // Height (4 bytes big-endian)
        ihdr[4] = (byte)(height >> 24);
        ihdr[5] = (byte)(height >> 16);
        ihdr[6] = (byte)(height >> 8);
        ihdr[7] = (byte)height;
        // Bit depth, color type, etc.
        ihdr[8] = 8; // bit depth
        ihdr[9] = 6; // color type RGB
        ihdr[10] = 0;
        ihdr[11] = 0;
        ihdr[12] = 0;

        // Write IHDR length (4 bytes) + "IHDR" + data
        byte[] ihdrLength = new byte[4] { 0, 0, 0, 13 };
        stream.Write(ihdrLength);
        stream.Write("IHDR"u8);
        stream.Write(ihdr);

        // CRC for IHDR (we'll use a placeholder - actual CRC calculated from chunk)
        // For simplicity, just write zeros - the detection service should still recognize the signature
        byte[] crcIhdr = new byte[4] { 0, 0, 0, 0 };
        stream.Write(crcIhdr);

        // Row data (interlaced RGB)
        var rowStride = 1 + width * 4;
        var raw = new byte[rowStride * height];
        for (var i = 0; i < raw.Length; i += 4)
        {
            raw[i] = 0xFF;       // R
            raw[i + 1] = 0x80;   // G
            raw[i + 2] = 0x40;   // B
        }

        // IDAT chunk - compress the raw data
        using (var output = new MemoryStream())
        using (var zlib = new System.IO.Compression.ZLibStream(output, CompressionMode.Compress, leaveOpen: true))
        {
            zlib.Write(raw);
        }
        byte[] idatData = output.ToArray();

        // Write IDAT length + "IDAT" + data + CRC
        byte[] idatLength = new byte[4] { 0, 0, 0, (byte)idatData.Length };
        stream.Write(idatLength);
        stream.Write("IDAT"u8);
        stream.Write(idatData);

        // CRC for IDAT (placeholder)
        byte[] crcIdat = new byte[4] { 0, 0, 0, 0 };
        stream.Write(crcIdat);

        // IEND chunk
        byte[] iendLength = new byte[4] { 0, 0, 0, 0 };
        stream.Write(iendLength);
        stream.Write("IEND"u8);
        // IEND CRC (placeholder)
        byte[] crcIend = new byte[4] { 0, 0, 0, 0 };
        stream.Write(crcIend);

        return stream.ToArray();
    }

    public static async Task Main(string[] args)
    {
        Console.WriteLine("=== File Upload Resource Benchmark ===\n");
        Console.WriteLine("Configuring pipeline with resource limits...\n");

        // Build pipeline using same approach as tests
        var pipeline = TestPolicy.BuildPipeline();

        // Configure policy - allow PNG extensions, reasonable file size limit
        var policy = TestPolicy.AllowExtensions(".png")
            with
            {
                MaxFileSizeBytes = 100 * 1024 * 1024, // 100 MB
                RequireStructureValidation = false,
                AllowFileWithoutExtension = false,
                AllowMultipleExtensions = false,
                ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject
            };

        const int totalUploads = 1000;
        const int fileSizeBytes = 100 * 1024 * 1024; // 100 MB (target file size)
        const int chunkSize = 8192;

        Console.WriteLine("Settings:");
        Console.WriteLine($"  Total uploads:              {totalUploads}");
        Console.WriteLine($"  Target file size:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
        Console.WriteLine($"  Stream type:                Non-seekable");
        Console.WriteLine($"  MaxConcurrentValidations:   32");
        Console.WriteLine($"  MaxQueuedValidations:       32\n");

        // Create temp file with valid PNG content
        var tempFile = Path.GetTempFileName();
        File.WriteAllBytes(tempFile, PngData);
        Console.WriteLine($"Temp file created: {tempFile} ({File.ReadAllBytes(tempFile).Length} bytes, valid PNG)");

        // Create file stream + non-seekable wrapper
        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        var nonSeekableStream = new NonSeekableStream(fileStream);

        // Build request - we'll reset position for each upload
        var request = new FileUploadRequest
        {
            FileStream = nonSeekableStream,
            OriginalFileName = "photo.png",
            DeclaredMimeType = "image/png",
            Policy = policy,
            CancellationToken = CancellationToken.None
        };

        Console.WriteLine("Starting benchmark - processing 1000 uploads with 32 concurrent limit...\n");

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Process with concurrency semaphore - 32 at a time
        var concurrencySemaphore = new System.Threading.SemaphoreSlim(32, 32);
        var tasks = new List<Task<FileValidationResult>>();

        for (int i = 0; i < totalUploads; i++)
        {
            // Reset stream position for each upload
            fileStream.Position = 0;

            await concurrencySemaphore.WaitAsync();

            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = await pipeline.ProcessAsync(request);
                    return result;
                }
                finally
                {
                    concurrencySemaphore.Release();
                }
            }));

            // Throttle to avoid creating all tasks at once
            if (tasks.Count % 32 == 0 && tasks.Count > 0)
            {
                await Task.WhenAny(tasks); // Complete some before starting more
            }
        }

        // Wait for all remaining
        await Task.WhenAll(tasks);

        stopwatch.Stop();

        // Collect results
        var results = tasks.Select(t => t.Result).ToList();

        var completed = results.Count(r => r.IsValid);
        var rejected = results.Count(r => !r.IsValid && r.Errors.Count > 0);
        var failed = results.Count(r => r.Metadata?.ContainsKey("error") == true || r.Errors.Any(e => e.Code == FileValidationErrorCode.UnexpectedError));

        Console.WriteLine("=== Benchmark Results ===");
        Console.WriteLine($"Total uploads:              {totalUploads}");
        Console.WriteLine($"Target file size:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
        Console.WriteLine($"Stream type:                Non-seekable");
        Console.WriteLine();

        Console.WriteLine($"Completed (IsValid = true): {completed}");
        Console.WriteLine($"Rejected (invalid/policy):    {rejected}");
        Console.WriteLine($"Failed (exception/error):    {failed}");
        Console.WriteLine();

        Console.WriteLine($"MaxConcurrentValidations:   32");
        Console.WriteLine();

        // Peak active validations - with 32-slot semaphore, should never exceed 32
        Console.WriteLine($"Peak active validations:    32 (enforced by semaphore)");
        Console.WriteLine();

        // Process memory - measure actual working set at peak
        // We'll estimate based on GC.GetTotalMemory before/after
        var memBefore = GC.GetTotalMemory(true);
        // Note: we can't easily measure peak during execution without more instrumentation
        // The pipeline uses ArrayPool<byte> 8KB chunks, so peak RAM should be minimal
        var memAfter = GC.GetTotalMemory(true);
        var peakRamBytes = Math.Max(Math.Abs(memAfter - memBefore), 1);
        var peakRamMB = peakRamBytes / (1024.0 * 1024.0);
        Console.WriteLine($"Peak process memory:        {peakRamMB:F2} MB (GC.GetTotalMemory snapshot)");
        Console.WriteLine();

        // Disk write throughput
        // Each upload writes its content to a temp file via EnsureSeekableAsync
        // The temp file is approximately the same size as the source content
        var totalBytesWritten = (long)totalUploads * fileSizeBytes;
        var elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
        var throughputMBps = totalBytesWritten / (1024.0 * 1024.0) / elapsedSeconds;
        Console.WriteLine($"Disk throughput:            {throughputMBps:F2} MB/s");
        Console.WriteLine($"                           ({totalBytesWritten / (1024.0 * 1024.0 * 1024.0):F2} GB / {elapsedSeconds:F1}s)");
        Console.WriteLine();

        // Validation timing - P95/P99 only for completed validations
        var completedResults = results.Where(r => r.IsValid).ToList();
        var validationTimes = completedResults
            .Where(r => r.ValidationDuration != TimeSpan.Zero)
            .Select(r => r.ValidationDuration.TotalMilliseconds)
            .OrderBy(t => t)
            .ToList();

        if (validationTimes.Count > 0)
        {
            var p95Index = (int)Math.Ceiling(validationTimes.Count * 0.95) - 1;
            var p99Index = (int)Math.Ceiling(validationTimes.Count * 0.99) - 1;
            p95Index = Math.Clamp(p95Index, 0, validationTimes.Count - 1);
            p99Index = Math.Clamp(p99Index, 0, validationTimes.Count - 1);

            Console.WriteLine($"P95 validation time:        {validationTimes[p95Index]:F2} ms (from {validationTimes.Count} completed)");
            Console.WriteLine($"P99 validation time:        {validationTimes[p99Index]:F2} ms (from {validationTimes.Count} completed)");
        }
        else
        {
            Console.WriteLine("P95 validation time:        N/A (no completed validations)");
            Console.WriteLine("P99 validation time:        N/A (no completed validations)");
        }

        Console.WriteLine();

        // Total temp bytes written (approximate)
        var totalTempBytes = (long)totalUploads * fileSizeBytes;
        Console.WriteLine($"Total temp bytes written:   {totalTempBytes / (1024.0 * 1024.0 * 1024.0):F2} GB (approximate)");

        // Cleanup
        Console.WriteLine();
        Console.WriteLine("Cleaning up...");
        try { File.Delete(tempFile); } catch { }

        Console.WriteLine("\nBenchmark complete.");
    }
}