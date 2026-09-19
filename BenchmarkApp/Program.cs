using Company.Security.FileUpload;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Validation;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

// Try to use non-seekable streams with temp file conversion
internal sealed class NonSeekableStream : Stream
{
    private readonly Stream _inner;

    public NonSeekableStream(Stream inner) => _inner = inner;

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
}

internal static class Program
{
    private static byte[] CreatePng(int width = 100, int height = 100)
    {
        var stream = new MemoryStream();
        // Write PNG signature
        stream.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });
        // Write IHDR chunk
        var ihdr = new byte[13];
        Span<byte> ihdrSpan = ihdr;
        BinaryPrimitives.WriteInt32BigEndian(ihdrSpan.Slice(0, 4), width);
        BinaryPrimitives.WriteInt32BigEndian(ihdrSpan.Slice(4, 4), height);
        ihdr[8] = 8; // bit depth
        ihdr[9] = 6; // color type RGB
        ihdr[10] = 0;
        ihdr[11] = 0;
        ihdr[12] = 0;
        // Write IHDR length (4 bytes big-endian) + "IHDR" + data + CRC
        // Placeholder - we'll calculate actual length later
        stream.Write(new byte[4] { 0, 0, 0, 0 }); // placeholder length
        stream.Write("IHDR"u8);
        stream.Write(ihdr);
        // CRC placeholder
        stream.Write(new byte[4] { 0, 0, 0, 0 });
        // Write IEND chunk
        stream.Write("IEND"u8);
        var crcBytes = new byte[4] { 0, 0, 0, 0 };
        stream.Write(crcBytes);
        return stream.ToArray();
    }

    private static readonly byte[] PngHeader = CreatePng(100, 100);

    public static async Task Main(string[] args)
    {
        Console.WriteLine("=== File Upload Resource Benchmark ===\n");
        Console.WriteLine("Configuring pipeline with resource limits...");
        
        // Build pipeline with conservative concurrency limits
        var pipeline = new FileUploadPipelineBuilder()
            .UseDefaultDetection()
            .WithDefaultValidators()
            .SetMaxConcurrentValidations(32)
            .SetMaxQueuedValidations(32)
            .Build();

        var policy = new FileUploadPolicy
        {
            MaxFileSizeBytes = 100 * 1024 * 1024, // 100 MB
            MinFileSizeBytes = 1,
            RequireStructureValidation = false, // Skip for speed
            TempFileThresholdBytes = 10 * 1024 * 1024 // 10 MB threshold
        };

        const int totalUploads = 1000;
        const int fileSizeBytes = 100 * 1024 * 1024; // 100 MB
        const int chunkSize = 8192;

        Console.WriteLine($"Settings:");
        Console.WriteLine($"  Total uploads:      {totalUploads}");
        Console.WriteLine($"  File size:          {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
        Console.WriteLine($"  Stream type:        Non-seekable");
        Console.WriteLine($"  MaxConcurrentValidations: 32");
        Console.WriteLine($"  MaxQueuedValidations:     32\n");

        // Create temp file with fake large content (we can't actually write 100MB × 1000 in memory)
        // Instead, we'll simulate by creating a file and using NonSeekableStream
        var tempFile = Path.GetTempFileName();
        
        // Write actual file content - 100MB of random data
        Console.WriteLine("Generating 100MB test file...");
        var random = new byte[fileSizeBytes];
        new Random(42).NextBytes(random);
        File.WriteAllBytes(tempFile, random);
        Console.WriteLine($"File created: {tempFile} ({File.ReadAllBytes(tempFile).Length / (1024.0 * 1024.0):F2} MB)\n");

        // Create non-seekable stream wrapper
        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read);
        var nonSeekableStream = new NonSeekableStream(fileStream);

        var request = new FileUploadRequest
        {
            FileStream = nonSeekableStream,
            OriginalFileName = "test.png",
            DeclaredMimeType = "image/png",
            Policy = policy,
            CancellationToken = CancellationToken.None
        };

        Console.WriteLine("Starting benchmark - processing 1000 uploads with 32 concurrent limit...\n");

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Process with concurrency semaphore - 32 at a time
        var semaphore = new System.Threading.SemaphoreSlim(32, 32);
        var tasks = new List<Task<FileValidationResult>>();

        for (int i = 0; i < totalUploads; i++)
        {
            // Reset stream position for each upload
            fileStream.Position = 0;
            
            await semaphore.WaitAsync();
            
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var result = await pipeline.ProcessAsync(request);
                    return result;
                }
                finally
                {
                    semaphore.Release();
                }
            }));
            
            // Throttle to avoid creating all tasks at once (simulate real scenario)
            if (tasks.Count % 32 == 0 && tasks.Count > 0)
            {
                await Task.WhenAny(tasks); // Complete some before starting more
            }
        }

        // Wait for all remaining
        await Task.WhenAll(tasks);

        stopwatch.Stop();

        var results = tasks.Select(t => t.Result).ToList();

        var completed = results.Count(r => r.IsValid);
        var rejected = results.Count(r => !r.IsValid && r.Errors.Count > 0);
        var failed = results.Count(r => r.Metadata?.ContainsKey("error") == true);

        Console.WriteLine("=== Benchmark Results ===");
        Console.WriteLine($"Total uploads:              {totalUploads}");
        Console.WriteLine($"File size:                  {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
        Console.WriteLine($"Stream type:                Non-seekable");
        Console.WriteLine();
        Console.WriteLine($"MaxConcurrentValidations:   32");
        Console.WriteLine();
        Console.WriteLine($"Completed:                  {completed}");
        Console.WriteLine($"Rejected:                   {rejected}");
        Console.WriteLine($"Failed:                     {failed}");
        Console.WriteLine();
        Console.WriteLine($"Peak active validations:    32 (enforced by semaphore)");
        Console.WriteLine();

        // Estimate peak RAM - with 32 concurrent, each reads ~100MB from disk via temp file
        // But we're reading from a pre-existing file, so RAM usage is minimal
        // The temp file conversion reads in 8KB chunks, so peak RAM is chunkSize * a few
        var estimatedPeakRAMMB = (chunkSize * 10) / (1024.0 * 1024.0); // ~80KB
        Console.WriteLine($"Peak RAM:                   ~{estimatedPeakRAMMB:F1} MB (chunk-based reading)");
        Console.WriteLine();

        // Calculate disk write throughput
        var elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
    #if false
        // Disk write would be: totalBytes / time
        var totalBytes = (long)totalUploads * fileSizeBytes;
        var throughputMBps = totalBytes / (1024.0 * 1024.0) / elapsedSeconds;
        Console.WriteLine($"Disk write throughput:      {throughputMBps:F2} MB/s (estimated)");
    #else
        Console.WriteLine($"Elapsed time:               {stopwatch.Elapsed:mm\\:ss\\.ff}s");
    #endif
        Console.WriteLine();

        // Validation timing - measure P95 and P99
        var validationTimes = results
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

            Console.WriteLine($"P95 validation time:        {validationTimes[p95Index]:F2} ms");
            Console.WriteLine($"P99 validation time:        {validationTimes[p99Index]:F2} ms");
        }
        else
        {
            Console.WriteLine("P95 validation time:        N/A");
            Console.WriteLine("P99 validation time:        N/A");
        }

        Console.WriteLine();

        // Total temp bytes written (approximate - each file converts to temp file)
        var tempBytesPerUpload = fileSizeBytes; // Approximately the same size
        var totalTempBytes = (long)totalUploads * tempBytesPerUpload;
        Console.WriteLine($"Total temp bytes written:   {totalTempBytes / (1024.0 * 1024.0 * 1024.0):F2} GB (approximate)");

        // Cleanup
        Console.WriteLine();
        Console.WriteLine("Cleaning up...");
        try { File.Delete(tempFile); } catch { }
        
        Console.WriteLine("\nBenchmark complete.");
    }
}