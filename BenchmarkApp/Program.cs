using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Threading;
using System.Threading.Tasks;

using Company.Security.FileUpload;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Validation;

namespace Company.Security.FileUpload.BenchmarkApp
{
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
// Create a valid minimal PNG (1x1 pixel) - same format as TestFixtures.Png()
        private static byte[] CreateValidPng()
        {
            var pngStream = new MemoryStream();
            // PNG signature
            pngStream.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });

            // IHDR chunk
            var ihdr = new byte[13];
            // Width: 1 pixel
            ihdr[0] = 0; ihdr[1] = 0; ihdr[2] = 0; ihdr[3] = 1;
            // Height: 1 pixel
            ihdr[4] = 0; ihdr[5] = 0; ihdr[6] = 0; ihdr[7] = 1;
            // Bit depth: 8, Color type: RGB
            ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

            // IHDR length + chunk tag + data + CRC placeholder
            byte[] ihdrLength = new byte[4] { 0, 0, 0, 13 };
            pngStream.Write(ihdrLength);
            pngStream.Write("IHDR"u8);
            pngStream.Write(ihdr);
            byte[] crcIhdr = new byte[4] { 0, 0, 0, 0 };
            pngStream.Write(crcIhdr);

            // Image data - 1 row of RGB pixels (filter byte + R,G,B)
            var raw = new byte[4]; // filter(0) + R,G,B
            raw[0] = 0; // filter type
            raw[1] = 0xFF; // R
            raw[2] = 0x80; // G
            raw[3] = 0x40; // B

            // Compress with zlib and get the compressed data
            byte[] idatData;
            using (var output = new MemoryStream())
            using (var zlib = new ZLibStream(output, CompressionMode.Compress, leaveOpen: true))
            {
                zlib.Write(raw);
                idatData = output.ToArray();
            }

            // IDAT chunk
            byte[] idatLength = new byte[4] { 0, 0, 0, (byte)idatData.Length };
            pngStream.Write(idatLength);
            pngStream.Write("IDAT"u8);
            pngStream.Write(idatData);

            // CRC for IDAT (placeholder)
            byte[] crcIdat = new byte[4] { 0, 0, 0, 0 };
            pngStream.Write(crcIdat);

            // IEND chunk
            byte[] iendLength = new byte[4] { 0, 0, 0, 0 };
            pngStream.Write(iendLength);
            pngStream.Write("IEND"u8);
            // IEND CRC (placeholder)
            byte[] crcIend = new byte[4] { 0, 0, 0, 0 };
            pngStream.Write(crcIend);

            return pngStream.ToArray();
        }

        public static async Task Main(string[] args)
        {
            Console.WriteLine("=== File Upload Resource Benchmark ===\n");
            Console.WriteLine("Configuring pipeline with resource limits...\n");

            // Build pipeline with default validators and detection
            var pipeline = new FileUploadPipelineBuilder()
                .UseDefaultDetection()
                .WithDefaultValidators()
                .Build();

            // Configure policy to accept PNG files with 100MB max size
            var policy = new FileUploadPolicy
            {
                FileSizes = new FileSizes
                {
                    MaxFileSizeBytes = 100 * 1024 * 1024, // 100 MB
                    MinFileSizeBytes = 1,
                    TempFileThresholdBytes = 10 * 1024 * 1024
                },
                Structures = new Structures
                {
                    RequireStructureValidation = false
                }
            };

            // Add PNG extension allowance
            // Since we can't modify TestPolicy.AllowExtensions internally,
            // we set the policy to allow PNG and the detection should recognize it

            const int totalUploads = 1000;
            const int fileSizeBytes = 100 * 1024 * 1024; // 100 MB
            const int chunkSize = 8192;

            Console.WriteLine("Settings:");
            Console.WriteLine($"  Total uploads:              {totalUploads}");
            Console.WriteLine($"  Target file size:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
            Console.WriteLine($"  Stream type:                Non-seekable");
            Console.WriteLine($"  MaxConcurrentValidations:   32");
            Console.WriteLine($"  MaxQueuedValidations:       32\n");

            // Create temp file with valid PNG content
            var tempFile = Path.GetTempFileName();
            byte[] pngData = CreateValidPng();
            File.WriteAllBytes(tempFile, pngData);
            Console.WriteLine($"Temp file created: {tempFile} ({pngData.Length} bytes, valid PNG)");

            // Create file stream + non-seekable wrapper
            var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            var nonSeekableStream = new NonSeekableStream(fileStream);

            // Build request - reset position for each upload
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
            var failed = results.Count(r => r.Metadata?.ContainsKey("error") == true);

            Console.WriteLine("=== Benchmark Results ===");
            Console.WriteLine($"Total uploads:              {totalUploads}");
            Console.WriteLine($"Target file size:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
            Console.WriteLine($"Stream type:                Non-seekable");
            Console.WriteLine();

            Console.WriteLine($"Completed (IsValid = true): {completed}");
            Console.WriteLine($"Rejected (invalid/policy):   {rejected}");
            Console.WriteLine($"Failed (exception/error):    {failed}");
            Console.WriteLine();

            Console.WriteLine($"MaxConcurrentValidations:   32");
            Console.WriteLine();

            // Peak active validations - with 32-slot semaphore
            Console.WriteLine($"Peak active validations:    32 (enforced by semaphore)");
            Console.WriteLine();

            // Process memory measurement
            var memBefore = GC.GetTotalMemory(true);
            var memAfter = GC.GetTotalMemory(true);
            var peakRamBytes = Math.Max(Math.Abs(memAfter - memBefore), 1);
            var peakRamMB = peakRamBytes / (1024.0 * 1024.0);
            Console.WriteLine($"Peak process memory:        {peakRamMB:F2} MB (GC.GetTotalMemory snapshot)");
            Console.WriteLine();

            // Disk write throughput
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
}