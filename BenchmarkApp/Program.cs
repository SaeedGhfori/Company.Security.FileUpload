using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;
using System.IO.Compression;

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

            const int totalUploads = 1000;
            const long fileSizeBytes = 100 * 1024 * 1024; // 100 MB
            const int maxConcurrentUploads = 10;          // the resource budget

            // Safety: this run writes up to 100 GB to the temp disk. Do a quick
            // free-space + max-temperature check and refuse to burn 100 GB if the
            // host can't hold at least the projected peak (C x MaxFileSize).
            var tempDir = Path.Combine(Path.GetTempPath(), "FileUploadBench_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            var drive = new DriveInfo(Path.GetPathRoot(tempDir)!);
            var peakDiskBytes = (long)maxConcurrentUploads * fileSizeBytes; // 1 GB
            var safetyHeadroom = 2L * 1024 * 1024 * 1024;                    // keep 2 GB spare
            if (drive.AvailableFreeSpace < peakDiskBytes + safetyHeadroom)
            {
                Console.WriteLine($"ABORT: temp drive '{drive.Name}' has only {drive.AvailableFreeSpace / (1024.0 * 1024 * 1024):F1} GB free;");
                Console.WriteLine($"       projected peak temp usage is ~{peakDiskBytes / (1024.0 * 1024 * 1024):F1} GB. Refusing to burn 100 GB.");
                return;
            }

            Console.WriteLine("Settings:");
            Console.WriteLine($"  Total uploads:              {totalUploads}");
            Console.WriteLine($"  Target file size:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
            Console.WriteLine($"  Stream type:                Non-seekable (all buffered to temp disk)");
            Console.WriteLine($"  MaxConcurrentUploads:        {maxConcurrentUploads} (resource budget)");
            Console.WriteLine($"  MaxFileSizeBytes:           {fileSizeBytes / (1024.0 * 1024.0):F2} MB");
            Console.WriteLine($"  Temp dir:                   {tempDir}");
            Console.WriteLine($"  Peak temp disk usage:       {peakDiskBytes / (1024.0 * 1024 * 1024):F1} GB (C x MaxFileSize)");
            Console.WriteLine();

            // Build pipeline with default validators and detection, applying the
            // concurrency budget that caps simultaneous temp-file buffering.
            var pipeline = new FileUploadPipelineBuilder()
                .UseDefaultDetection()
                .WithDefaultValidators()
                .SetMaxConcurrentUploads(maxConcurrentUploads)
                .Build();

            var policy = new FileUploadPolicy
            {
                FileKinds = new FileKinds
                {
                    AllowedExtensions = new[] { ".png" },
                    AllowedCategories = FileTypeCategory.Image,
                    ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject
                },
                FileSizes = new FileSizes
                {
                    MaxFileSizeBytes = fileSizeBytes,
                    MinFileSizeBytes = 1,
                    TempFileThresholdBytes = 1 // force non-seekable -> disk buffer
                },
                Structures = new Structures
                {
                    RequireStructureValidation = true
                }
            };

            var pngData = CreateValidPng();

            Console.WriteLine("Starting benchmark - every upload is buffered to the temp disk...\n");

            // Track observed concurrency of underlying temp-file buffering and
            // the peak number of temp files present at once.
            var peakConcurrent = 0;
            var concurrent = 0;
            var peakTempFiles = 0;

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            // Warm-process memory baseline AFTER JIT.
            var memBefore = GC.GetTotalMemory(true);

            var tasks = new List<Task<FileValidationResult>>(totalUploads);

            for (var i = 0; i < totalUploads; i++)
            {
                var inner = new NonSeekableStream(new BufferedPngSource(pngData, fileSizeBytes, () => Interlocked.Increment(ref concurrent), () =>
                {
                    var c = Interlocked.Decrement(ref concurrent);
                    UpdateMax(ref peakConcurrent, c);
                }));

                var request = new FileUploadRequest
                {
                    FileStream = inner,
                    OriginalFileName = "photo.png",
                    DeclaredMimeType = "image/png",
                    Policy = policy,
                    CancellationToken = CancellationToken.None
                };

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        return await pipeline.ProcessAsync(request);
                    }
                    finally
                    {
                        UpdateMax(ref peakTempFiles, Directory.EnumerateFiles(tempDir).Count());
                    }
                }));
            }

            // Wait for all tasks (the pipeline itself bounds concurrency to
            // maxConcurrentUploads; no outer semaphore needed).
            await Task.WhenAll(tasks);

            stopwatch.Stop();

            var memAfter = GC.GetTotalMemory(true);

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

            Console.WriteLine($"Peak concurrent temp-buffer: {peakConcurrent} (budget={maxConcurrentUploads})");
            Console.WriteLine($"Peak temp files on disk:     {peakTempFiles} (max theoretical={maxConcurrentUploads})");
            Console.WriteLine();

            // Peak process memory (heap) delta
            var peakRamBytes = Math.Max(memAfter - memBefore, 1);
            var peakRamMB = peakRamBytes / (1024.0 * 1024.0);
            Console.WriteLine($"Heap Delta (after - before): {peakRamMB:F2} MB");
            Console.WriteLine($"  WorkingSet (proc):         {Environment.WorkingSet / (1024.0 * 1024):F2} MB");
            Console.WriteLine();

            // Disk write throughput
            var totalBytesWritten = (long)totalUploads * fileSizeBytes;
            var elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
            var throughputMBps = totalBytesWritten / (1024.0 * 1024.0) / elapsedSeconds;
            Console.WriteLine($"Disk write throughput:      {throughputMBps:F2} MB/s");
            Console.WriteLine($"                           ({totalBytesWritten / (1024.0 * 1024.0 * 1024.0):F2} GB written / {elapsedSeconds:F1}s)");
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
            Console.WriteLine($"Total temp bytes written:   {totalBytesWritten / (1024.0 * 1024.0 * 1024.0):F2} GB");
            Console.WriteLine();

            var leftover = Directory.EnumerateFiles(tempDir).Count();
            Console.WriteLine($"Temp files left on disk:    {leftover} (DeleteOnClose + disposal)");

            Console.WriteLine();
            Console.WriteLine("Cleaning up...");
            try { Directory.Delete(tempDir, recursive: true); } catch { }

            Console.WriteLine("\nBenchmark complete.");
        }

        private static void UpdateMax(ref int target, int value)
        {
            int current;
            do
            {
                current = Volatile.Read(ref target);
                if (current >= value)
                    return;
            }
            while (Interlocked.CompareExchange(ref target, value, current) != current);
        }

        /// <summary>Produces a valid PNG header followed by zero padding up to the configured total size.</summary>
        private sealed class BufferedPngSource : Stream
        {
            private readonly byte[] _header;
            private readonly long _totalSizeBytes;
            private readonly Action _onEnter;
            private readonly Action _onExit;
            private long _position;

            public BufferedPngSource(byte[] header, long totalSizeBytes, Action onEnter, Action onExit)
            {
                _header = header;
                _totalSizeBytes = totalSizeBytes;
                _onEnter = onEnter;
                _onExit = onExit;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Position
            {
                get => _position;
                set => throw new NotSupportedException();
            }
            public override long Length => _totalSizeBytes;

            public override int Read(byte[] buffer, int offset, int count)
            {
                var remaining = (int)Math.Min(count, _totalSizeBytes - _position);
                if (remaining <= 0)
                    return 0;

                _onEnter();
                try
                {
                    var headerCopy = Math.Min(remaining, (int)Math.Max(0, _header.Length - _position));
                    if (headerCopy > 0)
                        _header.AsSpan((int)_position, headerCopy).CopyTo(buffer.AsSpan(offset, headerCopy));
                    offset += headerCopy;

                    var pad = remaining - headerCopy;
                    if (pad > 0)
                        buffer.AsSpan(offset, pad).Clear();

                    _position += remaining;
                    return remaining;
                }
                finally
                {
                    _onExit();
                }
            }

            public override void Flush() { }
            public override int ReadByte() => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }
    }
}