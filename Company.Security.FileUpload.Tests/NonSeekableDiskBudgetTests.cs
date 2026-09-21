using System.IO;
using System.Threading;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Tests;

/// <summary>
/// Reproduces the "many concurrent MAX-SIZE non-seekable uploads" scenario at
/// bounded scale: every upload must be buffered to the temp disk (non-seekable),
/// the concurrency budget guarantees fewer than N files touch the disk at once,
/// and nothing leaks after processing.
///
/// The unit test replays the shape (real bytes, real temp writes, real gate)
/// but bounded in count/size; the BenchmarkApp brings the same shape up to
/// 1000 x 100MB with measured numbers.
/// </summary>
public class NonSeekableDiskBudgetTests
{
    [Fact]
    public async Task NonSeekableUploads_ConcurrencyBudget_And_TempCleanup()
    {
        const int maxUploads = 2;      // the resource budget: <=2 files may hit the temp disk concurrently
        const int totalUploads = 6;    // 3x the budget; the rest must queue behind the disk gate
        const long fileSize = 64L * 1024 * 1024; // 64 MB per upload

        var tempDir = Path.Combine(Path.GetTempPath(), "FileUpload_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        var active = new CountingProbe();

        var pipeline = new FileUploadPipelineBuilder()
            .UseDefaultDetection()
            .SetMaxConcurrentUploads(maxUploads)
            .Build();

        var policy = TestPolicy.AllowExtensions(".png") with
        {
            FileSizes = new FileSizes
            {
                TempDirectory = tempDir,
                MaxFileSizeBytes = fileSize,
                TempFileThresholdBytes = 1 // everything non-seekable goes straight to disk
            },
            Structures = new Structures { RequireStructureValidation = false }
        };

        var tasks = Enumerable.Range(0, totalUploads).Select(async _ =>
        {
            var generator = new NonSeekableStream(new ObservingPngStream(fileSize, active));
            var request = new FileUploadRequest
            {
                FileStream = generator,
                OriginalFileName = "photo.png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        }).ToArray();

        var results = await Task.WhenAll(tasks);

        // Every upload succeeded end-to-end.
        Assert.All(results, r => Assert.True(r.IsValid, r.Errors.FirstOrDefault()?.Code.ToString()));

        // The concurrency budget capped how many non-seekable streams were
        // draining to the temp disk at once.
        Assert.True(active.Peak <= maxUploads,
            $"observed peak concurrent temp buffering {active.Peak} > budget {maxUploads}");

        // No temp file survived processing (DeleteOnClose + disposal).
        Assert.Empty(Directory.EnumerateFiles(tempDir));

        Directory.Delete(tempDir);
    }

    private static int InterlockedMax(ref int target, int value)
    {
        int current;
        do
        {
            current = Volatile.Read(ref target);
            if (current >= value)
                return current;
        }
        while (Interlocked.CompareExchange(ref target, value, current) != current);
        return value;
    }

    /// <summary>Non-seekable producer of a valid PNG followed by padding up to the configured total size.</summary>
    private sealed class ObservingPngStream : Stream
    {
        private readonly byte[] _header = TestFixtures.Png(1, 1);
        private readonly long _totalBytes;
        private readonly CountingProbe _probe;
        private long _position;

        public ObservingPngStream(long totalBytes, CountingProbe probe)
        {
            _totalBytes = totalBytes;
            _probe = probe;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }
        public override long Length => _totalBytes;

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = (int)Math.Min(count, _totalBytes - _position);
            if (remaining <= 0)
                return 0;

            _probe.Enter();
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
                _probe.Exit();
            }
        }

        public override void Flush() { }
        public override int ReadByte() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class CountingProbe
    {
        private int _active;
        private int _peak;

        public void Enter() => Interlocked.Increment(ref _active);
        public void Exit() => Interlocked.Decrement(ref _active);

        public int Peak
        {
            get
            {
                InterlockedMax(ref _peak, Volatile.Read(ref _active));
                return Volatile.Read(ref _peak);
            }
        }
    }
}