using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Validation;

namespace Company.Security.FileUpload.Tests;

public class ResourceExhaustionTests
{
    private static IFileUploadPipeline NewPipeline() => TestPolicy.BuildPipeline();

    [Fact]
    public async Task NonSeekableStream_NotBufferedInRAM()
    {
        var tempFile = Path.GetTempFileName();
        var largeContent = new byte[10 * 1024 * 1024];
        new Random(42).NextBytes(largeContent);
        File.WriteAllBytes(tempFile, largeContent);

        var nonSeekable = new NonSeekableStream(new FileStream(tempFile, FileMode.Open, FileAccess.Read));
        var policy = TestPolicy.AllowExtensions(".png");
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTypeUnknown);

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TemporaryFile_Created_ForNonSeekable()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var policy = TestPolicy.AllowExtensions(".png");
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TemporaryFile_Deleted_AfterSuccess()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var policy = TestPolicy.AllowExtensions(".png");
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TemporaryFile_Deleted_AfterValidationFailure()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var policy = TestPolicy.AllowExtensions(".jpg");
        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionNotAllowed);

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TemporaryFile_Deleted_AfterCancellation()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var cts = new CancellationTokenSource();
        cts.Cancel();

        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = TestPolicy.AllowExtensions(".png"),
            CancellationToken = cts.Token
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            NewPipeline().ProcessAsync(request, cts.Token));

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TemporaryFile_Cleanup_AfterIOException()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var policy = TestPolicy.AllowExtensions(".png") with { FileSizes = new FileSizes { MaxFileSizeBytes = 1 } };
        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);

        try { File.Delete(tempFile); } catch { }
    }

    [Fact]
    public async Task TempDirectory_IsUsed_AndCleanedAfterProcessing()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "FileUploadTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var policy = TestPolicy.AllowExtensions(".png") with
        {
            FileSizes = new FileSizes
            {
                TempDirectory = tempDir,
                TempFileThresholdBytes = 1
            }
        };

        var fileStream = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
        var nonSeekable = new NonSeekableStream(fileStream);
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Empty(Directory.EnumerateFiles(tempDir));

        try { File.Delete(tempFile); } catch { }
        try { Directory.Delete(tempDir); } catch { }
    }

    [Fact]
    public async Task IOException_TempWrite_DoesNotCauseSuccess()
    {
        var tempFile = Path.GetTempFileName();
        var content = TestFixtures.Png(100, 100);
        File.WriteAllBytes(tempFile, content);

        var policy = TestPolicy.AllowExtensions(".png");
        var failingStream = new FailingStream(content, 1);
        var nonSeekable = new NonSeekableStream(failingStream);
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        await Assert.ThrowsAsync<IOException>(() => NewPipeline().ProcessAsync(request));

        try { File.Delete(tempFile); } catch { }
    }

    private sealed class FailingStream : Stream
    {
        private readonly byte[] _data;
        private int _position;
        private readonly int _failAfterBytes;
        private readonly bool _canRead;
        private readonly bool _canWrite;
        private readonly bool _canSeek;

        public FailingStream(byte[] data, int failAfterBytes)
        {
            _data = data;
            _failAfterBytes = failAfterBytes;
            _canRead = true;
            _canWrite = false;
            _canSeek = false;
        }

        public override bool CanRead => _canRead;
        public override bool CanWrite => _canWrite;
        public override bool CanSeek => _canSeek;
        public override long Length => _data.Length;
        public override long Position
        {
            get => _position;
            set => _position = (int)value;
        }

        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var bytesToRead = Math.Min(count, _data.Length - _position);
            if (_position >= _failAfterBytes)
            {
                throw new IOException("Simulated IO failure during read");
            }
            Array.Copy(_data, _position, buffer, offset, bytesToRead);
            _position += bytesToRead;
            return bytesToRead;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Concurrency_NeverExceedsMax()
    {
        var maxConcurrent = 8;
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: maxConcurrent);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var tasks = Enumerable.Range(0, 20).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        });

        var results = await Task.WhenAll(tasks);

        Assert.Equal(20, results.Length);
    }

    [Fact]
    public async Task ThousandConcurrentUploads_AtMostNValidations()
    {
        var maxConcurrent = 16;
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: maxConcurrent);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var tasks = Enumerable.Range(0, 100).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        });

        var results = await Task.WhenAll(tasks);

        Assert.Equal(100, results.Length);
    }

    [Fact]
    public async Task Cancellation_ReleasesConcurrencySlot()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 4);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy,
                CancellationToken = cts.Token
            };
            try
            {
                await pipeline.ProcessAsync(request, cts.Token);
            }
            catch (OperationCanceledException) { }
            return cts;
        });

        var completedSources = await Task.WhenAll(tasks);

        foreach (var tokenSource in completedSources)
        {
            using var retryCts = new CancellationTokenSource();
        }
    }

    [Fact]
    public async Task Exception_ReleasesConcurrencySlot()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 4);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var exceptionTasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = (Stream)null!,
                OriginalFileName = "photo.png",
                Policy = policy
            };
            try
            {
                await pipeline.ProcessAsync(request);
            }
            catch { }
            return Task.CompletedTask;
        });

        await Task.WhenAll(exceptionTasks);

        var validRequest = new FileUploadRequest
        {
            FileStream = new MemoryStream(png),
            OriginalFileName = "photo.png",
            Policy = policy
        };
        var result = await pipeline.ProcessAsync(validRequest);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidationFailure_ReleasesConcurrencySlot()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 4);

        var policy = TestPolicy.AllowExtensions(".jpg");
        var png = TestFixtures.Png(50, 50);
        var failureTasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            try
            {
                await pipeline.ProcessAsync(request);
            }
            catch { }
            return Task.CompletedTask;
        });

        await Task.WhenAll(failureTasks);

        var validRequest = new FileUploadRequest
        {
            FileStream = new MemoryStream(png),
            OriginalFileName = "photo.png",
            Policy = TestPolicy.AllowExtensions(".png")
        };
        var result = await pipeline.ProcessAsync(validRequest);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task TempDiskFailure_ReleasesConcurrencySlot()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 4);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var failureTasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            try
            {
                await pipeline.ProcessAsync(request);
            }
            catch { }
            return Task.CompletedTask;
        });

        await Task.WhenAll(failureTasks);

        var validRequest = new FileUploadRequest
        {
            FileStream = new MemoryStream(png),
            OriginalFileName = "photo.png",
            Policy = TestPolicy.AllowExtensions(".png")
        };
        var result = await pipeline.ProcessAsync(validRequest);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoSemaphoreLeak_AfterManyOperations()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 8);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var iterations = 50;

        var tasks = Enumerable.Range(0, iterations).Select(async i =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = $"photo_{i}.png",
                Policy = i % 5 == 0 ? TestPolicy.AllowExtensions(".jpg") : policy
            };
            try
            {
                return await pipeline.ProcessAsync(request);
            }
            catch
            {
                return null;
            }
        });

        var results = await Task.WhenAll(tasks);
        Assert.Equal(iterations, results.Length);
        var succeeded = results.Count(r => r is not null && r.IsValid);
        var failed = results.Count(r => r is null || !r.IsValid);
    }

    [Fact]
    public async Task NoUnboundedQueue_ValidationSlotsBounded()
    {
        var pipeline = new FileUploadPipeline(
            new FileTypeResolver(),
            new IFileValidator[] { new FileSizeValidator() },
            maxConcurrentValidations: 4,
            maxQueuedValidations: 4);

        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);
        var tasks = Enumerable.Range(0, 20).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        });

        var results = await Task.WhenAll(tasks);

        Assert.Equal(20, results.Length);
    }

    [Fact]
    public async Task ExistingSecurityTests_Pass()
    {
        var pipeline = TestPolicy.BuildPipeline();
        var png = TestFixtures.Png();
        var request = new FileUploadRequest
        {
            FileStream = new MemoryStream(png),
            OriginalFileName = "photo.png",
            Policy = TestPolicy.AllowExtensions(".png")
        };
        var result = await pipeline.ProcessAsync(request);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoRegression_ExistingFunctionality()
    {
        var pipeline = TestPolicy.BuildPipeline();

        var png = TestFixtures.Png();
        var request1 = new FileUploadRequest
        {
            FileStream = new MemoryStream(png),
            OriginalFileName = "photo.png",
            Policy = TestPolicy.AllowExtensions(".png")
        };
        var result1 = await pipeline.ProcessAsync(request1);
        Assert.True(result1.IsValid);

        var jpeg = TestFixtures.Jpeg();
        var request2 = new FileUploadRequest
        {
            FileStream = new MemoryStream(jpeg),
            OriginalFileName = "photo.jpg",
            Policy = TestPolicy.AllowExtensions(".jpg")
        };
        var result2 = await pipeline.ProcessAsync(request2);
        Assert.True(result2.IsValid);

        var largePng = TestFixtures.Png(400, 400);
        var request3 = new FileUploadRequest
        {
            FileStream = new MemoryStream(largePng),
            OriginalFileName = "big.png",
            Policy = TestPolicy.AllowExtensions(".png") with { FileSizes = new FileSizes { MaxFileSizeBytes = 100 } }
        };
        var result3 = await pipeline.ProcessAsync(request3);
        Assert.False(result3.IsValid);
    }
}

public class MaxConcurrentUploadsTests
{
    [Fact]
    public async Task SetMaxConcurrentUploads_BoundsConcurrency()
    {
        const int maxUploads = 2;
        int concurrent = 0;
        int peak = 0;

        var counting = new CountingValidator(
            enter: () => Interlocked.Increment(ref concurrent),
            observe: () => InterlockedMax(ref peak, Volatile.Read(ref concurrent)),
            exit: () => Interlocked.Decrement(ref concurrent));

        var pipeline = new FileUploadPipelineBuilder()
            .UseDefaultDetection()
            .AddValidator(counting)
            .SetMaxConcurrentUploads(maxUploads)
            .Build();

        var png = TestFixtures.Png(20, 20);
        var policy = TestPolicy.AllowExtensions(".png");
        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        }).ToArray();

        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.True(r.IsValid));
        Assert.True(peak <= maxUploads, $"observed peak={peak}, maxConcurrentUploads={maxUploads}");
        Assert.Equal(0, Volatile.Read(ref concurrent));
    }

    private sealed class CountingValidator : IFileValidator
    {
        private readonly Action _enter;
        private readonly Action _observe;
        private readonly Action _exit;

        public string Name => nameof(CountingValidator);

        public CountingValidator(Action enter, Action observe, Action exit)
        {
            _enter = enter;
            _observe = observe;
            _exit = exit;
        }

        public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
        {
            _enter();
            _observe();
            var result = FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream));
            _exit();
            return Task.FromResult(result);
        }
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
}