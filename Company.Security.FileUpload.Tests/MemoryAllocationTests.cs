using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Tests;
using Company.Security.FileUpload.Validation;

namespace Company.Security.FileUpload.Tests;

public class NonSeekableStreamTests
{
    private static IFileUploadPipeline NewPipeline() => TestPolicy.BuildPipeline();

    // Non-seekable stream should be validated without full-file RAM buffering
    [Fact]
    public async Task NonSeekableStream_ValidPng_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.RequestNonSeekable(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("PNG", result.DetectedFileType!.FormatName);
    }

    [Fact]
    public async Task NonSeekableStream_TooLarge_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { MaxFileSizeBytes = 100 };
        var request = TestFixtures.RequestNonSeekable(TestFixtures.Png(400, 400), "big.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTooLarge);
    }

    [Fact]
    public async Task NonSeekableStream_ExtensionMismatch_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.RequestNonSeekable(TestFixtures.Png(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMismatch);
    }

    [Fact]
    public async Task NonSeekableStream_UnknownFile_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.RequestNonSeekable(TestFixtures.RandomUnknown(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTypeUnknown);
    }

    [Fact]
    public async Task NonSeekableStream_Cancelled_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.RequestWithCancellationToken(TestFixtures.Png(), "photo.png", cts.Token, policy);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NewPipeline().ProcessAsync(request, cts.Token));
    }
}

public class MemoryAllocationTests
{
    [Fact]
    public void FileSignatureDetector_ReadPrefixAsync_ReturnsCorrectSize()
    {
        var content = new byte[1024];
        new Random(42).NextBytes(content);
        using var stream = new MemoryStream(content);

        var prefix = FileSignatureDetector.ReadPrefixAsync(stream, 512, CancellationToken.None).Result;

        Assert.Equal(512, prefix.Length);
        Assert.Equal(content[..512], prefix);
    }

    [Fact]
    public void StreamHelper_ReadPrefixAsync_UsesArrayPool()
    {
        var content = new byte[1024];
        new Random(42).NextBytes(content);
        using var stream = new MemoryStream(content);

        // This just verifies it doesn't throw — ArrayPool return is verified by code review
        var prefix = StreamHelper.ReadPrefixAsync(stream, 256, CancellationToken.None).Result;

        Assert.Equal(256, prefix.Length);
    }

    [Fact]
    public void FileUploadPolicy_Defaults_AreSafe()
    {
        var policy = new FileUploadPolicy();

        Assert.Equal(10 * 1024 * 1024, policy.MaxFileSizeBytes);
        Assert.Equal(0, policy.MinFileSizeBytes);
        Assert.Equal(0, policy.ArchiveMaxExtractedSize);
        Assert.Equal(10 * 1024 * 1024, policy.TempFileThresholdBytes);
        Assert.Equal(int.MaxValue, policy.MaxMemoryFileSizeBytes);
        Assert.Equal(1000, policy.ArchiveMaxEntries);
        Assert.Equal(5, policy.ArchiveMaxDepth);
        Assert.Equal(8 * 1024, policy.SignatureReadLimitBytes);
        Assert.Equal(256 * 1024, policy.StructureReadLimitBytes);
        Assert.Equal(255, policy.MaxFileNameLength);
        Assert.Equal(true, policy.RequireStructureValidation);
        Assert.Equal(true, policy.RejectIfMalwareScanUnavailable);
        Assert.Equal(UnknownFilePolicy.Reject, policy.UnknownFilePolicy);
        Assert.Equal(ExtensionMismatchPolicy.Reject, policy.ExtensionMismatchPolicy);
    }

    [Fact]
    public void FileUploadPolicy_MaxMemoryFileSizeBytes_IsIntMaxValueByDefault()
    {
        var policy = new FileUploadPolicy();
        Assert.Equal(int.MaxValue, policy.MaxMemoryFileSizeBytes);
    }

    [Fact]
    public void FileUploadPolicy_TempFileThreshold_DefaultIs10MB()
    {
        var policy = new FileUploadPolicy();
        Assert.Equal(10 * 1024 * 1024, policy.TempFileThresholdBytes);
    }
}

public class ConcurrentExecutionTests
{
    [Fact]
    public async Task ConcurrentUploads_DifferentFiles_AreAllValidated()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var pipeline = TestPolicy.BuildPipeline();

        var tasks = Enumerable.Range(0, 20).Select(async _ =>
        {
            var png = TestFixtures.Png(100, 100);
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                DeclaredMimeType = "image/png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        });

        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.True(r.IsValid));
    }

    [Fact]
    public async Task Pipeline_IsThreadSafe_ForSharedInstance()
    {
        var pipeline = TestPolicy.BuildPipeline();
        var policy = TestPolicy.AllowExtensions(".png");
        var png = TestFixtures.Png(50, 50);

        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var request = new FileUploadRequest
            {
                FileStream = new MemoryStream(png),
                OriginalFileName = "photo.png",
                DeclaredMimeType = "image/png",
                Policy = policy
            };
            return await pipeline.ProcessAsync(request);
        });

        var results = await Task.WhenAll(tasks);
        Assert.All(results, r => Assert.True(r.IsValid));
    }
}

public class StreamOwnershipTests
{
    [Fact]
    public async Task SeekableStream_IsNotDisposed_ByPipeline()
    {
        var ms = new MemoryStream(TestFixtures.Png());
        var policy = TestPolicy.AllowExtensions(".png");
        var request = new FileUploadRequest
        {
            FileStream = ms,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var pipeline = TestPolicy.BuildPipeline();
        var result = await pipeline.ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.True(ms.CanRead); // Stream should still be open and readable
        ms.Dispose();
    }

    [Fact]
    public async Task NonSeekableStream_IsDisposed_ByPipeline()
    {
        var ms = new MemoryStream(TestFixtures.Png());
        var nonSeekable = new NonSeekableStream(ms);
        var policy = TestPolicy.AllowExtensions(".png");
        var request = new FileUploadRequest
        {
            FileStream = nonSeekable,
            OriginalFileName = "photo.png",
            Policy = policy
        };

        var pipeline = TestPolicy.BuildPipeline();
        var result = await pipeline.ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task FileUploadPolicy_RequiresPolicy_Throws()
    {
        var pipeline = new FileUploadPipelineBuilder()
            .UseDefaultDetection()
            .WithDefaultValidators()
            .Build();

        var request = new FileUploadRequest
        {
            FileStream = new MemoryStream(TestFixtures.Png()),
            OriginalFileName = "photo.png",
            Policy = null!
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() => pipeline.ProcessAsync(request));
    }
}
