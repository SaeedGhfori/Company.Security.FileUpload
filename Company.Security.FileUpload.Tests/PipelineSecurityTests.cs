using System.Collections.ObjectModel;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Pipeline;
using Company.Security.FileUpload.Tests;
using Company.Security.FileUpload.Validation;

namespace Company.Security.FileUpload.Tests;

public class PipelineSecurityTests
{
    private static FileUploadPipeline NewPipeline() => TestPolicy.BuildPipeline();

    // OWASP: File size limits / Validate actual file type (allowlist)
    [Fact]
    public async Task ValidJpeg_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".jpg");
        var request = TestFixtures.Request(TestFixtures.Jpeg(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("JPEG", result.DetectedFileType!.FormatName);
    }

    // OWASP: Validate actual file type (magic bytes)
    [Fact]
    public async Task ValidPng_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("PNG", result.DetectedFileType!.FormatName);
    }

    // OWASP: Extension mismatch / Do not trust the file extension
    [Fact]
    public async Task PngBytesNamedJpg_Rejected_ExtensionMismatch()
    {
        var policy = TestPolicy.AllowExtensions(".png", ".jpg");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMismatch);
    }

    // OWASP: Extension mismatch / Binary executable masquerading as image
    [Fact]
    public async Task JpegBytesNamedExe_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".jpg");
        var request = TestFixtures.Request(TestFixtures.Jpeg(), "payload.exe", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code is FileValidationErrorCode.ExtensionMismatch
            or FileValidationErrorCode.ExtensionNotAllowed);
    }

    // OWASP: File size limits (reject empty)
    [Fact]
    public async Task EmptyFile_Rejected_FileEmpty()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(Array.Empty<byte>(), "empty.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileEmpty);
    }

    // OWASP: File structure validation
    [Fact]
    public async Task TruncatedFile_Rejected_StructureInvalid()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.TruncatedPng(), "broken.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    // OWASP: File structure validation (fake signature with broken payload)
    [Fact]
    public async Task FakeSignature_BrokenStructure_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".webp");
        var request = TestFixtures.Request(TestFixtures.FakeRiifWebp(), "forged.webp", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    // OWASP: File size limits
    [Fact]
    public async Task FileTooLarge_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { MaxFileSizeBytes = 100 };
        var request = TestFixtures.Request(TestFixtures.Png(400, 400), "big.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTooLarge);
    }

    // OWASP: Safe file naming (control characters)
    [Fact]
    public async Task FileNameWithControlChars_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "bad\u0001photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNameContainsInvalidCharacters);
    }

    // OWASP: Prevent path traversal
    [Fact]
    public async Task PathTraversalFileName_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "..\\..\\windows\\evil.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNamePathTraversalDetected);
    }

    // OWASP: Allowlist extensions / multi-extension control
    [Fact]
    public async Task MultipleExtension_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".gz");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("a.txt"), "archive.tar.gz", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMultipleDetected);
    }

    // OWASP: Files without extension control
    [Fact]
    public async Task NoExtension_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMissing);
    }

    // OWASP: Unknown file handling
    [Fact]
    public async Task UnknownFile_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.RandomUnknown(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTypeUnknown);
    }

    // OWASP: Do not trust the Content-Type / MIME mismatch
    [Fact]
    public async Task FakeMime_Rejected_MimeMismatch()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy, mimeType: "text/plain");
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.MimeMismatchWithSignature);
    }

    // OWASP: File structure validation (valid signature, corrupted body)
    [Fact]
    public async Task SignatureValidButStructureCorrupt_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.PngWithBrokenIhdrLength(), "broken.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    // OWASP: Archive zip-slip / path traversal inside archive
    [Fact]
    public async Task ZipWithMaliciousEntryPath_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("../escape/evil.txt"), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipPathTraversal);
    }

    // OWASP: Archive entry count control (resource limits)
    [Fact]
    public async Task ZipTooManyEntries_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { ArchiveMaxEntries = 10 };
        var manyNames = Enumerable.Range(0, 50).Select(i => $"file{i}.txt").ToArray();
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries(manyNames), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipTooManyEntries);
    }

    // OWASP: Zip bomb detection (compression ratio limit)
    [Fact]
    public async Task ZipBomb_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipBomb(), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipBombDetected);
    }

    // OWASP: Nested archive depth control (resource limits)
    [Fact]
    public async Task ZipNestedTooDeep_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { ArchiveMaxDepth = 5 };
        var request = TestFixtures.Request(TestFixtures.ZipNestedDepth(8), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipDepthExceeded);
    }

    // OWASP: Image dimension limits
    [Fact]
    public async Task ImageTooLargeDimensions_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { MaxImageWidth = 100, MaxImageHeight = 100 };
        var request = TestFixtures.Request(TestFixtures.Png(1500, 1500), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageDimensionExceeded);
    }

    // OWASP: Pixel bomb / image resource limits
    [Fact]
    public async Task ImagePixelCountExceeded_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { MaxPixelCount = 50_000 };
        var request = TestFixtures.Request(TestFixtures.Png(1000, 1000), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImagePixelCountExceeded);
    }

    // OWASP: Archive controls (path traversal should exist even when valid zip otherwise)
    [Fact]
    public async Task NestedZipLegit_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { ArchiveMaxDepth = 10 };
        var request = TestFixtures.Request(TestFixtures.ZipNestedDepth(2), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    // Clean archive accepted
    [Fact]
    public async Task CleanZip_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("a.txt", "b.txt"), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    // OWASP: Resource limits / cancellation
    [Fact]
    public async Task CancellationRequested_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NewPipeline().ProcessAsync(request, cts.Token));
    }
}