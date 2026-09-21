using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Extensions;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Tests;

public class PipelineSecurityTests
{
    private static IFileUploadPipeline NewPipeline() => TestPolicy.BuildPipeline();

    [Fact]
    public async Task ValidJpeg_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".jpg");
        var request = TestFixtures.Request(TestFixtures.Jpeg(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("JPEG", result.DetectedFileType!.FormatName);
    }

    [Fact]
    public async Task ValidPng_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("PNG", result.DetectedFileType!.FormatName);
    }

    [Fact]
    public async Task PngBytesNamedJpg_Rejected_ExtensionMismatch()
    {
        var policy = TestPolicy.AllowExtensions(".png", ".jpg");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMismatch);
    }

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

    [Fact]
    public async Task EmptyFile_Rejected_FileEmpty()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(Array.Empty<byte>(), "empty.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileEmpty);
    }

    [Fact]
    public async Task TruncatedFile_Rejected_StructureInvalid()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.TruncatedPng(), "broken.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    [Fact]
    public async Task FakeSignature_BrokenStructure_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".webp");
        var request = TestFixtures.Request(TestFixtures.FakeRiifWebp(), "forged.webp", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    [Fact]
    public async Task FileTooLarge_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { FileSizes = new FileSizes { MaxFileSizeBytes = 100 } };
        var request = TestFixtures.Request(TestFixtures.Png(400, 400), "big.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTooLarge);
    }

    [Fact]
    public async Task FileNameWithControlChars_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "bad\u0001photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNameContainsInvalidCharacters);
    }

    [Fact]
    public async Task PathTraversalFileName_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "..\\..\\windows\\evil.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNamePathTraversalDetected);
    }

    [Fact]
    public async Task MultipleExtension_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".gz");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("a.txt"), "archive.tar.gz", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMultipleDetected);
    }

    [Fact]
    public async Task NoExtension_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMissing);
    }

    [Fact]
    public async Task UnknownFile_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.RandomUnknown(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileTypeUnknown);
    }

    [Fact]
    public async Task FakeMime_Rejected_MimeMismatch()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy, mimeType: "text/plain");
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.MimeMismatchWithSignature);
    }

    [Fact]
    public async Task SignatureValidButStructureCorrupt_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.PngWithBrokenIhdrLength(), "broken.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageInvalid);
    }

    [Fact]
    public async Task ZipWithMaliciousEntryPath_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("../escape/evil.txt"), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipPathTraversal);
    }

    [Fact]
    public async Task ZipTooManyEntries_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { Structures = new Structures { ArchiveMaxEntries = 10 } };
        var manyNames = Enumerable.Range(0, 50).Select(i => $"file{i}.txt").ToArray();
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries(manyNames), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipTooManyEntries);
    }

    [Fact]
    public async Task ZipBomb_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipBomb(), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipBombDetected);
    }

    [Fact]
    public async Task ZipNestedTooDeep_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { Structures = new Structures { ArchiveMaxDepth = 5 } };
        var request = TestFixtures.Request(TestFixtures.ZipNestedDepth(8), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureZipDepthExceeded);
    }

    [Fact]
    public async Task ImageTooLargeDimensions_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { Structures = new Structures { MaxImageWidth = 100, MaxImageHeight = 100 } };
        var request = TestFixtures.Request(TestFixtures.Png(1500, 1500), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImageDimensionExceeded);
    }

    [Fact]
    public async Task ImagePixelCountExceeded_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".png") with { Structures = new Structures { MaxPixelCount = 50_000 } };
        var request = TestFixtures.Request(TestFixtures.Png(1000, 1000), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.StructureImagePixelCountExceeded);
    }

    [Fact]
    public async Task NestedZipLegit_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".zip") with { Structures = new Structures { ArchiveMaxDepth = 10 } };
        var request = TestFixtures.Request(TestFixtures.ZipNestedDepth(2), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CleanZip_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".zip");
        var request = TestFixtures.Request(TestFixtures.ZipWithEntries("a.txt", "b.txt"), "archive.zip", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CancellationRequested_Throws()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var policy = TestPolicy.AllowExtensions(".png");
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NewPipeline().ProcessAsync(request, cts.Token));
    }

    [Fact]
    public async Task InvoicePdfExe_Rejected_MultipleExtensions()
    {
        var policy = TestPolicy.AllowExtensions(".pdf", ".exe");
        var request = TestFixtures.Request(TestFixtures.ExeHeader(), "invoice.pdf.exe", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMultipleDetected);
    }

    [Fact]
    public async Task InvoicePdf_ExeContent_Rejected_ExtensionMismatch()
    {
        var policy = TestPolicy.AllowExtensions(".pdf");
        var request = TestFixtures.Request(TestFixtures.ExeHeader(), "invoice.pdf", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMismatch);
    }

    [Fact]
    public async Task PathTraversal_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".aspx");
        var request = TestFixtures.Request(TestFixtures.RandomUnknown(), "../../../../wwroot/shell.aspx", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNamePathTraversalDetected);
    }

    [Fact]
    public async Task UrlEncodedPathTraversal_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".aspx");
        var request = TestFixtures.Request(TestFixtures.RandomUnknown(), "..%2F..%2F..%2Fwwroot%2Fshell.aspx", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNamePathTraversalDetected);
    }

    [Fact]
    public async Task NullByteInjection_Rejected()
    {
        var policy = TestPolicy.AllowExtensions(".pdf");
        var request = TestFixtures.Request(TestFixtures.Pdf(), "invoice.pdf\0.exe", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.FileNameContainsNullBytes);
    }

    [Fact]
    public async Task ValidPdf_Accepted()
    {
        var policy = TestPolicy.AllowExtensions(".pdf");
        var request = TestFixtures.Request(TestFixtures.Pdf(), "report.pdf", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
        Assert.Equal("PDF", result.DetectedFileType!.FormatName);
    }
}

public class FileExtensionRegistryTests
{
    [Fact]
    public void AllForCategory_NonEmpty_ForAllCategories()
    {
        var cats = new[]
        {
            FileTypeCategory.Image,
            FileTypeCategory.Video,
            FileTypeCategory.Audio,
            FileTypeCategory.Document,
            FileTypeCategory.Office,
            FileTypeCategory.Archive,
            FileTypeCategory.Binary,
            FileTypeCategory.Text,
            FileTypeCategory.Svg
        };

        foreach (var cat in cats)
        {
            var exts = FileExtensionRegistry.AllForCategory(cat);
            Assert.NotEmpty(exts);
        }
    }

    [Fact]
    public void IsRegistered_RecognizesCommon()
    {
        Assert.True(FileExtensionRegistry.IsRegistered(".png"));
        Assert.True(FileExtensionRegistry.IsRegistered("exe"));
        Assert.False(FileExtensionRegistry.IsRegistered(".notarealext"));
    }

    [Fact]
    public void ImageCategory_ContainsPngJpgWebp()
    {
        var exts = FileExtensionRegistry.AllForCategory(FileTypeCategory.Image);
        Assert.Contains("png", exts);
        Assert.Contains("jpg", exts);
        Assert.Contains("webp", exts);
    }
}

public class PerCallSubsetTests
{
    private static IFileUploadPipeline NewPipeline() => TestPolicy.BuildPipeline();

    [Fact]
    public async Task EmptyPolicyAllowlist_Png_Accepted()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task NoSubset_Png_Accepted()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Subset_Png_Match_Accepted()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [".png"] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Subset_JpgOnly_PngBytes_Rejected()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [".jpg"] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionNotAllowed);
    }

    [Fact]
    public async Task Subset_Mismatch_DeclaredVsDetected_Rejected()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [".jpg"] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.jpg", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == FileValidationErrorCode.ExtensionMismatch
            || e.Code == FileValidationErrorCode.ExtensionNotAllowed);
    }

    [Fact]
    public async Task Subset_DeclaredAndDetected_BothInSubset_Accepted()
    {
        var policy = TestPolicy.Default with { FileKinds = TestPolicy.Default.FileKinds with { AllowedExtensions = [".png", ".jpg"] } };
        var request = TestFixtures.Request(TestFixtures.Png(), "photo.png", policy);
        var result = await NewPipeline().ProcessAsync(request);

        Assert.True(result.IsValid);
    }
}