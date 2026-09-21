using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Detection;
using Company.Security.FileUpload.Tests;

namespace Company.Security.FileUpload.Tests;

public class DetectionTests
{
    private readonly FileTypeResolver _resolver = new();

    [Theory]
    [InlineData(0, "PNG", ".png", FileTypeCategory.Image)]
    [InlineData(1, "JPEG", ".jpg", FileTypeCategory.Image)]
    [InlineData(2, "GIF", ".gif", FileTypeCategory.Image)]
    [InlineData(3, "BMP", ".bmp", FileTypeCategory.Image)]
    [InlineData(4, "PDF", ".pdf", FileTypeCategory.Document)]
    public async Task Detect_KnownFormats_Correct(int fixtureIndex, string format, string extension, FileTypeCategory category)
    {
        var bytes = fixtureIndex switch
        {
            0 => TestFixtures.Png(),
            1 => TestFixtures.Jpeg(),
            2 => TestFixtures.Gif1x1(),
            3 => TestFixtures.Bmp1x1(),
            4 => TestFixtures.Pdf(),
            _ => throw new ArgumentOutOfRangeException()
        };

        using var stream = new MemoryStream(bytes);
        var result = await _resolver.DetectAsync(stream);

        Assert.True(result.IsKnownFormat);
        Assert.Equal(format, result.FormatName);
        Assert.Equal(extension, result.DetectedExtension);
        Assert.Equal(category, result.Category);
    }

    [Fact]
    public async Task Detect_OoxmlZip_ResolvesToXlsx()
    {
        using var stream = new MemoryStream(TestFixtures.Ooxml("xlsx"));
        var result = await _resolver.DetectAsync(stream, declaredExtension: ".xlsx");

        Assert.True(result.IsKnownFormat);
        Assert.Equal("XLSX", result.FormatName);
        Assert.Equal(FileTypeCategory.Office, result.Category);
        Assert.Equal(".xlsx", result.DetectedExtension);
    }

    [Fact]
    public async Task Detect_WebpLossless_Recognized()
    {
        using var stream = new MemoryStream(TestFixtures.WebpLossless(10, 10));
        var result = await _resolver.DetectAsync(stream);

        Assert.True(result.IsKnownFormat);
        Assert.Equal("WEBP", result.FormatName);
        Assert.Equal(".webp", result.DetectedExtension);
    }

    [Fact]
    public async Task Detect_Mp4Ftyp_Recognized()
    {
        using var stream = new MemoryStream(TestFixtures.Mp4FtypHeader());
        var result = await _resolver.DetectAsync(stream);

        Assert.True(result.IsKnownFormat);
        Assert.Equal("MP4", result.FormatName);
        Assert.Equal(".mp4", result.DetectedExtension);
        Assert.Equal(FileTypeCategory.Video, result.Category);
    }

    [Fact]
    public async Task Detect_DoesNotTrustDeclaredMime()
    {
        var png = TestFixtures.Png();

        using var stream = new MemoryStream(png);
        var result = await _resolver.DetectAsync(stream, declaredExtension: ".png", declaredMimeType: "application/x-ms-download");

        Assert.Equal("PNG", result.FormatName);
        Assert.Equal("image/png", result.DetectedMimeType);
    }

    [Fact]
    public async Task Detect_UnknownBinary_ReturnsUnknown()
    {
        using var stream = new MemoryStream(TestFixtures.RandomUnknown());
        var result = await _resolver.DetectAsync(stream, declaredExtension: ".xyz");

        Assert.False(result.IsKnownFormat);
        Assert.False(result.HasValidSignature);
        Assert.Equal(FileTypeCategory.Unknown, result.Category);
    }

    [Fact]
    public async Task Detect_PngBytesNamedJpg_FlagsMismatch()
    {
        using var stream = new MemoryStream(TestFixtures.Png());
        var result = await _resolver.DetectAsync(stream, declaredExtension: ".jpg");

        Assert.Equal("PNG", result.FormatName);
        Assert.False(result.ExtensionMatchesSignature);
        Assert.Equal(".jpg", result.DeclaredExtension);
    }

    [Fact]
    public async Task Detect_PngBytesNamedPng_NoMismatch()
    {
        using var stream = new MemoryStream(TestFixtures.Png());
        var result = await _resolver.DetectAsync(stream, declaredExtension: ".png");

        Assert.True(result.ExtensionMatchesSignature);
    }

    [Theory]
    [InlineData("photo.jpeg", "jpeg")]
    [InlineData("photo.JPG", "jpg")]
    [InlineData("photo.PnG", "png")]
    [InlineData("noext", "")]
    [InlineData("photo.tar.gz", "gz")]
    public void ExtensionResolver_Normalize_ReturnsLastExtension(string name, string expected)
    {
        Assert.Equal(expected, ExtensionResolver.Normalize(name));
    }

    [Theory]
    [InlineData("noext", false)]
    [InlineData("a.b.c", true)]
    [InlineData("name.tar.gz", true)]
    public void ExtensionResolver_MultipleExtensions_Detected(string name, bool expected)
    {
        Assert.Equal(expected, ExtensionResolver.HasMultipleExtensions(name));
    }

    [Theory]
    [InlineData("..\\..\\evil.jpg", true)]
    [InlineData("../evil.jpg", true)]
    [InlineData("C:\\windows\\evil.jpg", true)]
    [InlineData("evil.jpg", false)]
    [InlineData("normal file.jpg", false)]
    public void ExtensionResolver_PathTraversal_Detected(string name, bool expected)
    {
        Assert.Equal(expected, ExtensionResolver.LooksLikePathTraversal(name));
    }

    [Theory]
    [InlineData("CON", true)]
    [InlineData("nul.txt", true)]
    [InlineData("COM1.txt", true)]
    [InlineData("report.txt", false)]
    public void ExtensionResolver_ReservedNames_Detected(string name, bool expected)
    {
        Assert.Equal(expected, ExtensionResolver.IsReservedFileName(name));
    }
}