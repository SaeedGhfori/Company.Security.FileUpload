using Company.Security.FileUpload.Detection;
using System.IO.Compression;

namespace Company.Security.FileUpload.Tests;

public class ZipCdResourceTests
{
    private static byte[] AdvertiseManyEntries(int advertised)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("a.txt");
            using var w = new StreamWriter(entry.Open());
            w.Write("x");
        }

        var bytes = ms.ToArray();

        for (var i = bytes.Length - 4; i > 0; i--)
        {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4B && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06)
            {
                bytes[i + 10] = (byte)(advertised & 0xFF);
                bytes[i + 11] = (byte)((advertised >> 8) & 0xFF);
                bytes[i + 12] = (byte)(advertised & 0xFF);
                bytes[i + 13] = (byte)((advertised >> 8) & 0xFF);
                break;
            }
        }

        return bytes;
    }

    [Fact]
    public void TryReadZipEntryCount_RealTwoEntryZip_ReturnsTwo()
    {
        var bytes = TestFixtures.ZipWithEntries("a.txt", "b.txt");
        using var stream = new MemoryStream(bytes);

        var count = FileTypeResolver.TryReadZipEntryCount(stream);

        Assert.Equal(2, count);
    }

    [Fact]
    public void TryReadZipEntryCount_AdvertisedHuge_ReturnsAdvertisedCount()
    {
        var bytes = AdvertiseManyEntries(60_000);
        using var stream = new MemoryStream(bytes);

        var count = FileTypeResolver.TryReadZipEntryCount(stream);

        Assert.Equal(60_000, count);
    }

    [Fact]
    public async Task Detect_Advertises_65kEntries_StillClassifiesAsZip()
    {
        var bytes = AdvertiseManyEntries(ushort.MaxValue);
        using var stream = new MemoryStream(bytes);

        var resolver = new FileTypeResolver();

        var detected = await resolver.DetectAsync(
            stream,
            declaredExtension: "zip",
            declaredMimeType: "application/zip",
            CancellationToken.None);

        Assert.NotNull(detected);
        Assert.Equal("ZIP", detected.FormatName);
    }

    [Fact]
    public async Task Pipeline_OoxmlAdvertisedHuge_StillClassifiesAsZip()
    {
        var small = TestFixtures.Ooxml("docx");
        var bytes = new byte[small.Length];
        System.Array.Copy(small, bytes, small.Length);

        for (var i = bytes.Length - 4; i > 0; i--)
        {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4B && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06)
            {
                bytes[i + 10] = 0xFF; bytes[i + 11] = 0xFF;
                bytes[i + 12] = 0xFF; bytes[i + 13] = 0xFF;
                break;
            }
        }

        using var stream = new MemoryStream(bytes);
        var resolver = new FileTypeResolver();

        var detected = await resolver.DetectAsync(
            stream,
            declaredExtension: "docx",
            declaredMimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            CancellationToken.None);

        Assert.NotNull(detected);
        Assert.Equal("ZIP", detected.FormatName);
    }
}