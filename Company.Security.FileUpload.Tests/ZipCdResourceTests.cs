using System.IO.Compression;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Tests;

/// <summary>
/// Verifies that a malicious/synthetic ZIP with a huge central directory
/// cannot force eager ZipArchiveEntry allocation during detection. The guard
/// reads the declared entry count from the End-Of-Central-Directory record
/// without opening ZipArchive, so a zip advertising a huge count is refused
/// inspection before any ZipArchiveEntry is materialized.
/// </summary>
public class ZipCdResourceTests
{
    // Builds a ZIP whose central directory advertises far more entries than
    // actually exist, and where the EOCD entry-count can be read cheaply.
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

        // Rewrite the EOCD entry-count fields (offset +10 entries-on-disk,
        // +12 total entries) without adding real entries. The first EOCD from
        // the end is the short one.
        for (var i = bytes.Length - 4; i > 0; i--)
        {
            // Signature 0x06054b50, little-endian on disk
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

    // ---- RED tests for the EOCD entry-count guard ----
    // The guard reads the declared entry count from the End-Of-Central-Directory
    // record WITHOUT opening ZipArchive, so a zip that advertises a huge count
    // is refused inspection before any ZipArchiveEntry is allocated.

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
        // The EOCD entry-count field is a ushort, so the max representable value
        // is 65535. Advertise a huge-but-legal count above the detection guard.
        var bytes = AdvertiseManyEntries(60_000);
        using var stream = new MemoryStream(bytes);

        var count = FileTypeResolver.TryReadZipEntryCount(stream);

        Assert.Equal(60_000, count);
    }

    // ---- Behavior regression: detection still classifies such a file as ZIP ----

    [Fact]
    public async Task Detect_Advertises_65kEntries_StillClassifiesAsZip()
    {
        // Arrange — central directory claims 65,535 entries (max ushort),
        // but the file physically contains only 1.
        var bytes = AdvertiseManyEntries(ushort.MaxValue);
        using var stream = new MemoryStream(bytes);

        var resolver = new FileTypeResolver();

        // Act — detect only (no policy/validators)
        var detected = await resolver.DetectAsync(
            stream,
            declaredExtension: "zip",
            declaredMimeType: "application/zip",
            CancellationToken.None);

        // Assert — detection completes and identifies the ZIP format via the
        // catalog fallback; it must NOT have thrown or brought 65k entries into
        // memory by opening ZipArchive.
        Assert.NotNull(detected);
        Assert.Equal("ZIP", detected.FormatName);
    }

    [Fact]
    public async Task Pipeline_OoxmlAdvertisedHuge_StillClassifiesAsZip()
    {
        // A ZIP that both advertises >50k entries AND contains OOXML markers.
        // The guard must refuse the eager ZipArchive path (which would materialize
        // the huge count) and fall back to catalog classification as ZIP — the
        // same result a legit ZIP gets, without the allocation attack.
        var small = TestFixtures.Ooxml("docx");
        var bytes = new byte[small.Length];
        System.Array.Copy(small, bytes, small.Length);

        // Same EOCD patching as AdvertiseManyEntries, but preserve the OOXML
        // central directory so detection would otherwise go down the ZipArchive path.
        for (var i = bytes.Length - 4; i > 0; i--)
        {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4B && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06)
            {
                bytes[i + 10] = 0xFF; bytes[i + 11] = 0xFF;  // 65535 entries on disk
                bytes[i + 12] = 0xFF; bytes[i + 13] = 0xFF;  // 65535 total
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