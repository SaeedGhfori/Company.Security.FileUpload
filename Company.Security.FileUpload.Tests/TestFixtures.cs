using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Tests;

internal static class TestFixtures
{
    private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

    public static byte[] Png(int width = 1, int height = 1)
    {
        var ihdr = new byte[13];
        WriteBe32(ihdr, 0, width);
        WriteBe32(ihdr, 4, height);
        ihdr[8] = 8;
        ihdr[9] = 6;
        ihdr[10] = 0;
        ihdr[11] = 0;
        ihdr[12] = 0;

        var rowStride = 1 + width * 4;
        var raw = new byte[rowStride * height];
        for (var row = 0; row < height; row++)
        {
            var scanlineStart = row * rowStride;
            for (var i = scanlineStart + 1; i < scanlineStart + rowStride; i += 4)
            {
                raw[i] = 0xFF;
                raw[i + 1] = 0x80;
                raw[i + 2] = 0x40;
                raw[i + 3] = 0xFF;
            }
        }

        return Concat(
            PngSignature,
            Chunk("IHDR", ihdr),
            Chunk("IDAT", ZlibCompress(raw)),
            Chunk("IEND", Array.Empty<byte>()));
    }

    public static byte[] PngWithBrokenIhdrLength()
    {
        var ihdr = new byte[13];
        WriteBe32(ihdr, 0, 1);
        WriteBe32(ihdr, 4, 1);
        ihdr[8] = 8;
        ihdr[9] = 6;

        var result = new List<byte>(PngSignature);
        result.AddRange(BitConverter.GetBytes(99L).Reverse().ToArray());
        result.AddRange(Encoding.ASCII.GetBytes("IHDR"));
        result.AddRange(ihdr);
        result.AddRange(Crc32(Concat(Encoding.ASCII.GetBytes("IHDR"), ihdr)));
        result.AddRange(Chunk("IEND", Array.Empty<byte>()));
        return result.ToArray();
    }

    public static byte[] TruncatedPng()
    {
        var full = Png(1, 1);
        return full.AsSpan(0, 12).ToArray();
    }

    public static byte[] Jpeg(int width = 1, int height = 1)
    {
        var buf = new MemoryStream();
        buf.WriteByte(0xFF);
        buf.WriteByte(0xD8);

        WriteSegment(buf, 0xE0, Concat(
            Encoding.ASCII.GetBytes("JFIF\0"),
            new byte[] { 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00 }));

        WriteSegment(buf, 0xDB, Concat(new byte[] { 0x00 }, StandardLuminanceQuantTable));

        var sof = new List<byte>
        {
            0x08,
            (byte)(height >> 8), (byte)height,
            (byte)(width >> 8), (byte)width,
            0x01,
            0x01, 0x11, 0x00
        };
        WriteSegment(buf, 0xC0, sof.ToArray());

        WriteSegment(buf, 0xC4, Concat(new byte[] { 0x00 }, StandardHuffmanBitsDcLuma, StandardHuffmanValuesDcLuma));
        WriteSegment(buf, 0xC4, Concat(new byte[] { 0x10 }, StandardHuffmanBitsAcLuma, StandardHuffmanValuesAcLuma));

        WriteSegment(buf, 0xDA, new byte[]
        {
            0x01,
            0x01, 0x00,
            0x00, 0x3F, 0x00
        });

        buf.WriteByte(0x2B);

        buf.WriteByte(0xFF);
        buf.WriteByte(0xD9);

        return buf.ToArray();
    }

    public static byte[] Gif1x1()
    {
        var buf = new MemoryStream();
        buf.Write(Encoding.ASCII.GetBytes("GIF89a"));
        buf.Write(new byte[] { 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00 });
        buf.Write(new byte[] { 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00 });
        buf.WriteByte(0x02);
        buf.Write(new byte[] { 0x02, 0x02, 0x44, 0x01, 0x00 });
        buf.WriteByte(0x00);
        buf.WriteByte(0x3B);
        return buf.ToArray();
    }

    public static byte[] Bmp1x1()
    {
        var rowSize = 4;
        var pixelData = new byte[rowSize];
        pixelData[0] = 0x00;
        pixelData[1] = 0x00;
        pixelData[2] = 0xFF;
        pixelData[3] = 0x00;

        var pixelOffset = 54;
        var fileSize = pixelOffset + pixelData.Length;

        var buf = new MemoryStream();
        buf.Write(Encoding.ASCII.GetBytes("BM"));
        buf.Write(BitConverter.GetBytes(fileSize));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(pixelOffset));
        buf.Write(BitConverter.GetBytes(40));
        buf.Write(BitConverter.GetBytes(1));
        buf.Write(BitConverter.GetBytes(1));
        buf.Write(BitConverter.GetBytes(1));
        buf.Write(BitConverter.GetBytes(24));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(BitConverter.GetBytes(0));
        buf.Write(pixelData);
        return buf.ToArray();
    }

    public static byte[] WebpLossless(int width, int height)
    {
        var buf = new MemoryStream();
        buf.Write(Encoding.ASCII.GetBytes("RIFF"));
        buf.Write(BitConverter.GetBytes(20 + 12L)); // RIFF size placeholder (webp chunk small)
        buf.Write(Encoding.ASCII.GetBytes("WEBP"));
        buf.Write(Encoding.ASCII.GetBytes("VP8L"));
        buf.Write(BitConverter.GetBytes(4));
        buf.Write(new byte[] { 0x2F, 0x00, 0x00, 0x00, 0x00 });

        var bits = (uint)((width - 1) & 0x3FFF) | (uint)(((height - 1) & 0x3FFF) << 14);
        buf.Position = 20;
        buf.Write(BitConverter.GetBytes(0x2F));
        buf.Write(BitConverter.GetBytes(bits));
        buf.Position = 0;
        var result = buf.ToArray();

        var riffSize = result.Length - 8;
        var sizeBytes = BitConverter.GetBytes((int)riffSize);
        Array.Copy(sizeBytes, 0, result, 4, 4);
        return result;
    }

    public static byte[] Pdf()
    {
        return Encoding.ASCII.GetBytes(
            "%PDF-1.4\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
            "xref\n0 3\n0000000000 65535 f \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n");
    }

    public static byte[] PdfWithoutEof()
    {
        return Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj\n<<>>\nendobj\n");
    }

    public static byte[] PdfFakeHeader()
    {
        return Encoding.ASCII.GetBytes("This is not a PDF at all, just text that starts with words.\n");
    }

    public static byte[] ZipWithEntries(params string[] entryNames)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var name in entryNames)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write("content for " + name);
            }
        }
        return ms.ToArray();
    }

    public static byte[] ZipWithNamedContent((string Name, string Content)[] entries)
    {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(content);
            }
        }
        return ms.ToArray();
    }

    public static byte[] Ooxml(string format)
    {
        var (contentType, documentPart) = format.ToLowerInvariant() switch
        {
            "docx" => ("wordprocessingml", "word/document.xml"),
            "xlsx" => ("spreadsheetml", "xl/workbook.xml"),
            "pptx" => ("presentationml", "ppt/presentation.xml"),
            _ => throw new ArgumentOutOfRangeException(nameof(format))
        };

        var contentTypesXml =
            $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            $"<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            $"<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
            $"<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
            $"<Override PartName=\"/{documentPart}\" ContentType=\"application/vnd.openxmlformats-officedocument.{contentType}.main+xml\"/>" +
            $"</Types>";

        return ZipWithNamedContent(new[]
        {
            ("[Content_Types].xml", contentTypesXml),
            ("_rels/.rels", "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>"),
            (documentPart, "<?xml version=\"1.0\"?><document xmlns=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><body/></document>")
        });
    }

    public static byte[] OoxmlWithMacro(string format = "docx")
    {
        var zipWithoutMacro = Ooxml(format);
        using var ms = new MemoryStream();
        using var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true);

        using (var src = new MemoryStream(zipWithoutMacro))
        using (var srcArchive = new ZipArchive(src, ZipArchiveMode.Read))
        {
            foreach (var entry in srcArchive.Entries)
            {
                var newEntry = archive.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                using var inStream = entry.Open();
                using var outStream = newEntry.Open();
                inStream.CopyTo(outStream);
            }
        }

        var macroEntry = archive.CreateEntry("word/vbaProject.bin", CompressionLevel.NoCompression);
        using (var writer = new StreamWriter(macroEntry.Open()))
        {
            writer.Write("FAKE-MACRO-CONTENT");
        }

        return ms.ToArray();
    }

    public static byte[] ZipBomb()
    {
        var payload = new byte[15 * 1024 * 1024];
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("bomb.bin", CompressionLevel.Fastest);
            using var es = entry.Open();
            es.Write(payload);
        }
        return ms.ToArray();
    }

    public static byte[] ZipNestedDepth(int depth)
    {
        var current = ZipWithEntries("file.txt");
        for (var i = 0; i < depth; i++)
        {
            using var ms = new MemoryStream();
            using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = archive.CreateEntry("nested.zip", CompressionLevel.Optimal);
                using var es = entry.Open();
                es.Write(current);
            }
            current = ms.ToArray();
        }
        return current;
    }

    public static byte[] ExeHeader()
    {
        return new byte[]
        {
            0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
            0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
            0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
            0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
    }

    public static byte[] RandomUnknown()
    {
        var rng = new Random(42);
        var data = new byte[4096];
        rng.NextBytes(data);
        return data;
    }

    public static byte[] FakeZipHeader()
    {
        var data = new byte[512];
        data[0] = 0x50;
        data[1] = 0x4B;
        data[2] = 0x03;
        data[3] = 0x04;
        new Random(7).NextBytes(data.AsSpan(4));
        return data;
    }

    public static byte[] FakeRiifWebp()
    {
        var data = new byte[512];
        Encoding.ASCII.GetBytes("RIFF").CopyTo(data, 0);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(4), 504);
        Encoding.ASCII.GetBytes("WEBP").CopyTo(data, 8);
        Encoding.ASCII.GetBytes("XXXX").CopyTo(data, 12);
        new Random(3).NextBytes(data.AsSpan(16));
        return data;
    }

    public static byte[] Mp4FtypHeader()
    {
        var data = new byte[1024];
        Encoding.ASCII.GetBytes("ftypisom").CopyTo(data, 4);
        return data;
    }

    public static byte[] UnknownBinaryWithJpgMagic()
    {
        var data = new byte[512];
        data[0] = 0xFF;
        data[1] = 0xD8;
        data[2] = 0xFF;
        new Random(11).NextBytes(data.AsSpan(3));
        return data;
    }

    public static FileUploadRequest Request(byte[] content, string fileName, FileUploadPolicy? policy = null, string? mimeType = null, long? declaredSize = null)
    {
        return new FileUploadRequest
        {
            FileStream = new MemoryStream(content),
            OriginalFileName = fileName,
            DeclaredMimeType = mimeType,
            DeclaredFileSize = declaredSize,
            Policy = policy ?? TestPolicy.Default
        };
    }

    private static void WriteSegment(Stream stream, byte marker, byte[] payload)
    {
        stream.WriteByte(0xFF);
        stream.WriteByte(marker);
        var length = payload.Length + 2;
        stream.WriteByte((byte)(length >> 8));
        stream.WriteByte((byte)length);
        stream.Write(payload);
    }

    private static byte[] Chunk(string type, byte[] data)
    {
        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes(data.Length).Reverse().ToArray());
        ms.Write(Encoding.ASCII.GetBytes(type));
        ms.Write(data);
        ms.Write(Crc32(Concat(Encoding.ASCII.GetBytes(type), data)));
        return ms.ToArray();
    }

    private static byte[] ZlibCompress(byte[] input)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionMode.Compress, leaveOpen: true))
        {
            zlib.Write(input);
        }
        return output.ToArray();
    }

    private static byte[] Crc32(byte[] data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
                crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xEDB88320u : 0);
        }
        crc ^= 0xFFFFFFFFu;
        return new[] { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        var result = new byte[arrays.Sum(a => a.Length)];
        var offset = 0;
        foreach (var a in arrays)
        {
            a.CopyTo(result, offset);
            offset += a.Length;
        }
        return result;
    }

    private static void WriteBe32(byte[] buffer, int offset, int value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)value;
    }

    private static readonly byte[] StandardLuminanceQuantTable =
    {
        16, 11, 10, 16, 24, 40, 51, 61,
        12, 12, 14, 19, 26, 58, 60, 55,
        14, 13, 16, 24, 40, 57, 69, 56,
        14, 17, 22, 29, 51, 87, 80, 62,
        18, 22, 37, 56, 68, 109, 103, 77,
        24, 35, 55, 64, 81, 104, 113, 92,
        49, 64, 78, 87, 103, 121, 120, 101,
        72, 92, 95, 98, 112, 100, 103, 99
    };

    private static readonly byte[] StandardHuffmanBitsDcLuma = { 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
    private static readonly byte[] StandardHuffmanValuesDcLuma = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    private static readonly byte[] StandardHuffmanBitsAcLuma =
    {
        0, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1
    };

    private static readonly byte[] StandardHuffmanValuesAcLuma =
    {
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
        0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
        0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
        0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
        0xF9, 0xFA
    };
}