using System.Text;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Core.Constants;

public static class FileSignatures
{
    public static readonly byte[] ZipLocalHeader = { 0x50, 0x4B, 0x03, 0x04 };
    public static readonly byte[] ZipEmptyHeader = { 0x50, 0x4B, 0x05, 0x06 };
    public static readonly byte[] ZipSpannedHeader = { 0x50, 0x4B, 0x07, 0x08 };

    public static IReadOnlyList<FileSignature> All { get; } = BuildCatalog();

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private static IReadOnlyList<FileSignature> BuildCatalog()
    {
        var list = new List<FileSignature>
        {
            new() { FormatName = "JPEG", Category = FileTypeCategory.Image, Extension = ".jpg", MimeType = "image/jpeg", Signature = new byte[] { 0xFF, 0xD8, 0xFF }, Offset = 0, Priority = 10 },
            new() { FormatName = "PNG", Category = FileTypeCategory.Image, Extension = ".png", MimeType = "image/png", Signature = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, Offset = 0, Priority = 10 },
            new() { FormatName = "GIF", Category = FileTypeCategory.Image, Extension = ".gif", MimeType = "image/gif", Signature = new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }, Offset = 0, Priority = 10 },
            new() { FormatName = "GIF", Category = FileTypeCategory.Image, Extension = ".gif", MimeType = "image/gif", Signature = new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 }, Offset = 0, Priority = 10 },
            new() { FormatName = "BMP", Category = FileTypeCategory.Image, Extension = ".bmp", MimeType = "image/bmp", Signature = new byte[] { 0x42, 0x4D }, Offset = 0, Priority = 10 },
            new() { FormatName = "TIFF", Category = FileTypeCategory.Image, Extension = ".tiff", MimeType = "image/tiff", Signature = new byte[] { 0x49, 0x49, 0x2A, 0x00 }, Offset = 0, Priority = 10 },
            new() { FormatName = "TIFF", Category = FileTypeCategory.Image, Extension = ".tiff", MimeType = "image/tiff", Signature = new byte[] { 0x4D, 0x4D, 0x00, 0x2A }, Offset = 0, Priority = 10 },
            new() { FormatName = "WEBP", Category = FileTypeCategory.Image, Extension = ".webp", MimeType = "image/webp", TextPattern = "WEBP", TextPatternBytes = Encoding.ASCII.GetBytes("WEBP"), TextPatternSearchEnd = 32, Priority = 20 },
            new() { FormatName = "SVG", Category = FileTypeCategory.Svg, Extension = ".svg", MimeType = "image/svg+xml", TextPattern = "<svg", TextPatternBytes = Encoding.ASCII.GetBytes("<svg"), TextPatternSearchEnd = 512, Priority = 20 },

            new() { FormatName = "MKV", Category = FileTypeCategory.Video, Extension = ".mkv", MimeType = "video/x-matroska", Signature = new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }, Offset = 0, Priority = 20 },

            new() { FormatName = "MP3", Category = FileTypeCategory.Audio, Extension = ".mp3", MimeType = "audio/mpeg", Signature = new byte[] { 0x49, 0x44, 0x33 }, Offset = 0, Priority = 20 },
            new() { FormatName = "FLAC", Category = FileTypeCategory.Audio, Extension = ".flac", MimeType = "audio/flac", Signature = new byte[] { 0x66, 0x4C, 0x61, 0x43 }, Offset = 0, Priority = 20 },
            new() { FormatName = "OGG", Category = FileTypeCategory.Audio, Extension = ".ogg", MimeType = "audio/ogg", Signature = new byte[] { 0x4F, 0x67, 0x67, 0x53 }, Offset = 0, Priority = 20 },

            new() { FormatName = "PDF", Category = FileTypeCategory.Document, Extension = ".pdf", MimeType = "application/pdf", TextPattern = "%PDF-", TextPatternBytes = Encoding.ASCII.GetBytes("%PDF-"), TextPatternSearchEnd = 16, Priority = 30 },
            new() { FormatName = "XML", Category = FileTypeCategory.Text, Extension = ".xml", MimeType = "application/xml", TextPattern = "<?xml", TextPatternBytes = Encoding.ASCII.GetBytes("<?xml"), TextPatternSearchEnd = 128, Priority = 30 },

            new() { FormatName = "ZIP", Category = FileTypeCategory.Archive, Extension = ".zip", MimeType = "application/zip", Signature = ZipLocalHeader, Offset = 0, Priority = 30 },
            new() { FormatName = "ZIP-EMPTY", Category = FileTypeCategory.Archive, Extension = ".zip", MimeType = "application/zip", Signature = ZipEmptyHeader, Offset = 0, Priority = 30 },
            new() { FormatName = "7Z", Category = FileTypeCategory.Archive, Extension = ".7z", MimeType = "application/x-7z-compressed", Signature = new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, Offset = 0, Priority = 30 },
            new() { FormatName = "TAR", Category = FileTypeCategory.Archive, Extension = ".tar", MimeType = "application/x-tar", TextPattern = "ustar", TextPatternBytes = Encoding.ASCII.GetBytes("ustar"), TextPatternSearchEnd = 262, Priority = 30 },
            new() { FormatName = "GZIP", Category = FileTypeCategory.Archive, Extension = ".gz", MimeType = "application/gzip", Signature = new byte[] { 0x1F, 0x8B }, Offset = 0, Priority = 30 },

            new() { FormatName = "OLE-CFB", Category = FileTypeCategory.Binary, Extension = ".doc", MimeType = "application/x-ole-storage", Signature = new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, Offset = 0, Priority = 40 },
            new() { FormatName = "EXE", Category = FileTypeCategory.Binary, Extension = ".exe", MimeType = "application/x-msdownload", Signature = new byte[] { 0x4D, 0x5A }, Offset = 0, Priority = 40 },
            new() { FormatName = "RAR", Category = FileTypeCategory.Archive, Extension = ".rar", MimeType = "application/vnd.rar", Signature = new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, Offset = 0, Priority = 40 },
        };

        return list.AsReadOnly();
    }
}
