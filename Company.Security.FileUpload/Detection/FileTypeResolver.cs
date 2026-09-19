using System.Buffers;
using System.IO.Compression;
using System.Text;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Detection;

public sealed class FileTypeResolver : IFileDetectionService
{
    private const int DefaultSignatureReadLimit = 16 * 1024;
    private const long MaxOoxmlInspectionFileSize = 256 * 1024 * 1024;
    private const int MaxContentTypesRead = 64 * 1024;

    private static readonly byte[] RiffHeader = { 0x52, 0x49, 0x46, 0x46 };
    private static readonly byte[] EbmlHeader = { 0x1A, 0x45, 0xDF, 0xA3 };
    private static readonly byte[] FtypHeader = { 0x66, 0x74, 0x79, 0x70 };
    private static readonly byte[] ZipLocalHeader = { 0x50, 0x4B, 0x03, 0x04 };
    private static readonly byte[] OleStorageHeader = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

    private readonly FileSignatureDetector _detector;

    public FileTypeResolver()
        : this(new FileSignatureDetector())
    {
    }

    public FileTypeResolver(FileSignatureDetector detector)
    {
        ArgumentNullException.ThrowIfNull(detector);
        _detector = detector;
    }

    public async Task<FileTypeInfo> DetectAsync(
        Stream stream,
        string? declaredExtension = null,
        string? declaredMimeType = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable.", nameof(stream));

        var prefix = await FileSignatureDetector.ReadPrefixAsync(stream, DefaultSignatureReadLimit, cancellationToken);

        var containerSignature = TryDetectContainerRefined(stream, prefix, cancellationToken);

        if (containerSignature is not null)
        {
            return BuildFromSignature(containerSignature, declaredExtension, declaredMimeType, prefix);
        }

        var catalogSignature = await _detector.DetectAsync(stream, prefix, DefaultSignatureReadLimit, cancellationToken);
        if (catalogSignature is not null)
        {
            return BuildFromSignature(catalogSignature, declaredExtension, declaredMimeType, prefix);
        }

        var textDetected = TextFormatDetector.Detect(prefix);
        if (textDetected is not null)
        {
            return Finalize(textDetected, declaredExtension, declaredMimeType);
        }

        return BuildUnknown(declaredExtension, declaredMimeType);
    }

    private static FileSignature? TryDetectContainerRefined(Stream stream, byte[] prefix, CancellationToken cancellationToken)
    {
        if (prefix.Length >= 12 && prefix.AsSpan(0, 4).SequenceEqual(RiffHeader))
        {
            var formType = Encoding.ASCII.GetString(prefix, 8, 4);
            return formType switch
            {
                "AVI " => NewContainerSignature("AVI", FileTypeCategory.Video, ".avi", "video/x-msvideo", prefix, 0, 12),
                "WAVE" => NewContainerSignature("WAV", FileTypeCategory.Audio, ".wav", "audio/wav", prefix, 0, 12),
                "WEBP" => NewContainerSignature("WEBP", FileTypeCategory.Image, ".webp", "image/webp", prefix, 0, 12),
                _ => null
            };
        }

        if (prefix.Length >= 4 && prefix.AsSpan(0, 4).SequenceEqual(EbmlHeader))
        {
            var inspectEnd = Math.Min(prefix.Length, 512);
            var headerText = Encoding.ASCII.GetString(prefix, 0, inspectEnd);

            return headerText.Contains("webm", StringComparison.OrdinalIgnoreCase)
                ? NewContainerSignature("WEBM", FileTypeCategory.Video, ".webm", "video/webm", prefix, 0, 4)
                : NewContainerSignature("MKV", FileTypeCategory.Video, ".mkv", "video/x-matroska", prefix, 0, 4);
        }

        if (prefix.Length >= 12 && prefix.AsSpan(4, 4).SequenceEqual(FtypHeader))
        {
            var brand = Encoding.ASCII.GetString(prefix, 8, 4).TrimEnd(' ', '\0');
            var isMov = brand.StartsWith("qt", StringComparison.OrdinalIgnoreCase);

            return NewContainerSignature(
                isMov ? "MOV" : "MP4",
                FileTypeCategory.Video,
                isMov ? ".mov" : ".mp4",
                isMov ? "video/quicktime" : "video/mp4",
                prefix, 0, 12);
        }

        if (prefix.Length >= 4 && prefix.AsSpan(0, 4).SequenceEqual(ZipLocalHeader))
        {
            return TryDetectZipContainer(stream, cancellationToken);
        }

        if (prefix.Length >= 8 && prefix.AsSpan(0, 8).SequenceEqual(OleStorageHeader))
        {
            return TryDetectOleStorageType(prefix);
        }

        return null;
    }

    private static FileSignature NewContainerSignature(string format, FileTypeCategory category, string extension, string mime, byte[] prefix, int offset, int length)
    {
        return new FileSignature
        {
            FormatName = format,
            Category = category,
            Extension = extension,
            MimeType = mime,
            Signature = prefix.AsSpan(offset, Math.Min(length, prefix.Length)).ToArray(),
            Offset = offset,
            Priority = 100
        };
    }

    private static FileSignature? TryDetectZipContainer(Stream stream, CancellationToken cancellationToken)
    {
        if (!stream.CanSeek || stream.Length > MaxOoxmlInspectionFileSize)
            return null;

        var originalPosition = stream.Position;

        try
        {
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

            var contentTypes = ReadEntryPrefix(archive, "[Content_Types].xml", MaxContentTypesRead);
            if (contentTypes is null || contentTypes.Length == 0)
                return null;

            var xml = Encoding.UTF8.GetString(contentTypes);

            if (xml.Contains("wordprocessingml", StringComparison.OrdinalIgnoreCase))
            {
                return new FileSignature { FormatName = "DOCX", Category = FileTypeCategory.Office, Extension = ".docx", MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Priority = 100 };
            }

            if (xml.Contains("spreadsheetml", StringComparison.OrdinalIgnoreCase))
            {
                return new FileSignature { FormatName = "XLSX", Category = FileTypeCategory.Office, Extension = ".xlsx", MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", Priority = 100 };
            }

            if (xml.Contains("presentationml", StringComparison.OrdinalIgnoreCase))
            {
                return new FileSignature { FormatName = "PPTX", Category = FileTypeCategory.Office, Extension = ".pptx", MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation", Priority = 100 };
            }

            return null;
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = originalPosition;
        }
    }

    private static byte[]? ReadEntryPrefix(ZipArchive archive, string entryName, int maxBytes)
    {
        var entry = archive.GetEntry(entryName)
            ?? archive.Entries.FirstOrDefault(e => string.Equals(e.FullName, entryName, StringComparison.OrdinalIgnoreCase));

        if (entry is null)
            return null;

        using var entryStream = entry.Open();
        using var memory = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(maxBytes, 8192));
        var readTotal = 0;

        try
        {
            while (readTotal < maxBytes)
            {
                var read = entryStream.Read(buffer, 0, Math.Min(buffer.Length, maxBytes - readTotal));
                if (read == 0)
                    break;
                memory.Write(buffer, 0, read);
                readTotal += read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return memory.ToArray();
    }

    private static FileSignature? TryDetectOleStorageType(byte[] prefix)
    {
        var inspect = (int)Math.Min(prefix.Length, 8192);
        var ascii = Encoding.ASCII.GetString(prefix, 0, inspect);

        if (ascii.Contains("WordDocument", StringComparison.Ordinal))
        {
            return NewContainerSignature("DOC", FileTypeCategory.Document, ".doc", "application/msword", prefix, 0, 8);
        }

        if (ascii.Contains("Workbook", StringComparison.Ordinal))
        {
            return NewContainerSignature("XLS", FileTypeCategory.Document, ".xls", "application/vnd.ms-excel", prefix, 0, 8);
        }

        if (ascii.Contains("PowerPoint Document", StringComparison.Ordinal))
        {
            return NewContainerSignature("PPT", FileTypeCategory.Document, ".ppt", "application/vnd.ms-powerpoint", prefix, 0, 8);
        }

        return NewContainerSignature("OLE-CFB", FileTypeCategory.Binary, ".doc", "application/x-ole-storage", prefix, 0, 8);
    }

    private static FileTypeInfo BuildFromSignature(FileSignature signature, string? declaredExtension, string? declaredMimeType, byte[] prefix)
    {
        var matchedBytes = signature.Signature.Length > 0
            ? signature.Signature.ToArray()
            : Array.Empty<byte>();

        return Finalize(new FileTypeInfo
        {
            DetectedExtension = signature.Extension,
            DetectedMimeType = signature.MimeType,
            Category = signature.Category,
            FormatName = signature.FormatName,
            HasValidSignature = true,
            IsKnownFormat = true,
            MatchedSignatureOffset = signature.Offset,
            MatchedSignatureBytes = matchedBytes
        }, declaredExtension, declaredMimeType);
    }

    private static FileTypeInfo Finalize(FileTypeInfo detected, string? declaredExtension, string? declaredMimeType, bool? extensionMatchOverride = null)
    {
        var match = extensionMatchOverride
            ?? (string.IsNullOrEmpty(declaredExtension)
                ? true
                : ExtensionResolver.IsEquivalentExtension(declaredExtension, detected.DetectedExtension));

        return detected with
        {
            DeclaredExtension = declaredExtension ?? string.Empty,
            DeclaredMimeType = declaredMimeType ?? string.Empty,
            ExtensionMatchesSignature = match
        };
    }

    private static FileTypeInfo BuildUnknown(string? declaredExtension, string? declaredMimeType)
    {
        return new FileTypeInfo
        {
            DetectedExtension = string.Empty,
            DetectedMimeType = string.Empty,
            Category = FileTypeCategory.Unknown,
            FormatName = "UNKNOWN",
            HasValidSignature = false,
            IsKnownFormat = false,
            DeclaredExtension = declaredExtension ?? string.Empty,
            DeclaredMimeType = declaredMimeType ?? string.Empty,
            ExtensionMatchesSignature = false
        };
    }
}