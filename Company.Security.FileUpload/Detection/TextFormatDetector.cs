using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;
using System.Text;

namespace Company.Security.FileUpload.Detection;

public static class TextFormatDetector
{
    public const int MaxTextInspection = 4096;

    public static FileTypeInfo? Detect(ReadOnlySpan<byte> prefix)
    {
        if (!LooksLikeText(prefix))
            return null;

        var inspection = prefix.Length <= MaxTextInspection
            ? Encoding.UTF8.GetString(prefix)
            : Encoding.UTF8.GetString(prefix.Slice(0, MaxTextInspection));

        var trimmed = inspection.TrimStart('\uFEFF', ' ', '\t', '\r', '\n');

        if (trimmed.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("<", StringComparison.Ordinal))
        {
            if (trimmed.Contains("<svg", StringComparison.OrdinalIgnoreCase))
            {
                return new FileTypeInfo
                {
                    DetectedExtension = ".svg",
                    DetectedMimeType = "image/svg+xml",
                    Category = FileTypeCategory.Svg,
                    FormatName = "SVG",
                    HasValidSignature = true,
                    IsKnownFormat = true
                };
            }

            return new FileTypeInfo
            {
                DetectedExtension = ".xml",
                DetectedMimeType = "application/xml",
                Category = FileTypeCategory.Text,
                FormatName = "XML",
                HasValidSignature = true,
                IsKnownFormat = true
            };
        }

        var firstChar = trimmed.Length > 0 ? trimmed[0] : '\0';
        if (firstChar is '{' or '[')
        {
            return new FileTypeInfo
            {
                DetectedExtension = ".json",
                DetectedMimeType = "application/json",
                Category = FileTypeCategory.Text,
                FormatName = "JSON",
                HasValidSignature = true,
                IsKnownFormat = true
            };
        }

        var containsComma = inspection.Contains(',', StringComparison.Ordinal)
            && inspection.Contains('\n', StringComparison.Ordinal);

        return new FileTypeInfo
        {
            DetectedExtension = containsComma ? ".csv" : ".txt",
            DetectedMimeType = containsComma ? "text/csv" : "text/plain",
            Category = FileTypeCategory.Text,
            FormatName = containsComma ? "CSV" : "TEXT",
            HasValidSignature = true,
            IsKnownFormat = true
        };
    }

    private static bool LooksLikeText(ReadOnlySpan<byte> prefix)
    {
        var limit = Math.Min(prefix.Length, 1024);
        for (var i = 0; i < limit; i++)
        {
            var b = prefix[i];
            if (b == 0)
                return false;

            if (b < 0x09)
                return false;

            if (b is > 0x0D and < 0x20)
                return false;
        }

        return true;
    }
}