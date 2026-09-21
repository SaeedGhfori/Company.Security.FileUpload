namespace Company.Security.FileUpload.Detection;

public static class ExtensionResolver
{
    private static readonly HashSet<string> InvalidExtensionChars = new()
    {
        "..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\0"
    };

    public static string Normalize(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return string.Empty;

        var name = DecodeUrlEncoding(fileName);
        name = name.Trim();
        var lastDot = name.LastIndexOf('.');
        if (lastDot < 0 || lastDot == name.Length - 1)
            return string.Empty;

        return name[(lastDot + 1)..].ToLowerInvariant();
    }

    public static bool IsValidExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
            return false;

        extension = DecodeUrlEncoding(extension);

        if (extension.Length > 32)
            return false;

        if (InvalidExtensionChars.Any(c => extension.Contains(c, StringComparison.Ordinal)))
            return false;

        if (extension.Any(c => char.IsWhiteSpace(c)))
            return false;

        return extension.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');
    }

    public static IReadOnlyList<string> GetAllExtensions(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return Array.Empty<string>();

        var name = DecodeUrlEncoding(fileName);
        name = name.Trim();
        var parts = name.Split('.');
        if (parts.Length < 2)
            return Array.Empty<string>();

        return parts[1..].Select(p => p.ToLowerInvariant()).ToArray();
    }

    public static bool HasMultipleExtensions(string fileName)
    {
        return GetAllExtensions(fileName).Count > 1;
    }

    public static bool IsEquivalentExtension(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;

        var aNorm = NormalizeAlias(a);
        var bNorm = NormalizeAlias(b);
        return string.Equals(aNorm, bNorm, StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikePathTraversal(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return false;

        var decoded = DecodeUrlEncoding(fileName);

        if (decoded.Contains("..", StringComparison.Ordinal))
            return true;

        if (decoded.Contains("/", StringComparison.Ordinal) && !IsWindowsAbsolutePath(decoded))
            return true;

        if (decoded.IndexOf('\\') >= 0)
            return true;

        if (decoded.Contains(':', StringComparison.Ordinal))
            return true;

        if (decoded.Contains('\0'))
            return true;

        if (decoded.Contains("%2e", StringComparison.OrdinalIgnoreCase)
            || decoded.Contains("%2e%2e", StringComparison.OrdinalIgnoreCase))
            return true;

        if (decoded.Contains("%00", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    public static bool IsReservedFileName(string fileName)
    {
        var name = DecodeUrlEncoding(fileName).ToUpperInvariant();
        return name is "CON" or "PRN" or "AUX" or "NUL"
            || name.StartsWith("CON.", StringComparison.Ordinal)
            || name.StartsWith("PRN.", StringComparison.Ordinal)
            || name.StartsWith("AUX.", StringComparison.Ordinal)
            || name.StartsWith("NUL.", StringComparison.Ordinal)
            || name.StartsWith("COM", StringComparison.Ordinal)
            || name.StartsWith("LPT", StringComparison.Ordinal);
    }

    public static string DecodeUrlEncoding(string input)
    {
        if (!input.Contains('%'))
            return input;

        try
        {
            return Uri.EscapeDataString(Uri.UnescapeDataString(input));
        }
        catch
        {
            return input;
        }
    }

    private static string NormalizeAlias(string extension)
    {
        var e = extension.ToLowerInvariant().TrimStart('.');
        return e switch
        {
            "jpeg" => "jpg",
            "jpg" => "jpeg",
            "tif" => "tiff",
            "tiff" => "tif",
            "htm" => "html",
            "html" => "htm",
            "mpeg" => "mpg",
            "mpg" => "mpeg",
            _ => e
        };
    }

    private static bool IsWindowsAbsolutePath(string fileName)
    {
        return fileName.Length >= 3
            && char.IsLetter(fileName[0])
            && fileName[1] == ':'
            && (fileName[2] == '\\' || fileName[2] == '/');
    }
}
