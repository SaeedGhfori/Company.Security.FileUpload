using Company.Security.FileUpload.Core.Constants;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Detection;

namespace Company.Security.FileUpload.Core.Extensions;

/// <summary>
/// Internal registry of all known file extensions keyed by <see cref="FileTypeCategory"/>.
/// Built from the full <see cref="FileSignatures.All"/> catalog plus expanded common extensions
/// so that every reasonable image/video/audio/document extension is covered per category.
/// </summary>
public static class FileExtensionRegistry
{
    /// <summary>
    /// Mapping from each <see cref="FileTypeCategory"/> to the set of normalized extensions
    /// (without leading dot, lowercase) that are recognized as valid for that category.
    /// </summary>
    public static readonly IReadOnlyDictionary<FileTypeCategory, IReadOnlySet<string>> ExtensionsByCategory = BuildExtensionsByCategory();

    /// <summary>
    /// Union of all extensions across every category.
    /// </summary>
    public static readonly IReadOnlySet<string> All = BuildAllExtensions();

    private static IReadOnlyDictionary<FileTypeCategory, IReadOnlySet<string>> BuildExtensionsByCategory()
    {
        var dict = new Dictionary<FileTypeCategory, HashSet<string>>();

        // Seed from FileSignatures.All — these are the extensions the detection system knows about.
        foreach (var sig in FileSignatures.All)
        {
            var ext = sig.Extension.TrimStart('.').ToLowerInvariant();
            if (!dict.TryGetValue(sig.Category, out var set))
            {
                set = new HashSet<string>();
                dict[sig.Category] = set;
            }
            set.Add(ext);
        }

        // Expand with common extensions per category so the registry is comprehensive:
        // every extension in a category should be allowed even if it has no magic bytes.
        var commonExtensions = new (FileTypeCategory Category, string[] Extensions)[]
        {
            (FileTypeCategory.Image, new[] { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".svg", ".ico", ".tga", ".exr", ".psd", ".rgb", ".bw", ".hdr" }),
            (FileTypeCategory.Video, new[] { ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv", ".flv", ".3gp", ".m4v", ".mpg", ".mpeg", ".f4v", ".rm", ".swf" }),
            (FileTypeCategory.Audio, new[] { ".mp3", ".wav", ".flac", ".ogg", ".oga", ".m4a", ".aac", ".wma", ".mid", ".midi", ".ac3", ".dts", ".aiff", ".au", ".ra" }),
            (FileTypeCategory.Document, new[] { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".tex" }),
            (FileTypeCategory.Office, new[] { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".wpd" }),
            (FileTypeCategory.Archive, new[] { ".zip", ".zipx", ".7z", ".rar", ".tar", ".gz", ".gzip", ".bz2", ".xz", ".ace", ".cab", ".iso", ".dmg", ".alz" }),
            (FileTypeCategory.Binary, new[] { ".exe", ".dll", ".so", ".dylib", ".ocx", ".sys", ".drv", ".scr", ".cpl", ".bin", ".dat", ".img" }),
            (FileTypeCategory.Text, new[] { ".txt", ".log", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".xml", ".csv", ".tsv", ".md", ".markdown", ".html", ".htm", ".css", ".js", ".ts", ".tsx", ".jsx", ".py", ".rb", ".pl", ".sh", ".bat", ".cmd", ".ps1" }),
            (FileTypeCategory.Svg, new[] { ".svg", ".svgz" })
        };

        foreach (var (cat, exts) in commonExtensions)
        {
            if (!dict.TryGetValue(cat, out var set))
            {
                set = new HashSet<string>();
                dict[cat] = set;
            }
            foreach (var e in exts)
                set.Add(e.TrimStart('.').ToLowerInvariant());
        }

        return dict.ToDictionary(kvp => kvp.Key, kvp => (IReadOnlySet<string>)kvp.Value);
    }

    private static IReadOnlySet<string> BuildAllExtensions()
    {
        var set = new HashSet<string>();
        foreach (var kvp in ExtensionsByCategory)
        {
            foreach (var ext in kvp.Value)
                set.Add(ext);
        }
        return set;
    }

    private static readonly IReadOnlySet<string> EmptySet = new HashSet<string>();

    /// <summary>
    /// Returns whether the given extension (with or without leading dot, case-insensitive) is registered in the catalog.
    /// </summary>
    public static bool IsRegistered(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
            return false;

        var norm = extension.Trim().TrimStart('.').ToLowerInvariant();
        return All.Contains(norm);
    }

    /// <summary>
    /// Returns whether the given extension is registered for the specified <see cref="FileTypeCategory"/>.
    /// </summary>
    public static bool IsCategoryRegistered(FileTypeCategory category, string extension)
    {
        if (string.IsNullOrWhiteSpace(extension))
            return false;

        var norm = extension.Trim().TrimStart('.').ToLowerInvariant();
        return ExtensionsByCategory.TryGetValue(category, out var set) && set.Contains(norm);
    }

    /// <summary>
    /// Returns all registered extensions for the given <see cref="FileTypeCategory"/>,
    /// or an empty set when the category has no registrations.
    /// </summary>
    public static IReadOnlySet<string> AllForCategory(FileTypeCategory category)
        => ExtensionsByCategory.TryGetValue(category, out var set) ? set : EmptySet;

    /// <summary>
    /// Resolves the effective allowed-extension set for a detected category:
    /// the configured allowlist (from policy or the per-call subset) when it is non-empty,
    /// otherwise every registered extension for that category.
    /// </summary>
    public static IReadOnlySet<string> ResolveEffectiveAllowed(FileTypeCategory category, IEnumerable<string>? configured)
    {
        if (configured is null)
            return AllForCategory(category);

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in configured)
        {
            var ext = raw?.Trim().TrimStart('.').ToLowerInvariant();
            if (!string.IsNullOrEmpty(ext))
                set.Add(ext);
        }

        return set.Count == 0 ? AllForCategory(category) : set;
    }

    /// <summary>
    /// Returns whether a (possibly dotted, case-mixed) extension is a member of the given
    /// registry/effective set. Matching is alias-aware (jpeg/jpg, tif/tiff, htm/html, mpeg/mpg).
    /// </summary>
    public static bool ContainsExtension(IReadOnlySet<string> set, string extension)
    {
        if (set is null || string.IsNullOrWhiteSpace(extension))
            return false;

        var norm = extension.Trim().TrimStart('.').ToLowerInvariant();
        if (set.Contains(norm))
            return true;

        foreach (var member in set)
        {
            if (ExtensionResolver.IsEquivalentExtension(member, norm))
                return true;
        }

        return false;
    }
}