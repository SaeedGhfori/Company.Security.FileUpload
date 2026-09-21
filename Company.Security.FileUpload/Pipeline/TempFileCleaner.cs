using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Pipeline;

public sealed class TempFileCleaner
{
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromHours(24);

    private static readonly System.Text.RegularExpressions.Regex TempNamePattern =
        new("^[0-9a-f]{32}\\.tmp$", System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public long FilesDeleted { get; private set; }
    public long BytesDeleted { get; private set; }

    public int CleanupStaleTempFiles(
        string? tempDirectory,
        TimeSpan? maxAge = null,
        CancellationToken cancellationToken = default)
    {
        var age = maxAge ?? DefaultMaxAge;
        var dir = string.IsNullOrWhiteSpace(tempDirectory)
            ? Path.GetTempPath()
            : tempDirectory;

        if (!Directory.Exists(dir))
            return 0;

        var cutoff = DateTime.UtcNow - age;
        var deleted = 0;

        foreach (var file in Directory.EnumerateFiles(dir))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var name = Path.GetFileName(file);
            if (!TempNamePattern.IsMatch(name))
                continue;

            FileInfo info;
            try { info = new FileInfo(file); }
            catch { continue; }

            try
            {
                if (info.LastWriteTimeUtc >= cutoff)
                    continue;

                var size = info.Length;
                File.Delete(file);
                FilesDeleted++;
                BytesDeleted += size;
                deleted++;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        return deleted;
    }
}