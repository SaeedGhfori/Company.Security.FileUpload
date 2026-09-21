using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Pipeline;

/// <summary>
/// Best-effort cleanup of stale temporary files left behind by
/// <see cref="FileUploadPipeline"/> after a hard crash (process kill, power
/// loss), when <c>FileOptions.DeleteOnClose</c> never ran because the handle
/// was never closed.
/// </summary>
public sealed class TempFileCleaner
{
    private static readonly TimeSpan DefaultMaxAge = TimeSpan.FromHours(24);

    /// <summary>Pattern that matches exactly the temp files this pipeline creates: a 32-char lowercase hex GUID plus ".tmp".</summary>
    private static readonly System.Text.RegularExpressions.Regex TempNamePattern =
        new("^[0-9a-f]{32}\\.tmp$", System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public long FilesDeleted { get; private set; }
    public long BytesDeleted { get; private set; }

    /// <summary>
    /// Deletes temp files older than <paramref name="maxAge"/> from
    /// <paramref name="tempDirectory"/>. When no directory is given, the
    /// process temp path is used and only files matching this pipeline's exact
    /// temp naming pattern are considered, so we never touch a .tmp file that
    /// belongs to another component sharing the system temp directory.
    /// </summary>
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

            // Only files at least maxAge old, and never one younger that an
            // in-flight upload might still be writing to.
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
            catch (IOException) { /* in use or just gone; skip */ }
            catch (UnauthorizedAccessException) { /* skip */ }
        }

        return deleted;
    }
}