using Company.Security.FileUpload.Pipeline;

namespace Company.Security.FileUpload.Tests;

public class TempFileCleanerTests
{
    // The pipeline creates temp files named {Guid:N}.tmp (32 lowercase hex). The
    // cleaner must delete exactly those and only when they are older than maxAge,
    // so it can never remove a .tmp file owned by another component in the shared
    // temp directory or one an in-flight upload may still be writing to.
    [Fact]
    public void DeletesOnlyStalePipelineTempFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "FileUploadClean_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var stalePipeline = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
            var freshPipeline = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
            var foreignFile = Path.Combine(dir, "other-component.tmp");
            var nonTemp = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".log");

            File.WriteAllText(stalePipeline, "x");
            File.WriteAllText(freshPipeline, "x");
            File.WriteAllText(foreignFile, "x");
            File.WriteAllText(nonTemp, "x");

            // Make the "stale" file old, the "fresh" one recent.
            File.SetLastWriteTimeUtc(stalePipeline, DateTime.UtcNow - TimeSpan.FromHours(48));

            var cleaner = new TempFileCleaner();
            var deleted = cleaner.CleanupStaleTempFiles(dir, maxAge: TimeSpan.FromHours(24));

            Assert.Equal(1, deleted);
            Assert.Equal(1, cleaner.FilesDeleted);
            Assert.False(File.Exists(stalePipeline));
            Assert.True(File.Exists(freshPipeline));
            Assert.True(File.Exists(foreignFile));
            Assert.True(File.Exists(nonTemp));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void MissingDirectory_ReturnsZero()
    {
        var cleaner = new TempFileCleaner();
        var missing = Path.Combine(Path.GetTempPath(), "DoesNotExist_" + Guid.NewGuid().ToString("N"));
        Assert.Equal(0, cleaner.CleanupStaleTempFiles(missing));
    }

    [Fact]
    public void NothingStale_DeletesNothing()
    {
        var dir = Path.Combine(Path.GetTempPath(), "FileUploadClean_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var freshPipeline = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(freshPipeline, "x");
            File.SetLastWriteTimeUtc(freshPipeline, DateTime.UtcNow - TimeSpan.FromMinutes(1));

            var cleaner = new TempFileCleaner();
            Assert.Equal(0, cleaner.CleanupStaleTempFiles(dir, maxAge: TimeSpan.FromHours(24)));
            Assert.True(File.Exists(freshPipeline));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Cancelled_Throws()
    {
        var dir = Path.Combine(Path.GetTempPath(), "FileUploadClean_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var stalePipeline = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(stalePipeline, "x");
            File.SetLastWriteTimeUtc(stalePipeline, DateTime.UtcNow - TimeSpan.FromHours(48));

            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var cleaner = new TempFileCleaner();

            Assert.ThrowsAny<OperationCanceledException>(
                () => cleaner.CleanupStaleTempFiles(dir, maxAge: TimeSpan.FromHours(24), cancellationToken: cts.Token));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}