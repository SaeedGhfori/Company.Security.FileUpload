using System.Buffers;
using System.IO.Compression;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class ArchiveStructureValidator : IFileValidator
{
    private const int NestedArchiveReadLimit = 512 * 1024;
    private const long ZipBombDefaultRatio = 100;
    private const long ZipBombMinimumAbsoluteSize = 10 * 1024 * 1024;

    // When the absolute extracted-size limit is left at its 0 ("unset") default,
    // we still enforce one so a zip-bomb with a modest ratio (e.g. 50x) but huge
    // total uncompressed size cannot just cruise past the ratio check. The cap is
    // a multiple of the per-file size limit, which is the closest safe reference
    // we have without a second policy knob.
    private const int DefaultExtractedSizeMultiple = 10;

    private static readonly string[] NestedContainerExtensions = { ".zip", ".7z", ".rar", ".gz", ".tar", ".tgz" };

    public string Name => nameof(ArchiveStructureValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        if (!policy.Structures.RequireStructureValidation || detectedType.Category != FileTypeCategory.Archive)
        {
            return Task.FromResult(FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream)));
        }

        if (!stream.CanSeek)
        {
            return Task.FromResult(FileValidationResult.Failure(
                new FileValidationError(FileValidationErrorCode.StructureUnsupported, "Archive structure validation requires a seekable stream.")));
        }

        try
        {
            return Task.FromResult(ValidateZipStructure(stream, detectedType, policy, cancellationToken));
        }
        catch (InvalidDataException ex)
        {
            return Task.FromResult(FileValidationResult.Failure(
                new FileValidationError(FileValidationErrorCode.StructureZipInvalid, "The archive structure is invalid or corrupted.", ex)));
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException)
        {
            return Task.FromResult(FileValidationResult.Failure(
                new FileValidationError(FileValidationErrorCode.StructureZipInvalid, "The archive structure is invalid or corrupted.", ex)));
        }
    }

    private static FileValidationResult ValidateZipStructure(Stream stream, FileTypeInfo detectedType, FileUploadPolicy policy, CancellationToken cancellationToken)
    {
        var errors = new List<FileValidationError>();
        var originalPosition = stream.Position;

        try
        {
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

            if (archive.Entries.Count > policy.Structures.ArchiveMaxEntries)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.StructureZipTooManyEntries,
                    $"The archive contains too many entries."));
                return FileValidationResult.Failure(errors);
            }

            // Effective absolute cap on extracted size. When the policy leaves it
            // at its 0 default, we fall back to a safe multiple of the per-file
            // size limit so ratio-only zip-bomb evasion is not possible.
            var effectiveMaxExtracted = policy.Structures.ArchiveMaxExtractedSize > 0
                ? policy.Structures.ArchiveMaxExtractedSize
                : policy.FileSizes.MaxFileSizeBytes * DefaultExtractedSizeMultiple;

            long totalUncompressed = 0;
            long totalCompressed = 0;

            foreach (var entry in archive.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (HasPathTraversal(entry.FullName))
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.StructureZipPathTraversal,
                        "The archive contains an entry with an unsafe path."));
                    continue;
                }

                totalUncompressed += entry.Length;
                totalCompressed += entry.CompressedLength;

                if (totalUncompressed > effectiveMaxExtracted)
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.StructureZipBombDetected,
                        "The total extracted size exceeds the allowed limit."));
                    return FileValidationResult.Failure(errors);
                }
            }

            if (errors.Count > 0)
                return FileValidationResult.Failure(errors);

            if (totalUncompressed > effectiveMaxExtracted)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.StructureZipBombDetected,
                    "The total extracted size exceeds the allowed limit."));
            }
            else if (totalUncompressed > ZipBombMinimumAbsoluteSize &&
                     totalCompressed > 0 &&
                     totalUncompressed > totalCompressed * ZipBombDefaultRatio)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.StructureZipBombDetected,
                    "The archive has an abnormally high compression ratio which indicates a potential zip bomb."));
            }

            if (errors.Count == 0)
            {
                var depth = MeasureNestedDepth(archive, policy.Structures.ArchiveMaxDepth, cancellationToken);
                if (depth > policy.Structures.ArchiveMaxDepth)
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.StructureZipDepthExceeded,
                        $"The archive nesting depth of {depth} exceeds the allowed maximum of {policy.Structures.ArchiveMaxDepth}."));
                }
            }

            return errors.Count == 0
                ? FileValidationResult.Success(detectedType, totalUncompressed)
                : FileValidationResult.Failure(errors);
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = originalPosition;
        }
    }

    private static int MeasureNestedDepth(ZipArchive archive, int maxDepth, CancellationToken cancellationToken)
    {
        var containerEntries = archive.Entries
            .Where(e => NestedContainerExtensions.Any(ext => e.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var maxFound = 0;
        foreach (var entry in containerEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var depth = MeasureEntryDepth(entry, maxDepth, 1, cancellationToken);
            if (depth > maxFound)
                maxFound = depth;
        }

        return maxFound;
    }

    private static int MeasureEntryDepth(ZipArchiveEntry entry, int maxDepth, int currentDepth, CancellationToken cancellationToken)
    {
        try
        {
            using var entryStream = entry.Open();

            // Cap the nested payload into a single rented buffer and view it
            // directly, so ZipArchive needs no second 512KB copy on the LOH.
            // IMPORTANT: the buffer is returned only after the recursion has
            // finished consuming it — returning it in the inner finally would
            // free the array back to the pool while the child levels might
            // re-rent it, corrupting the child reads.
            var buffer = ArrayPool<byte>.Shared.Rent(NestedArchiveReadLimit);
            try
            {
                var total = 0;
                int read;
                while (total < NestedArchiveReadLimit &&
                       (read = entryStream.Read(buffer, total, NestedArchiveReadLimit - total)) > 0)
                {
                    total += read;
                }

                if (total == 0)
                    return currentDepth;

                using var bufferStream = new MemoryStream(buffer, 0, total, writable: false);
                using var nested = new ZipArchive(bufferStream, ZipArchiveMode.Read, leaveOpen: false);
                var nestedContainers = nested.Entries
                    .Where(e => NestedContainerExtensions.Any(ext => e.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (nestedContainers.Count == 0)
                    return currentDepth;

                if (currentDepth >= maxDepth)
                    return currentDepth + 1;

                var deepest = currentDepth;
                foreach (var nestedEntry in nestedContainers)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var d = MeasureEntryDepth(nestedEntry, maxDepth, currentDepth + 1, cancellationToken);
                    if (d > deepest)
                        deepest = d;
                }

                return deepest;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (InvalidDataException)
        {
            return currentDepth;
        }
    }

    private static bool HasPathTraversal(string entryName)
    {
        if (string.IsNullOrEmpty(entryName))
            return false;

        if (entryName.Contains("..", StringComparison.Ordinal))
            return true;

        if (entryName.StartsWith("/", StringComparison.Ordinal) || entryName.StartsWith("\\", StringComparison.Ordinal))
            return true;

        if (entryName.Contains('\\', StringComparison.Ordinal))
            return true;

        if (entryName.Length >= 2 && char.IsLetter(entryName[0]) && entryName[1] == ':')
            return true;

        if (entryName.Contains('\0'))
            return true;

        return false;
    }
}
