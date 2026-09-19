using System.Buffers;
using Company.Security.FileUpload.Core.Constants;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Detection;

public sealed class FileSignatureDetector
{
    private readonly IReadOnlyList<FileSignature> _signatures;

    public FileSignatureDetector()
        : this(FileSignatures.All)
    {
    }

    public FileSignatureDetector(IEnumerable<FileSignature> customSignatures)
    {
        var list = new List<FileSignature>(FileSignatures.All);
        list.AddRange(customSignatures);
        _signatures = list.AsReadOnly();
    }

    public IReadOnlyList<FileSignature> Signatures => _signatures;

    public ValueTask<FileSignature?> DetectAsync(Stream stream, int readLimit, CancellationToken cancellationToken)
        => DetectAsync(stream, null, readLimit, cancellationToken);

    public async ValueTask<FileSignature?> DetectAsync(
        Stream stream,
        byte[]? cachedPrefix,
        int readLimit,
        CancellationToken cancellationToken)
    {
        var prefix = cachedPrefix ?? await ReadPrefixAsync(stream, readLimit, cancellationToken);

        FileSignature? best = null;

        foreach (var signature in _signatures)
        {
            if (signature.Signature.Length > 0)
            {
                if (signature.Offset + signature.Signature.Length > prefix.Length)
                    continue;

                if (prefix.AsSpan(signature.Offset, signature.Signature.Length).SequenceEqual(signature.Signature))
                {
                    if (best is null || signature.Priority > best.Priority)
                        best = signature;
                }
            }
            else if (signature.TextPatternBytes is not null)
            {
                var searchEnd = signature.TextPatternSearchEnd > 0
                    ? Math.Min(signature.TextPatternSearchEnd, prefix.Length)
                    : prefix.Length;

                if (prefix.AsSpan(0, searchEnd).IndexOf(signature.TextPatternBytes.AsSpan()) >= 0)
                {
                    if (best is null || signature.Priority > best.Priority)
                        best = signature;
                }
            }
        }

        return best;
    }

    public static async ValueTask<byte[]> ReadPrefixAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes), maxBytes, "Value must be positive.");

        var position = stream.CanSeek ? stream.Position : 0;
        var buffer = ArrayPool<byte>.Shared.Rent(maxBytes);
        var total = 0;

        try
        {
            while (total < maxBytes)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total, maxBytes - total), cancellationToken);
                if (read == 0)
                    break;
                total += read;
            }
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = position;
        }

        var result = buffer.AsSpan(0, total).ToArray();
        ArrayPool<byte>.Shared.Return(buffer);
        return result;
    }
}
