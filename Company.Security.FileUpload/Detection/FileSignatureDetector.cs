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
            else if (signature.TextPattern is not null)
            {
                var searchEnd = signature.TextPatternSearchEnd > 0
                    ? Math.Min(signature.TextPatternSearchEnd, prefix.Length)
                    : prefix.Length;

                if (ContainsAscii(prefix.AsSpan(0, searchEnd), signature.TextPattern))
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
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

        var position = stream.CanSeek ? stream.Position : 0;
        var buffer = new byte[maxBytes];
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

        return total == maxBytes ? buffer : buffer.AsSpan(0, total).ToArray();
    }

    private static bool ContainsAscii(ReadOnlySpan<byte> data, string text)
    {
        if (text.Length == 0 || data.Length < text.Length)
            return false;

        for (var i = 0; i <= data.Length - text.Length; i++)
        {
            if (data[i] == (byte)text[0] && data.Slice(i, text.Length).SequenceEqual(System.Text.Encoding.ASCII.GetBytes(text)))
                return true;
        }

        return false;
    }
}