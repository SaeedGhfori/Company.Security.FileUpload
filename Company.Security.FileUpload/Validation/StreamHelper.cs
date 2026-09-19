using System.Buffers;

namespace Company.Security.FileUpload.Validation;

internal static class StreamHelper
{
    public static async Task<byte[]> ReadPrefixAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var position = stream.CanSeek ? stream.Position : 0;
        var buffer = ArrayPool<byte>.Shared.Rent(maxBytes);
        var total = 0;

        try
        {
            while (total < maxBytes)
            {
                var read = await stream.ReadAsync(new Memory<byte>(buffer, total, maxBytes - total), cancellationToken);
                if (read == 0)
                    break;
                total += read;
            }
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = position;
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return total == maxBytes ? buffer : buffer.AsSpan(0, total).ToArray();
    }

    public static long GetLength(Stream stream)
    {
        if (stream.CanSeek)
            return stream.Length;

        if (stream is MemoryStream memory)
            return memory.Length;

        return -1;
    }
}
