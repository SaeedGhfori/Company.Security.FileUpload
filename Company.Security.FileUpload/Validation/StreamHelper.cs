namespace Company.Security.FileUpload.Validation;

internal static class StreamHelper
{
    public static async Task<byte[]> ReadPrefixAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
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

    public static long GetLength(Stream stream)
    {
        if (stream.CanSeek)
            return stream.Length;

        if (stream is MemoryStream memory)
            return memory.Length;

        return -1;
    }
}