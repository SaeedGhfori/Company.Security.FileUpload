namespace Company.Security.FileUpload.Pipeline;

internal sealed class ManagedTempFileStream : Stream
{
    private readonly FileStream _inner;
    private readonly string _path;

    public ManagedTempFileStream(FileStream inner, string path)
    {
        _inner = inner;
        _path = path;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;
    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override void SetLength(long value) => _inner.SetLength(value);
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override int Read(Span<byte> buffer) => _inner.Read(buffer);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.ReadAsync(buffer, cancellationToken);
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _inner.Dispose(); } catch { }
            TryDelete();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        try { await _inner.DisposeAsync(); } catch { }
        TryDelete();
        await base.DisposeAsync();
    }

    private void TryDelete()
    {
        // FileOptions.DeleteOnClose already removes the file when the handle is
        // closed. The explicit delete is a harmless no-op that also covers
        // platforms/filesystems where DeleteOnClose is best-effort.
        try { if (File.Exists(_path)) File.Delete(_path); } catch { }
    }
}