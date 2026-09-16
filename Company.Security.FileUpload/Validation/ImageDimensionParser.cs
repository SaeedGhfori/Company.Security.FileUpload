using System.Buffers.Binary;

namespace Company.Security.FileUpload.Validation;

internal readonly record struct ImageDimensions(int Width, int Height)
{
    public static ImageDimensions None => default;

    public long PixelCount => (long)Width * Height;

    public bool HasValue => Width > 0 && Height > 0;
}

internal static class ImageDimensionParser
{
    private static readonly byte[] PngSignature = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    private static readonly byte[] Gif87a = { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 };
    private static readonly byte[] Gif89a = { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 };
    private static readonly byte[] Riff = { 0x52, 0x49, 0x46, 0x46 };
    private static readonly byte[] WebpVp8x = { 0x56, 0x50, 0x38, 0x58 };
    private static readonly byte[] WebpVp8l = { 0x56, 0x50, 0x38, 0x4C };
    private static readonly byte[] WebpVp8 = { 0x56, 0x50, 0x38, 0x20 };
    private static readonly byte[] Vp8StartCode = { 0x9D, 0x01, 0x2A };

    public static ImageDimensions Parse(string formatName, ReadOnlySpan<byte> data)
    {
        return formatName.ToUpperInvariant() switch
        {
            "PNG" => ParsePng(data),
            "JPEG" => ParseJpeg(data),
            "GIF" => ParseGif(data),
            "BMP" => ParseBmp(data),
            "WEBP" => ParseWebp(data),
            "TIFF" => ParseTiff(data),
            _ => ImageDimensions.None
        };
    }

    private static ImageDimensions ParsePng(ReadOnlySpan<byte> data)
    {
        if (data.Length < 24 || !data[..8].SequenceEqual(PngSignature))
            return ImageDimensions.None;

        var length = BinaryPrimitives.ReadInt32BigEndian(data[8..12]);
        if (length != 13 || !data.Slice(12, 4).SequenceEqual("IHDR"u8))
            return ImageDimensions.None;

        var width = BinaryPrimitives.ReadInt32BigEndian(data[16..20]);
        var height = BinaryPrimitives.ReadInt32BigEndian(data[20..24]);

        if (width <= 0 || height <= 0)
            return ImageDimensions.None;

        return new ImageDimensions(width, height);
    }

    private static ImageDimensions ParseJpeg(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 || data[0] != 0xFF || data[1] != 0xD8)
            return ImageDimensions.None;

        var offset = 2;
        while (offset + 4 <= data.Length)
        {
            if (data[offset] != 0xFF)
                return ImageDimensions.None;

            var marker = data[offset + 1];

            if (marker == 0xD9)
                break;

            offset += 2;

            if (marker is 0x00 or 0x01 or 0xD8 or 0xD9)
                continue;

            if (offset + 2 > data.Length)
                return ImageDimensions.None;

            var segmentLength = BinaryPrimitives.ReadUInt16BigEndian(data[offset..(offset + 2)]);
            if (segmentLength < 2)
                return ImageDimensions.None;

            if (marker is >= 0xC0 and <= 0xCF && marker is not 0xC4 and not 0xC8 and not 0xCC)
            {
                if (offset + 7 > data.Length)
                    return ImageDimensions.None;

                var height = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 3)..(offset + 5)]);
                var width = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 5)..(offset + 7)]);

                if (height == 0 || width == 0)
                    return ImageDimensions.None;

                return new ImageDimensions(width, height);
            }

            offset += segmentLength;
        }

        return ImageDimensions.None;
    }

    private static ImageDimensions ParseGif(ReadOnlySpan<byte> data)
    {
        if (data.Length < 10)
            return ImageDimensions.None;

        if (!data[..6].SequenceEqual(Gif87a) && !data[..6].SequenceEqual(Gif89a))
            return ImageDimensions.None;

        var width = (short)(data[6] | (data[7] << 8));
        var height = (short)(data[8] | (data[9] << 8));

        if (width <= 0 || height <= 0)
            return ImageDimensions.None;

        return new ImageDimensions(width, height);
    }

    private static ImageDimensions ParseBmp(ReadOnlySpan<byte> data)
    {
        if (data.Length < 26 || data[0] != (byte)'B' || data[1] != (byte)'M')
            return ImageDimensions.None;

        var dibSize = BinaryPrimitives.ReadInt32LittleEndian(data[14..18]);
        if (dibSize < 12)
            return ImageDimensions.None;

        var width = BinaryPrimitives.ReadInt32LittleEndian(data[18..22]);
        var height = BinaryPrimitives.ReadInt32LittleEndian(data[22..26]);

        if (width <= 0 || height == 0)
            return ImageDimensions.None;

        return new ImageDimensions(width, Math.Abs(height));
    }

    private static ImageDimensions ParseWebp(ReadOnlySpan<byte> data)
    {
        if (data.Length < 30 || !data[..4].SequenceEqual(Riff) || !data.Slice(8, 4).SequenceEqual("WEBP"u8))
            return ImageDimensions.None;

        var chunkType = data.Slice(12, 4);

        if (chunkType.SequenceEqual(WebpVp8x))
        {
            var widthMinusOne = data[24] | (data[25] << 8) | (data[26] << 16);
            var heightMinusOne = data[27] | (data[28] << 8) | (data[29] << 16);
            var width = (widthMinusOne & 0xFFFFFF) + 1;
            var height = (heightMinusOne & 0xFFFFFF) + 1;
            return new ImageDimensions(width, height);
        }

        if (chunkType.SequenceEqual(WebpVp8l))
        {
            var bits = (uint)(data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24));
            var widthMinusOne = bits & 0x3FFF;
            var heightMinusOne = (bits >> 14) & 0x3FFF;
            return new ImageDimensions((int)(widthMinusOne + 1), (int)(heightMinusOne + 1));
        }

        if (chunkType.SequenceEqual(WebpVp8))
        {
            if (data.Slice(20, 3).SequenceEqual(Vp8StartCode))
            {
                var frameTag = data[23];
                var isKeyFrame = (frameTag & 0x01) == 0x01;
                if (isKeyFrame)
                {
                    var widthMinusOne = data[27] | ((data[28] & 0x3F) << 8);
                    var heightMinusOne = data[29] | ((data[30] & 0x3F) << 8);
                    var width = (widthMinusOne & 0x3FFF) + 1;
                    var height = (heightMinusOne & 0x3FFF) + 1;
                    if (width > 0 && height > 0 && width <= 16384 && height <= 16384)
                        return new ImageDimensions(width, height);
                }
            }
            return ImageDimensions.None;
        }

        return ImageDimensions.None;
    }

    private static ImageDimensions ParseTiff(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
            return ImageDimensions.None;

        bool littleEndian;
        if (data[0] == (byte)'I' && data[1] == (byte)'I')
            littleEndian = true;
        else if (data[0] == (byte)'M' && data[1] == (byte)'M')
            littleEndian = false;
        else
            return ImageDimensions.None;

        int ifdOffset;
        if (littleEndian)
            ifdOffset = BinaryPrimitives.ReadInt32LittleEndian(data[4..8]);
        else
            ifdOffset = BinaryPrimitives.ReadInt32BigEndian(data[4..8]);

        if (ifdOffset <= 0 || ifdOffset + 2 > data.Length)
            return ImageDimensions.None;

        var entryCount = littleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(data[ifdOffset..(ifdOffset + 2)])
            : BinaryPrimitives.ReadUInt16BigEndian(data[ifdOffset..(ifdOffset + 2)]);

        var maxEntries = Math.Min((int)entryCount, 200);
        int? width = null;
        int? height = null;

        for (var i = 0; i < maxEntries; i++)
        {
            var entryOffset = ifdOffset + 2 + i * 12;
            if (entryOffset + 12 > data.Length)
                break;

            var tag = littleEndian
                ? BinaryPrimitives.ReadUInt16LittleEndian(data[entryOffset..(entryOffset + 2)])
                : BinaryPrimitives.ReadUInt16BigEndian(data[entryOffset..(entryOffset + 2)]);

            if (tag == 0x0100)
                width = ReadTiffUInt32(data, entryOffset + 8, littleEndian);
            else if (tag == 0x0101)
                height = ReadTiffUInt32(data, entryOffset + 8, littleEndian);

            if (width is > 0 && height is > 0)
                return new ImageDimensions(width.Value, height.Value);
        }

        return ImageDimensions.None;
    }

    private static int ReadTiffUInt32(ReadOnlySpan<byte> data, int offset, bool littleEndian)
    {
        var count = littleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(data[offset..(offset + 4)])
            : BinaryPrimitives.ReadUInt32BigEndian(data[offset..(offset + 4)]);

        return count > int.MaxValue ? 0 : (int)count;
    }
}