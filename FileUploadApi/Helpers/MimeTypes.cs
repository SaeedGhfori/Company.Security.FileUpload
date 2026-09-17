internal static class MimeTypes
{
    private static readonly Dictionary<string, string> Extensions = new()
    {
        [".txt"] = "text/plain",
        [".html"] = "text/html",
        [".css"] = "text/css",
        [".js"] = "application/javascript",
        [".json"] = "application/json",
        [".xml"] = "application/xml",
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
        [".bmp"] = "image/bmp",
        [".svg"] = "image/svg+xml",
        [".webp"] = "image/webp",
        [".pdf"] = "application/pdf",
        [".doc"] = "application/msword",
        [".docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        [".xls"] = "application/vnd.ms-excel",
        [".xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        [".ppt"] = "application/vnd.ms-powerpoint",
        [".pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        [".zip"] = "application/zip",
        [".rar"] = "application/x-rar-compressed",
        [".tar"] = "application/x-tar",
        [".gz"] = "application/gzip",
        [".avi"] = "video/x-msvideo",
        [".mp3"] = "audio/mpeg",
        [".mp4"] = "video/mp4",
        [".wav"] = "audio/wav",
        [".mov"] = "video/quicktime",
        [".exe"] = "application/octet-stream",
        [".dll"] = "application/octet-stream",
        [".class"] = "application/java-class",
        [".midi"] = "audio/midi",
        [".mpeg"] = "video/mpeg",
        [".mpga"] = "audio/mpeg",
        [".wma"] = "audio/wma",
        [".ram"] = "audio/x-pn-realaudio",
        [".m3u"] = "audio/x-mpegurl",
        [".amr"] = "audio/amr",
        [".cab"] = "application/vnd.ms-cabinet",
    };

    public static string? GetMimeType(string extension)
    {
        if (string.IsNullOrEmpty(extension))
            return null;

        var ext = extension.StartsWith('.') ? extension : '.' + extension;
        return Extensions.TryGetValue(ext, out var mime) ? mime : "application/octet-stream";
    }
}