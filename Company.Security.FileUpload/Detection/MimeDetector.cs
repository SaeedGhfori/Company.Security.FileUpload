using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Detection;

public static class MimeDetector
{
    public static string? Resolve(FileSignature? signature, FileTypeInfo? customDetected)
    {
        if (signature is not null)
            return signature.MimeType;

        return customDetected?.DetectedMimeType;
    }

    public static bool IsSuspectMime(string? declaredMime, string? detectedMime)
    {
        if (string.IsNullOrWhiteSpace(declaredMime) || string.IsNullOrWhiteSpace(detectedMime))
            return false;

        var declared = declaredMime.Split(';')[0].Trim().ToLowerInvariant();
        var detected = detectedMime.Split(';')[0].Trim().ToLowerInvariant();

        if (string.Equals(declared, detected, StringComparison.Ordinal))
            return false;

        if (declared == "application/octet-stream")
            return false;

        return true;
    }
}