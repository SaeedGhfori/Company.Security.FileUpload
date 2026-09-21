namespace Company.Security.FileUpload.Detection;

public static class MimeDetector
{
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