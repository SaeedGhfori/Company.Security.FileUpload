namespace Company.Security.FileUpload.Core.Exceptions;

public sealed class FileUploadSecurityException : Exception
{
    public FileUploadSecurityException(string message)
        : base(message)
    {
    }

    public FileUploadSecurityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}