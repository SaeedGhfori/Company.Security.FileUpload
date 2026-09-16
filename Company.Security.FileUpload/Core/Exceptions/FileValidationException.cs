using Company.Security.FileUpload.Core.Enums;

namespace Company.Security.FileUpload.Core.Exceptions;

public sealed class FileValidationException : Exception
{
    public FileValidationException(FileValidationErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public FileValidationException(FileValidationErrorCode errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    public FileValidationErrorCode ErrorCode { get; }
}