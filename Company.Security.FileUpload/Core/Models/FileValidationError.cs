using System.Collections.ObjectModel;

namespace Company.Security.FileUpload.Core.Models;

public sealed class FileValidationError
{
    public FileValidationError(Enums.FileValidationErrorCode code, string message)
    {
        Code = code;
        Message = message;
    }

    public FileValidationError(Enums.FileValidationErrorCode code, string message, Exception innerException)
    {
        Code = code;
        Message = message;
        InnerException = innerException;
    }

    public Exception? InnerException { get; }

    public Enums.FileValidationErrorCode Code { get; }

    public string Message { get; }

    public IReadOnlyDictionary<string, string> Metadata { get; init; }
        = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());
}
