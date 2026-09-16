namespace Company.Security.FileUpload.Core.Enums;

public enum FileValidationErrorCode
{
    None = 0,

    FileNameInvalid = 1000,
    FileNameTooLong = 1001,
    FileNameContainsInvalidCharacters = 1002,
    FileNamePathTraversalDetected = 1003,
    FileNameEmpty = 1004,
    FileNameContainsNullBytes = 1005,
    FileNameReserved = 1006,

    ExtensionNotAllowed = 2000,
    ExtensionMissing = 2001,
    ExtensionMultipleDetected = 2002,
    ExtensionMismatch = 2003,
    ExtensionEmpty = 2004,
    ExtensionUnknown = 2005,

    FileTooLarge = 3000,
    FileTooSmall = 3001,
    FileEmpty = 3002,

    SignatureNotDetected = 4000,
    SignatureNotAllowed = 4001,
    SignatureMismatch = 4002,
    SignatureCorrupted = 4003,
    SignatureUnknown = 4004,

    MimeNotAllowed = 5000,
    MimeNotDetected = 5001,
    MimeMismatchWithSignature = 5002,

    StructureInvalid = 6000,
    StructureImageInvalid = 6001,
    StructurePdfInvalid = 6002,
    StructureZipInvalid = 6003,
    StructureZipTooManyEntries = 6004,
    StructureZipDepthExceeded = 6005,
    StructureZipBombDetected = 6006,
    StructureZipPathTraversal = 6007,
    StructureOfficeInvalid = 6008,
    StructureUnsupported = 6009,
    StructureImageDimensionExceeded = 6010,
    StructureImagePixelCountExceeded = 6011,

    FileTypeUnknown = 7000,
    FileTypeNotAllowed = 7001,

    MalwareScanRequired = 8000,
    MalwareScanFailed = 8001,
    MalwareScanInfected = 8002,
    MalwareScanTimeout = 8003,
    MalwareScanError = 8004,

    PolicyViolation = 10000,
    CancellationTokenRequested = 11000
}
