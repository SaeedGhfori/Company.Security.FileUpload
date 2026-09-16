using System.IO.Compression;
using System.Text;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class OfficeStructureValidator : IFileValidator
{
    private static readonly Dictionary<string, string> RequiredParts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["DOCX"] = "word/document.xml",
        ["XLSX"] = "xl/workbook.xml",
        ["PPTX"] = "ppt/presentation.xml"
    };

    public string Name => nameof(OfficeStructureValidator);

    public Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var policy = request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.");
        if (!policy.RequireStructureValidation || detectedType.Category != FileTypeCategory.Office)
        {
            return Task.FromResult(FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream)));
        }

        if (!stream.CanSeek)
        {
            return Task.FromResult(FileValidationResult.Failure(
                new FileValidationError(FileValidationErrorCode.StructureUnsupported, "Office structure validation requires a seekable stream.")));
        }

        try
        {
            return Task.FromResult(ValidateOfficeStructure(stream, detectedType, policy, cancellationToken));
        }
        catch (InvalidDataException)
        {
            return Task.FromResult(FileValidationResult.Failure(
                new FileValidationError(FileValidationErrorCode.StructureOfficeInvalid, "The Office document container is corrupted or not a valid OOXML package.")));
        }
    }

    private static FileValidationResult ValidateOfficeStructure(Stream stream, FileTypeInfo detectedType, FileUploadPolicy policy, CancellationToken cancellationToken)
    {
        var errors = new List<FileValidationError>();
        var originalPosition = stream.Position;

        try
        {
            stream.Position = 0;
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

            var hasContentTypes = archive.Entries.Any(e =>
                string.Equals(e.FullName, "[Content_Types].xml", StringComparison.OrdinalIgnoreCase));

            if (!hasContentTypes)
            {
                errors.Add(new FileValidationError(
                    FileValidationErrorCode.StructureOfficeInvalid,
                    "The Office document is missing the [Content_Types].xml part."));
                return FileValidationResult.Failure(errors);
            }

            if (RequiredParts.TryGetValue(detectedType.FormatName, out var requiredPart))
            {
                var hasRequired = archive.Entries.Any(e =>
                    string.Equals(e.FullName, requiredPart, StringComparison.OrdinalIgnoreCase)
                    || e.FullName.StartsWith(requiredPart.Split('/')[0] + "/", StringComparison.OrdinalIgnoreCase));

                if (!hasRequired)
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.StructureOfficeInvalid,
                        $"The Office document is missing the required part '{requiredPart}' for format {detectedType.FormatName}."));
                    return FileValidationResult.Failure(errors);
                }
            }

            if (!policy.AllowMacroEnabledOfficeDocuments)
            {
                var macroDetected = DetectMacros(archive);
                if (macroDetected)
                {
                    errors.Add(new FileValidationError(
                        FileValidationErrorCode.StructureOfficeInvalid,
                        "The Office document contains macro code which is not allowed by policy."));
                }
            }

            return errors.Count == 0
                ? FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream))
                : FileValidationResult.Failure(errors);
        }
        finally
        {
            if (stream.CanSeek)
                stream.Position = originalPosition;
        }
    }

    private static bool DetectMacros(ZipArchive archive)
    {
        foreach (var entry in archive.Entries)
        {
            if (entry.FullName.Contains("vbaProject", StringComparison.OrdinalIgnoreCase))
                return true;

            if (entry.FullName.Contains("/vba/", StringComparison.OrdinalIgnoreCase))
                return true;

            if (entry.FullName.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                && entry.FullName.Contains("vba", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var contentTypes = archive.GetEntry("[Content_Types].xml");
        if (contentTypes is not null)
        {
            try
            {
                using var reader = new StreamReader(contentTypes.Open(), Encoding.UTF8);
                var content = reader.ReadToEnd();
                if (content.Contains("vbaProject", StringComparison.OrdinalIgnoreCase)
                    || content.Contains("macrosenabled", StringComparison.OrdinalIgnoreCase)
                    || content.Contains("application/vnd.ms-office.vbaProject", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch (InvalidDataException)
            {
                // treat as no macro content
            }
        }

        return false;
    }
}