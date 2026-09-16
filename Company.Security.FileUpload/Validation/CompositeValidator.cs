using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Core.Models;

namespace Company.Security.FileUpload.Validation;

public sealed class CompositeValidator : IFileValidator
{
    public string Name => nameof(CompositeValidator);

    public CompositeValidator(params IFileValidator[] validators)
    {
        ArgumentNullException.ThrowIfNull(validators);
        InnerValidators = validators;
    }

    public CompositeValidator(IEnumerable<IFileValidator> validators)
    {
        ArgumentNullException.ThrowIfNull(validators);
        InnerValidators = validators.ToArray();
    }

    public IReadOnlyList<IFileValidator> InnerValidators { get; }

    public async Task<FileValidationResult> ValidateAsync(Stream stream, FileTypeInfo detectedType, FileUploadRequest request, CancellationToken cancellationToken = default)
    {
        var errors = new List<FileValidationError>();
        var warnings = new List<string>();
        var result = FileValidationResult.Success(detectedType, StreamHelper.GetLength(stream));

        foreach (var validator in InnerValidators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var validatorResult = await validator.ValidateAsync(stream, detectedType, request, cancellationToken);
            errors.AddRange(validatorResult.Errors);
            warnings.AddRange(validatorResult.Warnings);

            if (validatorResult.FileSizeBytes >= 0 && validatorResult.FileSizeBytes != result.FileSizeBytes)
            {
                result = result with { FileSizeBytes = validatorResult.FileSizeBytes };
            }
        }

        if (errors.Count > 0)
        {
            result = FileValidationResult.Failure(errors);
        }

        foreach (var warning in warnings)
        {
            result = result.AddWarning(warning);
        }

        return result;
    }
}