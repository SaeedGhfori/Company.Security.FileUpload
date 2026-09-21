using Company.Security.FileUpload.Core.Interfaces;
using Company.Security.FileUpload.Pipeline;
using Microsoft.Extensions.DependencyInjection;

namespace Company.Security.FileUpload;

public static class FileUploadPipelineExtensions
{
    public static IFileUploadPipelineBuilder CreateBuilder() => new FileUploadPipelineBuilder();

    public static IServiceCollection AddFileUploadPipeline(
        this IServiceCollection services,
        Action<FileUploadPipelineBuilder>? configure = null)
    {
        var builder = new FileUploadPipelineBuilder();
        configure?.Invoke(builder);
        var pipeline = builder.Build();
        services.AddSingleton<IFileUploadPipeline>(pipeline);
        services.AddSingleton<FileUploadPipeline>(pipeline);
        return services;
    }

    /// <summary>
    /// Registers the <see cref="TempFileCleaner"/> as a singleton. Call it at
    /// startup to sweep temp files left behind by a crash; pass the same
    /// <c>FileSizes.TempDirectory</c> you configured on the pipeline policy.
    /// Optional — anything that uses it opts in.
    /// </summary>
    public static IServiceCollection AddTempFileCleanup(this IServiceCollection services)
    {
        services.AddSingleton<TempFileCleaner>();
        return services;
    }
}
