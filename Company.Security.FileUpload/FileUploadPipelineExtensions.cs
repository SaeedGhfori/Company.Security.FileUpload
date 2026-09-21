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

    public static IServiceCollection AddTempFileCleanup(this IServiceCollection services)
    {
        services.AddSingleton<TempFileCleaner>();
        return services;
    }
}
