using Company.Security.FileUpload;
using Company.Security.FileUpload.Pipeline;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<FileUploadPipeline>(sp =>
    new FileUploadPipelineBuilder()
        .UseDefaultDetection()
        .WithDefaultValidators()
        .Build());

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

app.MapOpenApi();
app.MapControllers();

app.Run();
