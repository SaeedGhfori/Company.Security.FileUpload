using Company.Security.FileUpload;
using Company.Security.FileUpload.Pipeline;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddFileUploadPipeline(b => b
    .UseDefaultDetection()
    .WithDefaultValidators());

builder.Services.AddControllers();
builder.Services.AddOpenApi();

var app = builder.Build();

app.MapOpenApi();
app.MapControllers();

app.Run();
