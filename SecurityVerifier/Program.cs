using Company.Security.FileUpload;
using Company.Security.FileUpload.Tests;
using Company.Security.FileUpload.Core.Enums;
using Company.Security.FileUpload.Core.Models;
using Company.Security.FileUpload.Pipeline;

var pipeline = new FileUploadPipelineBuilder()
    .UseDefaultDetection()
    .WithDefaultValidators()
    .Build();

// ===== TEST 1: Allow-list Empty / Default Behavior =====
Console.WriteLine("=== TEST 1: Allow-list Empty / Default Behavior ===");

// Test 1a: Empty allow-list with PNG file
var policy1 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedCategories = FileTypeCategory.All } };
var req1 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy1
};
var result1 = await pipeline.ProcessAsync(req1);
Console.WriteLine($"1a - Empty allow-list, PNG file: IsValid={result1.IsValid}, Errors={result1.Errors.Count}, Detected={result1.DetectedFileType?.FormatName}");

// Test 1b: Default policy (AllowedCategories = All) with no explicit allowlists
var policy2 = new FileUploadPolicy();
var req2 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy2
};
var result2 = await pipeline.ProcessAsync(req2);
Console.WriteLine($"1b - Default policy, PNG file: IsValid={result2.IsValid}, Errors={result2.Errors.Count}, Detected={result2.DetectedFileType?.FormatName}");

// Test 1c: JPEG content with .png extension, .png in allowlist
var policy3 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req3 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Jpeg()),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Jpeg().Length,
    Policy = policy3
};
var result3 = await pipeline.ProcessAsync(req3);
Console.WriteLine($"1c - JPEG content, .png extension, .png allowlist: IsValid={result3.IsValid}, Errors={result3.Errors.Count}, ErrorCodes={string.Join(",", result3.Errors.Select(e => e.Code))}, Detected={result3.DetectedFileType?.FormatName}");

// ===== TEST 2: Extension Spoofing =====
Console.WriteLine("\n=== TEST 2: Extension Spoofing ===");

// Test 2a: PNG content with .exe extension
var policy4 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req5 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "malware.exe",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy4
};
var result5 = await pipeline.ProcessAsync(req5);
Console.WriteLine($"2a - PNG content, .exe extension, .png allowlist: IsValid={result5.IsValid}, Errors={result5.Errors.Count}, ErrorCodes={string.Join(",", result5.Errors.Select(e => e.Code))}");

// Test 2b: EXE content with .jpg extension
var policy5 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".jpg" } } };
var req6 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Jpeg()),
    OriginalFileName = "malware.exe",
    DeclaredMimeType = "image/jpeg",
    DeclaredFileSize = TestFixtures.Jpeg().Length,
    Policy = policy5
};
var result6 = await pipeline.ProcessAsync(req6);
Console.WriteLine($"2b - EXE content (.jpg bytes), .jpg extension, .jpg allowlist: IsValid={result6.IsValid}, Errors={result6.Errors.Count}, ErrorCodes={string.Join(",", result6.Errors.Select(e => e.Code))}");

// Test 2c: PDF content with .png extension
var policy6 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req7 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Pdf()),
    OriginalFileName = "document.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Pdf().Length,
    Policy = policy6
};
var result7 = await pipeline.ProcessAsync(req7);
Console.WriteLine($"2c - PDF content, .png extension, .png allowlist: IsValid={result7.IsValid}, Errors={result7.Errors.Count}, ErrorCodes={string.Join(",", result7.Errors.Select(e => e.Code))}, Detected={result7.DetectedFileType?.FormatName}");

// ===== TEST 3: MIME Spoofing =====
Console.WriteLine("\n=== TEST 3: MIME Spoofing ===");

// Test 3a: PNG content with text/plain MIME
var policy7 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req8 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "text/plain",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy7
};
var result8 = await pipeline.ProcessAsync(req8);
Console.WriteLine($"3a - PNG content, text/plain MIME, .png allowlist: IsValid={result8.IsValid}, Errors={result8.Errors.Count}, ErrorCodes={string.Join(",", result8.Errors.Select(e => e.Code))}");

// Test 3b: Text file with .png extension and .png MIME
var policy9 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" }, AllowedMimeTypes = new[] { "image/png" } } };
var req9 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes("just text content")),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = 15,
    Policy = policy9
};
var result9 = await pipeline.ProcessAsync(req9);
Console.WriteLine($"3b - Text content, .png extension + image/png MIME, .png allowlist: IsValid={result9.IsValid}, Errors={result9.Errors.Count}, ErrorCodes={string.Join(",", result9.Errors.Select(e => e.Code))}");

// ===== TEST 4: Magic Bytes / File Signature =====
Console.WriteLine("\n=== TEST 4: Magic Bytes / File Signature ===");

// Test 4a: Truncated PNG (valid signature but broken body)
var policy10 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req10 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.TruncatedPng()),
    OriginalFileName = "broken.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.TruncatedPng().Length,
    Policy = policy10
};
var result10 = await pipeline.ProcessAsync(req10);
Console.WriteLine($"4a - Truncated PNG: IsValid={result10.IsValid}, Errors={result10.Errors.Count}, ErrorCodes={string.Join(",", result10.Errors.Select(e => e.Code))}");

// Test 4b: Fake RIFF/WEBP (valid RIFF header but invalid content)
var policy11 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".webp" } } };
var req11 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.FakeRiifWebp()),
    OriginalFileName = "forged.webp",
    DeclaredMimeType = "image/webp",
    DeclaredFileSize = TestFixtures.FakeRiifWebp().Length,
    Policy = policy11
};
var result11 = await pipeline.ProcessAsync(req11);
Console.WriteLine($"4b - Fake RIFF/WEBP: IsValid={result11.IsValid}, Errors={result11.Errors.Count}, ErrorCodes={string.Join(",", result11.Errors.Select(e => e.Code))}");

// Test 4c: PNG with broken IHDR length
var policy12 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req12 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.PngWithBrokenIhdrLength()),
    OriginalFileName = "broken.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.PngWithBrokenIhdrLength().Length,
    Policy = policy12
};
var result12 = await pipeline.ProcessAsync(req12);
Console.WriteLine($"4c - PNG with broken IHDR length: IsValid={result12.IsValid}, Errors={result12.Errors.Count}, ErrorCodes={string.Join(",", result12.Errors.Select(e => e.Code))}");

// ===== TEST 5: File Name Security =====
Console.WriteLine("\n=== TEST 5: File Name Security ===");

// Test 5a: Path traversal in filename
var policy13 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req13 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "..\\..\\windows\\evil.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy13
};
var result13 = await pipeline.ProcessAsync(req13);
Console.WriteLine($"5a - Path traversal filename: IsValid={result13.IsValid}, Errors={result13.Errors.Count}, ErrorCodes={string.Join(",", result13.Errors.Select(e => e.Code))}");

// Test 5b: Null bytes in filename
var policy14 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } } };
var req14 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo\u0001.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy14
};
var result14 = await pipeline.ProcessAsync(req14);
Console.WriteLine($"5b - Null byte filename: IsValid={result14.IsValid}, Errors={result14.Errors.Count}, ErrorCodes={string.Join(",", result14.Errors.Select(e => e.Code))}");

// Test 5c: Multiple extensions
var policy15 = new FileUploadPolicy
{
    FileKinds = new FileKinds { AllowedExtensions = new[] { ".png" } },
    FileNames = new FileNames { AllowMultipleExtensions = false }
};
var req15 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.ZipWithEntries("a.txt")),
    OriginalFileName = "archive.tar.gz",
    DeclaredMimeType = "application/zip",
    DeclaredFileSize = TestFixtures.ZipWithEntries("a.txt").Length,
    Policy = policy15
};
var result15 = await pipeline.ProcessAsync(req15);
Console.WriteLine($"5c - Multiple extensions: IsValid={result15.IsValid}, Errors={result15.Errors.Count}, ErrorCodes={string.Join(",", result15.Errors.Select(e => e.Code))}");

// ===== TEST 6: Archive / ZIP Security =====
Console.WriteLine("\n=== TEST 6: Archive / ZIP Security ===");

// Test 6a: ZIP with path traversal entry
var policy16 = new FileUploadPolicy
{
    FileKinds = new FileKinds { AllowedExtensions = new[] { ".zip" } },
    Structures = new Structures { ArchiveMaxEntries = 10 }
};
var req16 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.ZipWithEntries("../escape/evil.txt")),
    OriginalFileName = "archive.zip",
    Policy = policy16
};
var result16 = await pipeline.ProcessAsync(req16);
Console.WriteLine($"6a - ZIP with path traversal entry: IsValid={result16.IsValid}, Errors={result16.Errors.Count}, ErrorCodes={string.Join(",", result16.Errors.Select(e => e.Code))}");

// Test 6b: ZIP with too many entries
var policy17 = new FileUploadPolicy
{
    FileKinds = new FileKinds { AllowedExtensions = new[] { ".zip" } },
    Structures = new Structures { ArchiveMaxEntries = 10 }
};
var manyNames = System.Linq.Enumerable.Range(0, 50).Select(i => $"file{i}.txt").ToArray();
var req17 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.ZipWithEntries(manyNames)),
    OriginalFileName = "archive.zip",
    Policy = policy17
};
var result17 = await pipeline.ProcessAsync(req17);
Console.WriteLine($"6b - ZIP with too many entries: IsValid={result17.IsValid}, Errors={result17.Errors.Count}, ErrorCodes={string.Join(",", result17.Errors.Select(e => e.Code))}");

// Test 6c: ZIP bomb (high compression ratio)
var policy18 = new FileUploadPolicy { FileKinds = new FileKinds { AllowedExtensions = new[] { ".zip" } } };
var req18 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.ZipBomb()),
    OriginalFileName = "archive.zip",
    Policy = policy18
};
var result18 = await pipeline.ProcessAsync(req18);
Console.WriteLine($"6c - ZIP bomb: IsValid={result18.IsValid}, Errors={result18.Errors.Count}, ErrorCodes={string.Join(",", result18.Errors.Select(e => e.Code))}");

// Test 6d: Nested archive depth
var policy19 = new FileUploadPolicy
{
    FileKinds = new FileKinds { AllowedExtensions = new[] { ".zip" } },
    Structures = new Structures { ArchiveMaxDepth = 5 }
};
var req19 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.ZipNestedDepth(8)),
    OriginalFileName = "archive.zip",
    Policy = policy19
};
var result19 = await pipeline.ProcessAsync(req19);
Console.WriteLine($"6d - Nested archive depth: IsValid={result19.IsValid}, Errors={result19.Errors.Count}, ErrorCodes={string.Join(",", result19.Errors.Select(e => e.Code))}");

// ===== TEST 8: Policy Defaults =====
Console.WriteLine("\n=== TEST 7: Policy Defaults ===");

// Test 7a: Malware scan unavailable with RequireMalwareScan=true
var policy20 = new FileUploadPolicy { MalwareScanning = new MalwareScanning { RequireMalwareScan = true } };
var req20 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy20
};
var result20 = await pipeline.ProcessAsync(req20);
Console.WriteLine($"7a - Malware scan required but unavailable: IsValid={result20.IsValid}, Errors={result20.Errors.Count}, ErrorCodes={string.Join(",", result20.Errors.Select(e => e.Code))}");

// Test 7b: UnknownFilePolicy = Allow with unknown file
var policy21 = new FileUploadPolicy
{
    FileKinds = new FileKinds { UnknownFilePolicy = UnknownFilePolicy.Allow, AllowedExtensions = new string[0] }
};
var req21 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.RandomUnknown()),
    OriginalFileName = "photo.xyz",
    DeclaredMimeType = "application/octet-stream",
    DeclaredFileSize = 100,
    Policy = policy21
};
var result21 = await pipeline.ProcessAsync(req21);
Console.WriteLine($"7b - UnknownFilePolicy=Allow, no allowlist: IsValid={result21.IsValid}, Errors={result21.Errors.Count}, ErrorCodes={string.Join(",", result21.Errors.Select(e => e.Code))}");

// Test 7c: ExtensionMismatchPolicy = Warn
var policy22 = new FileUploadPolicy
{
    FileKinds = new FileKinds { ExtensionMismatchPolicy = ExtensionMismatchPolicy.Warn, AllowedExtensions = new[] { ".png" } }
};
var req22 = new FileUploadRequest
{
    FileStream = new System.IO.MemoryStream(TestFixtures.Png()),
    OriginalFileName = "photo.jpg",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = TestFixtures.Png().Length,
    Policy = policy22
};
var result22 = await pipeline.ProcessAsync(req22);
Console.WriteLine($"7c - ExtensionMismatchPolicy=Warn: IsValid={result22.IsValid}, Errors={result22.Errors.Count}, Warnings={result22.Warnings.Count}, ErrorCodes={string.Join(",", result22.Errors.Select(e => e.Code))}");

Console.WriteLine("\n=== TEST COMPLETE ===");