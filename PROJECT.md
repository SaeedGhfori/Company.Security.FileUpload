# Company.Security.FileUpload — پروژه‌نما / Architecture Reference

> این سند مرجع کاملی است از لایه اصلی `Company.Security.FileUpload`.
> هدف: در گفتگوهای آینده، بدون نیاز به خواندن دوباره سورس‌کد، از این مستند استفاده شود.
> اگر این مستند با وضعیت فعلی کد مغایرت داشت، **کد مرجع است** و این سند باید به‌روز شود.

---

## 1. نمای کلی و حقایق کلیدی

| مورد | مقدار |
|---|---|
| هدف | کتابخانه اعتبارسنجی امن آپلود فایل (OWASP‑based) |
| Target Framework | `net10.0` |
| وابستگی NuGet (Core) | فقط `Microsoft.Extensions.Logging.Abstractions` 10.0.0 — بقیه BCL خالص |
| خاصیت‌های csproj | `ImplicitUsings: enable`، `Nullable: enable`، `GenerateDocumentationFile: true`، `Version 1.0.0`، `PackageId: Company.Security.FileUpload` |
| نام‌ها | `Company` / `Company Security Team` / MIT |
| ایده اصلی | هرگز به نام/پسوند/MIME/اندازه اعلام‌شده اعتماد نمی‌کند؛ بایت واقعی + ساختار container بررسی بعدی |

`Directory.Build.props` در ریشه: `net10.0` + `Nullable` + NoWarn `XML0042;CS1591;CS0219`.

### نقشه Namespace ها
```
Company.Security.FileUpload            ← ریشه: Builder + DI extension
├── Core/Constants/   FileSignatures.cs         (کاتالوگ magic bytes)
├── Core/Enums/       FileTypeCategory, FileValidationErrorCode,
│                     ExtensionMismatchPolicy, MalwareScanErrorPolicy,
│                     MalwareScanStatus, UnknownFilePolicy
├── Core/Exceptions/  FileUploadSecurityException, FileValidationException
├── Core/Interfaces/  IFileDetectionService, IFileUploadPipeline,
│                     IFileUploadPipelineBuilder, IFileValidator, IMalwareScanner
├── Core/Models/      FileSignature, FileTypeInfo, FileUploadPolicy,
│                     FileUploadRequest, FileValidationError,
│                     FileValidationResult, MalwareScanResult
├── Core/Policies/    PolicyEngine.cs            (موتور پالیسی fail‑closed)
├── Detection/        ExtensionResolver, FileSignatureDetector,
│                     FileTypeResolver, MimeDetector, TextFormatDetector
├── Pipeline/         FileUploadPipeline.cs      (هماهنگ‌کننده اصلی)
└── Validation/       FileNameValidator, FileExtensionValidator,
                      FileSizeValidator, FileSignatureValidator,
                      FileContentValidator, ImageStructureValidator,
                      PdfStructureValidator, ArchiveStructureValidator,
                      OfficeStructureValidator, CompositeValidator,
                      StreamHelper, ImageDimensionParser (internal)
```

---

## 2. نقطه ورود (Public API)

### Builder — `FileUploadPipelineBuilder` (sealed)
Namespace `Company.Security.FileUpload`. فلوئنت؛ همه متدها `this` برمی‌گردانند:

```csharp
public sealed class FileUploadPipelineBuilder : IFileUploadPipelineBuilder
{
    UseDetection(IFileDetectionService detectionService)
    UseDefaultDetection()                       // = new FileTypeResolver()
    UseMalwareScanner(IMalwareScanner? scanner)
    SetMaxConcurrentValidations(int count)      // پیش‌فرض 32
    SetMaxQueuedValidations(int count)          // پیش‌فرض 32
    AddValidator(IFileValidator validator)      // اضافه به لیست (بدون clear)
    WithDefaultValidators()                     // clear سپس افزودن 9 اعتبارسنج پیش‌فرض نه تایی
    Build() → FileUploadPipeline
}
```

- `_detectionService` پیش‌فرض NULL → در `Build()` با `new FileTypeResolver()` جایگزین می‌شود.
- اگر `_validators.Count == 0` در `Build()`، `WithDefaultValidators()` صدا زده می‌شود.
- ترتیب **۹** اعتبارسنج پیش‌فرض (Singleton استاتیک):
  `FileNameValidator → FileExtensionValidator → FileSizeValidator → FileSignatureValidator → FileContentValidator → ImageStructureValidator → PdfStructureValidator → ArchiveStructureValidator → OfficeStructureValidator`.

### DI — `FileUploadPipelineExtensions` (static)
```csharp
CreateBuilder() → IFileUploadPipelineBuilder                  (new FileUploadPipelineBuilder())
services.AddFileUploadPipeline(Action<FileUploadPipelineBuilder>? configure = null)
    // pipeline = builder.Build();
    // services.AddSingleton<IFileUploadPipeline>(pipeline);
    // services.AddSingleton<FileUploadPipeline>(pipeline);   ← همان instance
```

### اینترفیس‌های Core (سیگنچر دقیق)
```csharp
interface IFileDetectionService {
    Task<FileTypeInfo> DetectAsync(Stream stream,
        string? declaredExtension = null, string? declaredMimeType = null,
        CancellationToken cancellationToken = default);
}
interface IFileUploadPipeline {
    Task<FileValidationResult> ProcessAsync(FileUploadRequest request,
        CancellationToken cancellationToken = default);
}
interface IFileValidator {
    string Name { get; }
    Task<FileValidationResult> ValidateAsync(Stream stream,
        FileTypeInfo detectedType, FileUploadRequest request,
        CancellationToken cancellationToken = default);
}
interface IMalwareScanner {
    string ScannerName { get; }
    Task<MalwareScanResult> ScanAsync(Stream stream,
        CancellationToken cancellationToken = default);
}
```

---

## 3. مدل‌ها

### `FileUploadRequest` (sealed, mutable)
| عضو | نوع | الزامی |
|---|---|---|
| `FileStream` | `Stream` | **بله** |
| `OriginalFileName` | `string` | **بله** |
| `DeclaredMimeType` | `string?` | نه |
| `DeclaredFileSize` | `long?` | نه |
| `Policy` | `FileUploadPolicy?` | عملاً بله (pipeline در غیابش `InvalidOperationException` پرتاب می‌کند) |
| `CancellationToken` | `CancellationToken` | نه |

### `FileUploadPolicy` (record — با `with` مشتق بگیرید). همه پیش‌فرض‌ها:
```csharp
PolicyName = "Default"
AllowedCategories = FileTypeCategory.All          // bit‑flag allowlist
AllowedExtensions = []                             // خالی = همه مجاز (صلاح‌دارانه لیست را پر کنید)
AllowedMimeTypes = []
AllowListedFormats = []                            // مثل "PNG"
MaxFileSizeBytes = 10 * 1024 * 1024
MinFileSizeBytes = 0
MaxMemoryFileSizeBytes = int.MaxValue              // سقف مطلق RAM برای بافر غیر seekable
TempFileThresholdBytes = 10 * 1024 * 1024           // آستانه‌ی RAM: فایل‌های ≤ این مقدار در RAM؛ بزرگ‌تر → دیسک (توسط ما)
TempDirectory = null                                // پوشه‌ی فایل موقت سفارشی؛ null → Path.GetTempPath()
RequireStructureValidation = true                  // کلید اصلی ساختار
RequireMalwareScan = false
UnknownFilePolicy = Reject
ExtensionMismatchPolicy = Reject
MaxImageWidth = 0 / MaxImageHeight = 0             // 0 = خاموش
MaxPixelCount = 0                                  // 0 = خاموش
ArchiveMaxEntries = 1000
ArchiveMaxDepth = 5
ArchiveMaxExtractedSize = 0                        // 0 = خاموش
VideoEnableDeepValidation = false
AllowMacroEnabledOfficeDocuments = false
AllowMultipleExtensions = false
AllowFileWithoutExtension = false
RejectIfMalwareScanUnavailable = true
MalwareScanErrorPolicy = Reject
MalwareScanUnknownPolicy = Reject
MaxFileNameLength = 255
SignatureReadLimitBytes = 8 * 1024
StructureReadLimitBytes = 256 * 1024
MaxConcurrentUploads = 10
```

### `FileValidationResult` (record)
| عضو | معنا |
|---|---|
| `IsValid` | نتیجه نهایی |
| `DetectedFileType` | `FileTypeInfo?` |
| `Errors` | `IReadOnlyList<FileValidationError>` |
| `Warnings` | `IReadOnlyList<string>` |
| `FileSizeBytes` | `long` |
| `MalwareScanResult` | `MalwareScanStatus?` |
| `ValidatedAt` | `DateTimeOffset.UtcNow` پیش‌فرض |
| `ValidationDuration` | `TimeSpan` (توسط pipeline در پایان ست می‌شود) |
| `Metadata` | `IReadOnlyDictionary<string, object>` |

Factory‌ها: `Success(detectedType, fileSizeBytes)`، `Failure(params)`، `Failure(IEnumerable)`.
متدهای record با `with`: `AddError(...)` (IsValid=false می‌کند)، `AddWarning(...)`.

### `FileValidationError` (sealed)
`Code` (`FileValidationErrorCode`) + `Message` + `InnerException?` + `Metadata` (`IReadOnlyDictionary<string,string>`).

### `FileTypeInfo` (record)
`DetectedExtension, DetectedMimeType, Category, FormatName, HasValidSignature, DeclaredExtension, DeclaredMimeType, ExtensionMatchesSignature, IsKnownFormat, MatchedSignatureOffset, MatchedSignatureBytes`.

### `MalwareScanResult` (sealed) — متدهای سازنده‌ی استاتیک:
`Clean(scannerName)`، `Infected(scannerName, threatName?)`، `Error(scannerName, details?)`، `Unknown(scannerName)`.
فیلدها: `Status, ScannerName, ThreatName?, Details?, ScannedAt, ScanDuration`.

---

## 4. Enum ها

### `FileTypeCategory` [Flags]
`None=0, Image=1, Video=2, Audio=4, Document=8, Office=16, Archive=32, Binary=64, Text=128, Svg=256, Unknown=1024, All = Image|Video|Audio|Document|Office|Archive|Binary|Text|Svg`.
(ثابت `All` شامل `Unknown` **نمی‌شود**.)

### `FileValidationErrorCode` — گروه‌ها (همه مقادیر دقیق، در ادامه):
- `None = 0`
- نام فایل `1000-1006`: `FileNameInvalid, FileNameTooLong, FileNameContainsInvalidCharacters, FileNamePathTraversalDetected, FileNameEmpty, FileNameContainsNullBytes, FileNameReserved`
- پسوند `2000-2005`: `ExtensionNotAllowed, ExtensionMissing, ExtensionMultipleDetected, ExtensionMismatch, ExtensionEmpty, ExtensionUnknown`
- اندازه `3000-3002`: `FileTooLarge, FileTooSmall, FileEmpty`
- سیگنچر `4000-4004`: `SignatureNotDetected, SignatureNotAllowed, SignatureMismatch, SignatureCorrupted, SignatureUnknown`
- MIME `5000-5002`: `MimeNotAllowed, MimeNotDetected, MimeMismatchWithSignature`
- ساختار `6000-6011`: `StructureInvalid, StructureImageInvalid, StructurePdfInvalid, StructureZipInvalid, StructureZipTooManyEntries, StructureZipDepthExceeded, StructureZipBombDetected, StructureZipPathTraversal, StructureOfficeInvalid, StructureUnsupported, StructureImageDimensionExceeded, StructureImagePixelCountExceeded`
- نوع فایل `7000-7001`: `FileTypeUnknown, FileTypeNotAllowed`
- بدافزار `8000-8004`: `MalwareScanRequired, MalwareScanFailed, MalwareScanInfected, MalwareScanTimeout, MalwareScanError`
- `PolicyViolation = 10000`، `CancellationTokenRequested = 11000`

### سیاست‌های رفتاری
- `ExtensionMismatchPolicy`: `Reject=0, Allow=1, Warn=2`. **نکته:** فقط `Reject`/`Warn` در کد هندل می‌شوند؛ `Allow` به‌نرمی «بدون بررسی» رفتار می‌کند (case تطبیق می‌خورد، نه خطا است).
- `MalwareScanErrorPolicy`: `Reject=0, Allow=1`.
- `MalwareScanStatus`: `Clean=0, Infected=1, Error=2, Unknown=3, NotSupported=4`.
- `UnknownFilePolicy`: `Reject=0, Allow=1, Quarantine=2`. **نکته:** در عمل `Quarantine` همان‌طورِ `Reject` بررسی می‌شود (هر دو خطا می‌دهند)؛ `Allow` خطا نمی‌دهد.

---

## 5. استثناها
- `FileUploadSecurityException : Exception` — خطای امنیتی سنگین (IMPORTANT: بدون `ErrorCode`).
- `FileValidationException : Exception` — دارای `ErrorCode` (readonly) + inner. سازنده‌ها: `(errorCode, message)` و `(errorCode, message, inner)`.

---

## 6. Pipeline — `FileUploadPipeline` (sealed، قلب همه‌چیز)

سازنده:
```csharp
FileUploadPipeline(IFileDetectionService detectionService,
    IEnumerable<IFileValidator> validators,
    IMalwareScanner? malwareScanner = null,
    ILogger? logger = null,
    int maxConcurrentUploads = 10,
    int maxConcurrentValidations = 32,
    int maxQueuedValidations = 32)
```
- `_concurrencySemaphore = new SemaphoreSlim(maxConcurrentUploads)`
- `_validationSemaphore = new SemaphoreSlim(maxQueued + maxConcurrent)`

### ترتیب `ProcessAsync(request, ct)`
1. **بررسی:** request، `request.FileStream` غیر null؛ `request.Policy` لازم → در نبودش `InvalidOperationException("FileUploadRequest requires a Policy.")`.
2. **Stopwatch** آغاز.
3. **برنامه‌ریزی:** `WaitAsync(_concurrencySemaphore)` ← سپس `WaitAsync(_validationSemaphore)`.
4. **موتور seek:** `(stream, shouldDispose) = EnsureSeekableAsync(request.FileStream, policy, ct)`:
   - قابل seek → `(source, false)`.
   - غیر seekable؛ اگر `sizeKnown && size <= MaxMemoryFileSizeBytes` → **دو شاخه یکسان** (هر دو) با buffer از `ArrayPool` + `MemoryStream`, `shouldDispose:true`. (در کد دو بلوک تکراری یکی برای «کوچک‌تر از threshold» و یکی «بزرگ‌تر از threshold» هست؛ رفتار یکسان — add در صورت لمس کد، ساده شود.)
   - در غیر این صورت (نامعلوم/بزرگ) → فایل موقت: `Path.GetTempFileName()` + `FileStream(..., FileOptions.DeleteOnClose)`، کپی تا limit `MaxFileSizeBytes + 1` بایت، `Position = 0`, `shouldDispose:true`. روی خطا: dispose + `File.Delete` و rethrow.
5. **تشخیص:** `stream.Position = 0`؛ `DetectAsync(stream, declaredExtension: ExtensionResolver.Normalize(OriginalFileName), declaredMimeType, ct)`.
6. **اعتبارسنجی:** پیمایش ترتیبی همه `_validators`، جمع کردن `Errors` هرکدام (هیچ‌کدام زنجیره را متوقف نمی‌کند).
7. **اندازه:** `GetSize(stream)` = `Length` اگر seekable وگرنه `Position`.
8. **پالیسی:** `PolicyEngine.Evaluate(detectedType, fileSize, policy, ct)` → جمع `Errors` + `Warnings`.
9. ترکیب `FileValidationResult` نهایی؛ افزودن `Warnings` پالیسی.
10. **بدافزار** فقط اگر `finalResult.IsValid && policy.RequireMalwareScan` → `RunMalwareScanAsync`.
11. `ValidationDuration = stopwatch.Elapsed`؛ برگرداندن نتیجه.
12. **finally:** `_validationSemaphore.Release()` همیشه؛ اگر `shouldDispose` → `stream.Dispose()` (خطای آن بلعیده می‌شود). سپس `_concurrencySemaphore.Release()`.
13. **catch `OperationCanceledException`:** هر دو سمانفور با `try/catch {}` رها می‌شوند (مقاوم در برابر رهاسازیِ سمانفوری که هرگز گرفته نشده → از `SemaphoreFullException` جلوگیری می‌کند)؛ rethrow.

### ماشین حالت اسکن بدافزار `RunMalwareScanAsync`
| وضعیت اسکنر | رفتار |
|---|---|
| بدون اسکنر | `policy.RejectIfMalwareScanUnavailable` → خطا `MalwareScanRequired` ؛ وگرنه بدون‌اثر (null). |
| `Clean` | قبول. |
| `Infected` | خطا `MalwareScanInfected` (با `ThreatName` اگر موجود باشد). |
| `Error` | `MalwareScanErrorPolicy == Reject` → خطا `MalwareScanError`؛ وگرنه قبول. |
| `Unknown` / `NotSupported` | `MalwareScanUnknownPolicy == Reject` → خطا `MalwareScanError` ؛ وگرنه قبول. `NotSupported` وقتی UnknownPolicy==Allow است قبول می‌شود. |
| وضعیت بالا | `scanRecord.Status` در `finalResult.MalwareScanResult` ثبت می‌شود. |

قبل از `ScanAsync`: `stream.Position = 0`.

---

## 7. موتور پالیسی — `PolicyEngine.Evaluate(detectedType, fileSize, policy, ct)`

ترتیب بررسی (خطاها به‌جای توقف، جمع می‌شوند):
1. `ct.ThrowIfCancellationRequested()`.
2. `policy == null` → خطا `PolicyViolation`، برگرد.
3. **فرمت ناشناخته** (`!IsKnownFormat`): اگر `UnknownFilePolicy ∈ {Reject, Quarantine}` → `FileTypeUnknown`.
4. **فرمت شناخته‌شده**:
   - `(policy.AllowedCategories & detectedType.Category) == 0` → `FileTypeNotAllowed`.
   - `AllowedExtensions` غیرخالی و `!Contains(detectedType.DetectedExtension, OrdinalIgnoreCase)` → `ExtensionNotAllowed`.
   - `AllowedMimeTypes` غیرخالی و `!Contains(detectedType.DetectedMimeType, OrdinalIgnoreCase)` → `MimeNotAllowed`.
   - `AllowListedFormats` غیرخالی و `!Contains(detectedType.FormatName, OrdinalIgnoreCase)` → `FileTypeNotAllowed`.
   - mismatch پسوند (`!IsEquivalentExtension(detected, declared)` و declared غیرخالی): According `ExtensionMismatchPolicy` → `Reject`→خطا `ExtensionMismatch`؛ `Warn`→warning؛ `Allow`/default→بی‌اثر.
5. **اندازه:** `fileSize > MaxFileSizeBytes` → `FileTooLarge`؛ `< MinFileSizeBytes` → `FileTooSmall`.

> **نکته ظریف:** در `PolicyEngine` مقایسه‌ی `AllowedExtensions` / `AllowedMimeTypes` با `string.Contains` ساده (فقط برابر) انجام می‌شود، در حالی‌که `FileExtensionValidator` از `ExtensionResolver.IsEquivalentExtension` (با alias مثل `jpeg↔jpg`) استفاده می‌کند. یعنی در گیت پالیسی، `allowed=[".jpg"]` به‌همراه پسوند واقعی `jpeg` **مردود** می‌شود هنگام‌یکه validator آن را می‌پذیرد.

---

## 8. تشخیص نوع (Detection)

### `FileTypeResolver.DetectAsync` — ترتیب لایه‌ها (اولین موفق برنده):
1. `FileSignatureDetector.ReadPrefixAsync(stream, 16KB, ct)` — پیشوند (بازیابی position اگر seekable).
2. **Container (Priority 100)** — `TryDetectContainerRefined(stream, prefix, ct)`:
   - RIFF (`RIFF` + FMT در offset 8): `"AVI "`→AVI/`,avi /video/x-msvideo`؛ `"WAVE"`→WAV/`.wav`/`audio/wav`؛ `"WEBP"`→WEBP/`.webp`/`image/webp`.
   - EBML (`1A 45 DF A3`): در 512 بایت اول اگر شامل `webm` (ci) باشد → `.webm`/`video/webm`، وگرنه MKV/`.mkv`/`video/x-matroska`.
   - `ftyp` در offset 4: brand در offset 8؛ اگر `qt...` (ci) → MOV/`.mov`/`video/quicktime`، وگرنه MP4/`.mp4`/`video/mp4`.
   - ZIP (`PK\x03\x04`): `TryDetectZipContainer` — فقط اگر `stream.CanSeek && stream.Length <= 256MB`. `ZipArchive` را باز می‌کند، ورودی `[Content_Types].xml` (سقف 64KB) را می‌خواند؛ شامل `wordprocessingml`→DOCX/`.docx`/office‑wordprocessingml؛ `spreadsheetml`→XLSX/`.xlsx`/office‑spreadsheetml؛ `presentationml`→PPTX/`.pptx`/office‑presentationml؛ هیچ‌کدام→null. تمام استثناهای باز شدن (`InvalidDataException/IOException/ArgumentException/Exception`) → null. position بازیابی می‌شود.
   - OLE‑CFB (`D0 CF 11 E0 A1 B1 1A E1`): اسکن ASCII تا 8192 بایت؛ `WordDocument`→DOC/`.doc`/`application/msword`؛ `Workbook`→XLS/`.xls`/`application/vnd.ms-excel`؛ `PowerPoint Document`→PPT/`.ppt`/`application/vnd.ms-powerpoint`؛ هیچ‌کدام→`OLE-CFB`/Binary/`.doc`/`application/x-ole-storage`.
   - نتیجه container → `BuildFromSignature`.
3. **کاتالوگ magic bytes** — `_detector.DetectAsync(stream, prefix, 16KB, ct)` (به‌ترتیب اولویت؛ همیشه `HasValidSignature=true`, `IsKnownFormat=true`).
4. **متن** — `TextFormatDetector.Detect(prefix)`.
5. ناامیدی → `BuildUnknown`: `FormatName="UNKNOWN"`, `Category=Unknown`, `IsKnownFormat=false`, `HasValidSignature=false`, `ExtensionMatchesSignature=false`.

`Finalize`: `ExtensionMatchesSignature = declaredExtension.IsNullOrEmpty ? true : ExtensionResolver.IsEquivalentExtension(declared, detected)`.

### کاتالوگ سیگنچر — `FileSignatures.All` (ساخته‌شده در `BuildCatalog`، فقط‌خواندنی)
استاتیک‌ها: `ZipLocalHeader = {50 4B 03 04}`، `ZipEmptyHeader = {50 4B 05 06}`، `ZipSpannedHeader = {50 4B 07 08}`؛ `Ascii(string)`.

| FormatName | Category | پسوند | MIME | نوع | بایت‌ها / الگو (Offset, Priority) |
|---|---|---|---|---|---|
| JPEG | Image | .jpg | image/jpeg | binary | `FF D8 FF` (0, 10) |
| PNG | Image | .png | image/png | binary | `89 50 4E 47 0D 0A 1A 0A` (0, 10) |
| GIF ×2 | Image | .gif | image/gif | binary | `GIF87a` و `GIF89a` (0, 10) |
| BMP | Image | .bmp | image/bmp | binary | `BM` (0, 10) |
| TIFF ×2 | Image | .tiff | image/tiff | binary | `II*\0` و `MM\0*` (0, 10) |
| WEBP | Image | .webp | image/webp | text | `WEBP` در 32 بایت اول (پریوری‌تی 20) |
| SVG | Svg | .svg | image/svg+xml | text | `<svg` در 512 بایت اول (20) |
| MKV | Video | .mkv | video/x-matroska | binary | `1A 45 DF A3` (0, 20) |
| MP3 | Audio | .mp3 | audio/mpeg | binary | `ID3` (0, 20) |
| FLAC | Audio | .flac | audio/flac | binary | `fLaC` (0, 20) |
| OGG | Audio | .ogg | audio/ogg | binary | `OggS` (0, 20) |
| PDF | Document | .pdf | application/pdf | text | `%PDF-` در 16 بایت اول (30) |
| XML | Text | .xml | application/xml | text | `<?xml` در 128 بایت اول (30) |
| ZIP | Archive | .zip | application/zip | binary | `PK\x03\x04` (0, 30) |
| ZIP‑EMPTY | Archive | .zip | application/zip | binary | `PK\x05\x06` (0, 30) |
| 7Z | Archive | .7z | application/x-7z-compressed | binary | `37 7A BC AF 27 1C` (0, 30) |
| TAR | Archive | .tar | application/x-tar | text | `ustar` در 262 بایت اول (30) |
| GZIP | Archive | .gz | application/gzip | binary | `1F 8B` (0, 30) |
| OLE‑CFB | Binary | .doc | application/x-ole-storage | binary | `D0 CF 11 E0 A1 B1 1A E1` (0, 40) |
| EXE | Binary | .exe | application/x-msdownload | binary | `MZ` (0, 40) |
| RAR | Archive | .rar | application/vnd.rar | binary | `52 61 72 21 1A 07` (0, 40) |

قانون `FileSignatureDetector.DetectAsync`: matching binary = "Signature در Offset مشخص‌تر"; matching text = "TextPatternBytes در محدوده `TextPatternSearchEnd` ظاهر شود". best = بالاترین `Priority` (اولین‌برابر هم سطح، اول لیست). تبصره: `Signature` خالی + `TextPatternBytes` غیرخالی → مسیر text.

### `FileSignatureDetector`
- سازنده‌های `()` → `FileSignatures.All`؛ و `(IEnumerable<FileSignature> custom)` → All + سفارشی (‌All اول، سفارشی بعد؛ همه در یک list).
- `ReadPrefixAsync(stream, maxBytes, ct)`: `maxBytes<=0` → `ArgumentOutOfRangeException`؛ `ArrayPool`؛ position بازیابی.

### `TextFormatDetector` (static) — `MaxTextInspection = 4096`
1. `LooksLikeText`: در 1024 بایت اول هیچ `0x00`، هیچ `< 0x09`، و هیچ مقداری در `0x0E..0x1F` نباشد.
2. Trim اولیه `'\uFEFF'` و whitespace.
3. `<?xml` یا `<` → اگر شامل `<svg` (ci) → SVG/`.svg`/`image/svg+xml`؛ وگرنه XML/`.xml`/`application/xml`.
4. اولین کاراکتر `{` یا `[` → JSON/`.json`/`application/json`.
5. شامل `,` و `\n` → CSV/`.csv`/`text/csv`; وگرنه `TEXT`/`.txt`/`text/plain`.
(همه text ‑نتایج `HasValidSignature=true, IsKnownFormat=true`.)

### `MimeDetector` (static)
- `Resolve(signature?, customDetected?)` → MIME از signature یا از custom.
- `IsSuspectMime(declared, detected)`: هردو مقادیر خالی→false؛ قیاس با مستثنی‌کردن `;params` و lowercase؛ برابر→false؛ `declared == "application/octet-stream"`→false؛ در غیر این صورت true (مشکوک/ناهماهنگ).

---

## 9. اعتبارسنج‌ها (بخش `Validation`)

مسئله مشترک: هر validator با `request.Policy ?? throw new InvalidOperationException("FileUploadRequest requires a Policy.")` شروع می‌شود و `ct.ThrowIfCancellationRequested()`. همه فقط پس‌زمینی‌خوانی می‌کنند (position را توسط `StreamHelper` بازیابی می‌کنند).

### `FileNameValidator`
خطاها:
- `fileName` خالی → `FileNameEmpty` (برگرد فوری).
- `nameOnly.Length > policy.MaxFileNameLength` → `FileNameTooLong`.
- `LooksLikePathTraversal(fileName)` **یا** (decoded) → `FileNamePathTraversalDetected`.
- `IsReservedFileName(nameOnly)` → `FileNameReserved`.
- شامل `\0` (خام یا decoded) → `FileNameContainsNullBytes`.
- `ContainsInvalidChars(nameOnly)` = شامل `Path.GetInvalidFileNameChars()` یا control → `FileNameContainsInvalidCharacters`.
- بدون پسوند (خام یا decoded) و `!AllowFileWithoutExtension` → `ExtensionMissing`.
- `HasMultipleExtensions` (خام) یا (decoded) و `!AllowMultipleExtensions` → `ExtensionMultipleDetected`.
- `nameOnly` = بخش قبل از آخرین نقطه؛ `SplitNameAndExtension`.

### `FileExtensionValidator`
- `AllowedExtensions.Count == 0` → قبول بی‌قید.
- `declaredExtension = ExtensionResolver.Normalize(OriginalFileName)`.
- خالی پسوند و `!AllowFileWithoutExtension` → `ExtensionMissing`.
- نه در allowlist (تطبیق با `IsEquivalentExtension`) → `ExtensionNotAllowed`.
- `!IsValidExtension(declared)` → `ExtensionUnknown`.

### `FileSizeValidator`
- `MeasureLengthAsync`: اگر `CanSeek` → `(Length, true)`؛ وگرنه می‌خواند تا `MaxFileSizeBytes + 1` و اگر از آن عبور کند → `(bytesRead, false)`.
- غیردقیق و `size == MaxFileSizeBytes+1` → `FileTooLarge` (برگرد فوری).
- `size == 0` → `FileEmpty`.
- `size > Max` → `FileTooLarge`؛ `size < Min` → `FileTooSmall`.
- (نکته: برای stream غیر seekable، این validator stream را مصرف می‌کند تا EOF؛ در بافت pipeline uns پردازش stream از قبل seekable می‌شود.)

### `FileSignatureValidator`
- `!HasValidSignature` و `UnknownFilePolicy ∈ {Reject, Quarantine}` → `SignatureNotDetected`.
- `IsKnownFormat`:
  - `AllowedExtensions` غیرخالی و `!Contains(detected ext, OrdinalIgnoreCase)` → `SignatureNotAllowed`.
  - declared پسوند غیرخالی و `!detectedType.ExtensionMatchesSignature` و `ExtensionMismatchPolicy==Reject` → `ExtensionMismatch`.

### `FileContentValidator`
- MIME: اگر `DeclaredMimeType` غیرخالی و `IsKnownFormat`؛ `MimeDetector.IsSuspectMime`؛ مطابق `ExtensionMismatchPolicy`: `Reject`→خطا `MimeMismatchWithSignature`، وگرنه warning.
- اندازه اعلام‌شده: اگر `DeclaredFileSize is > 0` و `stream.CanSeek` و `stream.Length != DeclaredFileSize` → `FileTooLarge` با پیام «actual … does not match the declared size».

### `ImageStructureValidator`
- فعال فقط اگر `RequireStructureValidation && detectedType.Category == Image && FormatName ∈ {JPEG, PNG, GIF, BMP, WEBP, TIFF}`.
- پیشوند تا `max(StructureReadLimitBytes, 512)`.
- ابعاد با `ImageDimensionParser.Parse(formatName, prefix)`؛ هیچ ابعادی → `StructureImageInvalid`.
- `MaxImageWidth/Height > 0` و `width/height > max` → `StructureImageDimensionExceeded` (در هر محور).
- `MaxPixelCount > 0` و `width*height > max` → `StructureImagePixelCountExceeded`.

### `ImageDimensionParser` (internal) — جزئیات هر فرمت:
- **PNG**: `IHDR` در offset 8 (length==13)؛ width/height big‑endian در 16/20.
- **JPEG**: اسکن markerهای SOF: `0xFF`…، marker در `0xC0..0xCF` به‌جز `0xC4/0xC8/0xCC` (DHT/JPGn/DAC)؛ `segmentLength>=2`؛ height/width big‑endian در `+3/+5`. علامت پایانی `0xD9`.
- **GIF**: `width = b7|b6<<8` (little‑endian)؛ در 6و6، 8و8.
- **BMP**: dibSize در 14; width/height little‑endian در 18/22؛ `dibSize>=12`؛ `height = Math.Abs`.
- **WEBP**: RIFF+`WEBP`؛ chunk VP8X→24‑بیتی minus‑one؛ VP8L→14‑bit two‑field؛ VP8 (lossy)→استارت‌کد `9D 01 2A`، keyframe، محدود 16384.
- **TIFF**: `II`/`MM`؛ IFD در offset 4؛ حداکثر 200 entry؛ tag `0x0100`→width، `0x0101`→height؛ مقادیر > int.MaxValue → 0.

### `PdfStructureValidator`
- فعال فقط اگر `RequireStructureValidation && FormatName == "PDF"`.
- پیشوند تا `max(StructureReadLimitBytes, 256)`.
- `prefix.Length < 5` → `StructurePdfInvalid`.
- هدر 16 بایت اول باید با `%PDF-` شروع شود → وگرنه `StructurePdfInvalid`.
- نسخه بعد از `%PDF-` باید با `1.` یا `2.` شروع شود → وگرنه `StructurePdfInvalid`.
- اگر seekable: تیلر 2048 بایت آخر باید شامل `%%EOF` → وگرنه `StructurePdfInvalid`.

### `ArchiveStructureValidator`
- فعال فقط اگر `RequireStructureValidation && Category == Archive`. غیر seekable → `StructureUnsupported`.
- `ValidateZipStructure` (با `ZipArchive`، leaveOpen):
  - `archive.Entries.Count > ArchiveMaxEntries` → `StructureZipTooManyEntries` (فوری).
  - به‌ازای هر entry: `HasPathTraversal` → `StructureZipPathTraversal`؛ جمع‌آوری `totalUncompressed += entry.Length`, `totalCompressed += entry.CompressedLength`.
  - `ArchiveMaxExtractedSize > 0 && totalUncompressed > max` → `StructureZipBombDetected` (فوری).
  - در پایان: اگر `ArchiveMaxExtractedSize > 0` و کل بیشتر از max → `StructureZipBombDetected`؛ وگرنه ratio: `totalUncompressed > 10MB && totalUncompressed > totalCompressed * 100` → `StructureZipBombDetected`.
  - `MeasureNestedDepth` روی entryهایی با پسوند در `{ .zip, .7z, .rar, .gz, .tar, .tgz }`: بازگشتی، هر سطح با سقف خواندن 512KB، `depth > ArchiveMaxDepth` → `StructureZipDepthExceeded`. سطح فعلی + 1 وقتی محدودیت عمق کل شد.
  - استثناهای `InvalidDataException`/`IOException`/`ArgumentException`/`InvalidOperationException` → `StructureZipInvalid`.
  - `FileSizeBytes` موفق = `totalUncompressed`.
- `HasPathTraversal(entryName)`: شامل `..`، شروع با `/` یا `\`، هر `\`، `X:` drive-letter در start، `\0` → true.

### `OfficeStructureValidator`
- فعال فقط اگر `RequireStructureValidation && Category == Office`. غیر seekable → `StructureUnsupported`.
- باید `[Content_Types].xml` موجود باشد → وگرنه `StructureOfficeInvalid`.
- بخش‌های لازم: `DOCX→word/document.xml`، `XLSX→xl/workbook.xml`، `PPTX→ppt/presentation.xml` — با تطبیق نام‌کامل یا پیشوند پوشه‌ی بخش اول → وگرنه `StructureOfficeInvalid`.
- اگر `!AllowMacroEnabledOfficeDocuments`: `DetectMacros` → جدید: entry حاوی `vbaProject`، `.../vba/...`، `.bin` حاوی `vba`، یا محتوای `[Content_Types].xml` شامل `vbaProject`/`macrosenabled`/`application/vnd.ms-office.vbaProject` → `StructureOfficeInvalid`.
- `InvalidDataException` → `StructureOfficeInvalid`.

### `CompositeValidator`
- سازنده `(params IFileValidator[])` یا `(IEnumerable<IFileValidator>)`؛ `InnerValidators` readonly.
- همه را اجرا می‌کند، `Errors` و `Warnings` را جمع می‌کند، و `FileSizeBytes` را از آخرین غیرمنفی/متفاوت به‌روز می‌کند.

### `StreamHelper` (static)
- `ReadPrefixAsync(stream, maxBytes, ct)` — ArrayPool، بازیابی position.
- `GetLength(stream)` — `Length` اگر seekable؛ `MemoryStream.Length`؛ وگرنه `Position`.

---

## 10. امنیت پسوند — `ExtensionResolver` (static)

| متد | رفتار |
|---|---|
| `Normalize(fileName)` | URL‑decode → trim → بی‌نقطه و lowercase پس از آخرین `.`؛ بدون نقطه/نقطه آخر → خالی |
| `IsValidExtension(ext)` | decode، `≤32` کاراکتر، خالی ممنوع؛ شامل `.. / \ : * ? " < > | NUL` ممنوع؛ whitespace ممنوع؛ فقط `letters/digits/-/_` |
| `GetAllExtensions(fileName)` | همه‌ی بخش‌های بعد از نقطه (lowercase)؛ `file.tar.gz` → `[tar, gz]` |
| `HasMultipleExtensions` | `GetAllExtensions(...).Count > 1` |
| `IsEquivalentExtension(a, b)` | برابر ci؛ یا از طریق alias-map: `jpeg↔jpg`، `tif↔tiff`، `htm↔html`، `mpeg↔mpg` |
| `LooksLikePathTraversal` | شامل `..`، `/` (مگر مسیر ویندوز `X:\`)، هر `\`، `:`، `\0`، `%2e`، `%2e%2e`، `%00` |
| `IsReservedFileName` | `CON PRN AUX NUL` (+ پیشوند `CON.`…)، هر نام شروع با `COM` یا `LPT` |
| `DecodeUrlEncoding` | double‑decode امن: `Uri.EscapeDataString(Uri.UnescapeDataString(x))`؛ در شرایط استثنا، خام برمی‌گرداند |

---

## 11. حفره‌ها / نکات پیاده‌سازی (قبل از لمس کد بررسی شود)

1. **`ExtensionMismatchPolicy.Allow`** و **`UnknownFilePolicy.Quarantine`**: در عمل شاخه‌ی خاصی ندارند — `Allow` روی mismatch «بی‌اثر» (نه خطا نه هشدار)، و `Quarantine` همان‌طورِ `Reject` است.
2. **`PolicyEngine`** برای `AllowedExtensions`/`AllowedMimeTypes` از `string.Contains` ساده استفاده می‌کند (نه alias‑aware)، در حالی‌که `FileExtensionValidator` با `IsEquivalentExtension` مقایسه می‌کند → عدم تطابق بالقوه بین این دو گیت.
3. **بافر stream غیر seekable** (در `FileUploadPipeline`): حالا ۳ مسیر — قابل seek → همان؛ `sizeKnown && size ≤ TempFileThresholdBytes && ≤ MaxMemoryFileSizeBytes` → RAM (`MemoryStream`); در غیر این صورت (بزرگ/نامعلوم) → دیسک با `ManagedTempFileStream` (فایل در `policy.TempDirectory ?? Path.GetTempPath()`، پاکسازی‌شده توسط ما در dispose؛ نه `FileOptions.DeleteOnClose`). اندازه‌ی نامعلوم از `Length` فقط در `CanSeek` خوانده می‌شود — از خواندن `Position` اجتناب می‌شود (چون برخی wrapper های غیر seekable روی `Position` `NotSupportedException` پرتاب می‌کنند).

   > رفتار قبلی: `Position` از منبع خوانده می‌شد → روی stream های غیر seekableِ بدون `Position` پرتاب می‌کرد. حالا چنین stream هایی مستقیماً به دیسک می‌روند (RAM نمی‌گیرند).
4. **همه‌ی validators** هنگام‌که با `Policy == null` داده شوند `InvalidOperationException` پرتاب می‌کنند؛ بنابراین پالیسی در هر مسیر pipeline الزامی است.
5. **رهاسازی سمانفور** در `OperationCanceledException` با `try/catch {}` — مقاوم در برابر رهاسازیِ سمانفوری که هرگز گرفته نشده (پیشگیری از `SemaphoreFullException`).
6. **`MeasureNestedDepth`**: عمق آرشیوهایی که باز شدن‌شان با `InvalidDataException` لو می‌رود، null صفر محسوب می‌شود (از `InvalidDataException` پایین می‌ماند).
7. ساخت کاتالوگ `FileSignatures`: سفارشی از طریق سازنده‌ی `FileSignatureDetector(IEnumerable<FileSignature>)` به end اضافه می‌شود؛ اول‌برابرهای Priority، اولین کدام برنده است → سفارشی‌ها بعد از کاتالوگ به‌دست کار می‌آیند.
8. تشخیص container ZIP/Office برای فایل‌هایی ≤ 256MB و فقط روی stream seekable باز می‌شود؛ تشخیص Office فقط با بازرسی signature، نه اسم فایل.

---

## 12. درخت پروژه (لایه اصلی)

```
Company.Security.FileUpload/
  Company.Security.FileUpload.csproj
  FileUploadPipelineBuilder.cs
  FileUploadPipelineExtensions.cs          (DI + CreateBuilder)
  Core/
    Constants/FileSignatures.cs
    Enums/{FileTypeCategory, FileValidationErrorCode, ExtensionMismatchPolicy,
           MalwareScanErrorPolicy, MalwareScanStatus, UnknownFilePolicy}.cs
    Exceptions/{FileUploadSecurityException, FileValidationException}.cs
    Interfaces/{IFileDetectionService, IFileUploadPipeline, IFileValidator, IMalwareScanner}.cs
    Models/{FileSignature, FileTypeInfo, FileUploadPolicy, FileUploadRequest,
            FileValidationError, FileValidationResult, MalwareScanResult}.cs
    Policies/PolicyEngine.cs
  Detection/{ExtensionResolver, FileSignatureDetector, FileTypeResolver,
             MimeDetector, TextFormatDetector}.cs
  Pipeline/FileUploadPipeline.cs
  Validation/{ArchiveStructureValidator, CompositeValidator, FileContentValidator,
              FileExtensionValidator, FileNameValidator, FileSignatureValidator,
              FileSizeValidator, ImageDimensionParser, ImageStructureValidator,
              OfficeStructureValidator, PdfStructureValidator, StreamHelper}.cs
```
(نام‌گذاری: `FileTypeResolver` در README قدیمی گاهی `FileTokenTypeResolver` نوشته شده — در کد `FileTypeResolver` است.)