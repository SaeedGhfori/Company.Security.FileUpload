# Company.Security.FileUpload

یک کتابخانه اعتبارسنجی آپلود فایل برای .NET 10، مبتنی بر
[OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).

کتابخانه **هرگز** نام فایل، MIME اعلام‌شده توسط کلاینت، یا اندازه اعلام‌شده را اعتماد نمی‌کند.
بایت‌های واقعی را بررسی می‌کند (magic bytes + ساختار container)، هر اعلامیه را با واقعیت تطبیق
می‌دهد، یک *پالیسی* قابل استفاده مجدد اعمال می‌کند، و اختیاری اسکنر بدافزار اجرا می‌کند.

> **قانون طراحی:** کتابخانه Core **هیچ وابستگی NuGet خارجی ندارد** — فقط روی BCL اجرا
> می‌شود. اسکنر بدافزار خودتان (ClamAV، Windows Defender، ...) را از طریق رابط کوچک
> `IMalwareScanner` متصل کنید.

---

## فهرست مطالب

- [امکانات](#امکانات)
- [فرمت‌های پشتیبانی‌شده](#فرمت‌های-پشتیبانی‌شده)
- [شروع سریع](#شروع-سریع)
- [نحوه کار پایپلاین](#نحوه-کار-پایپلاین)
- [ورودی‌های متد `ProcessAsync`](#ورودی-های-متد-processasync)
- [پیکربندی پالیسی](#پیکربندی-پالیسی)
- [تشخیص نوع](#تشخیص-نوع)
- [اعتبارسنجی](#اعتبارسنجی)
- [اسکنر بدافزار](#اسکنر-بدافزار)
- [قابلیت توسعه](#قابلیت-توسعه)
- [مدل خطاها](#مدل-خطاها)
- [عملکرد و محدودیت‌ها](#عملکرد-و-محدودیت‌ها)
- [پوشش OWASP](#پوشش-owasp)
- [ساخت و تست](#ساخت-و-تست)

---

## امکانات

- **تشخیص بر اساس محتوا، نه اعتماد به پسوند** — magic bytes، text patterns، و بازبینی
  container (RIFF، EBML، `ftyp`، ZIP/OOXML، OLE‑CFB).
- **موتور پالیسی fail‑closed** — فایل‌های ناشناخته، عدم تطابق سیگنچر، عدم تطابق MIME به
  صورت پیش‌فرض رد می‌شوند. قابل تنظیم برای فقط هشدار دادن.
- **اعتبارسنجی ساختار** — تصاویر (PNG/JPEG/GIF/BMP/WEBP/TIFF)، PDFها، آرشیوهای ZIP،
  بسته‌های آفیس OOXML.
- **تحکیم آرشیو** — zip‑slip / path traversal داخل آرشیوها، محدودیت نسبت zip‑bomb،
  تعداد entry، عمق تو در تو، تشخیص آفیس با ماکرو.
- **محدودیت‌های منابع تصویر** — حداکثر عرض / ارتفاع / تعداد پیکسل (محافظت در برابر pixel‑bomb).
- **تحکیم نام فایل** — path traversal، نام‌های رزرو شده (CON, PRN, ...)، کاراکترهای کنترلی،
  چند پسوند، بدون پسوند.
- **اسکنر بدافزار اختیاری** — `IMalwareScanner` قابل اتصال با سیاست‌های clean / infected / error /
  unknown.
- **محدودیت‌های منابع در همه جا** — هر مرحله `CancellationToken` و خواندن‌های محدود را رعایت
  می‌کند.
- **صفر وابستگی خارجی در Core** — هدف `net10.0`، فقط BCL.

---

## فرمت‌های پشتیبانی‌شده

| دسته‌بندی | فرمت‌ها |
|---|---|
| تصویر | JPEG, PNG, GIF (87a/89a), BMP, TIFF (II/MM), WEBP (RIFF container) |
| SVG | SVG (text `<svg`) |
| ویدیو | MP4 / MOV (`ftyp`), MKV / WEBM (EBML), AVI (RIFF) |
| صدا | MP3 (ID3), FLAC, OGG, WAV (RIFF) |
| سند | PDF (`%PDF-`), DOC / XLS / PPT (OLE‑CFB), تشخیص OLE قدیمی |
| آفیس | DOCX / XLSX / PPTX (ZIP + `[Content_Types].xml`) |
| آرشیو | ZIP (+ empty/spanned variants), 7Z, TAR, GZIP, RAR |
| باینری | EXE (PE `MZ`), OLE‑CFB container |

تشخیص توسط:
1. `FileSignatureDetector` — کاتالوگ سیگنچر بایتی + text pattern (`FileSignatures`).
2. `FileTypeResolver` — بازبینی container روی کاتالوگ (فرمت‌هایی مانند MP4/MOV/WEBM/AVI
   که اندازه box متغیر دارند با magic offset ثابت قابل توصیف نیستند).

---

## شروع سریع

```csharp
using Company.Security.FileUpload;
using Company.Security.FileUpload.Core.Models;

// ۱. پالیسی
var policy = new FileUploadPolicy
{
    PolicyName = "AvatarUpload",
    FileKinds = new FileKinds
    {
        AllowedCategories = FileTypeCategory.Image,
        AllowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".webp" },
        ExtensionMismatchPolicy = ExtensionMismatchPolicy.Reject,
        UnknownFilePolicy = UnknownFilePolicy.Reject
    },
    FileSizes = new FileSizes { MaxFileSizeBytes = 5 * 1024 * 1024 },
    Structures = new Structures
    {
        MaxImageWidth = 4000,
        MaxImageHeight = 4000,
        MaxPixelCount = 16_000_000
    }
};

// ۲. پایپلاین
var pipeline = new FileUploadPipelineBuilder()
    .UseDefaultDetection()
    .WithDefaultValidators()
    .Build();

// ۳. درخواست
using var upload = File.OpenRead("photo.png");
var request = new FileUploadRequest
{
    FileStream = upload,
    OriginalFileName = "photo.png",
    DeclaredMimeType = "image/png",
    DeclaredFileSize = upload.Length,
    Policy = policy
};

// ۴. اعتبارسنجی
var result = await pipeline.ProcessAsync(request);

if (!result.IsValid)
{
    foreach (var error in result.Errors)
        Console.WriteLine($"{error.Code}: {error.Message}");
}
else
{
    Console.WriteLine($"واقعیش: {result.DetectedFileType.FormatName}");
}
```

---

## نحوه کار پایپلاین

`FileUploadPipeline.ProcessAsync(request)` یک جریان ثابت و متوالی اجرا می‌کند:

1. **قابلیت seek** — اگر stream قابل seek نبود، تا `FileSizes.MaxFileSizeBytes + 1` بافر می‌شود.
2. **تشخیص** — `IFileDetectionService.DetectAsync` یک پیشوند محدود خوانده و `FileTypeInfo`
   برمی‌گرداند (پسوند، MIME، دسته‌بندی، فرمت، نتیجه سیگنچر).
3. **اعتبارسنج‌ها** — هر `IFileValidator` روی نوع تشخیص‌داده‌شده و درخواست اجرا می‌شود و
   خطاها (و اختیاری هشدارها) را بدون توقف زنجیره جمع‌آوری می‌کند.
4. **موتور پالیسی** — `PolicyEngine` پالیسی `FileUploadPolicy` را اعمال می‌کند: دسته‌بندی‌ها /
   پسوندها / MIME types / فرمت‌ها، عدم تطابق پسوند vs نوع واقعی، سیاست فایل ناشناخته،
   محدودیت‌های اندازه.
5. **اسکن بدافزار (اختیاری)** — فقط وقتی اعتبارسنجی رد نشده و
   `policy.MalwareScanning.RequireMalwareScan == true` باشد. نتیجه اسکن در `FileValidationResult.MalwareScanResult`
   ثبت می‌شود.

---

## ورودی‌های متد `ProcessAsync`

امضای متد فقط دو پارامتر دارد؛ پالیسی داخل `request` است:

```csharp
Task<FileValidationResult> ProcessAsync(FileUploadRequest request, CancellationToken cancellationToken = default)
```

### `FileUploadRequest` — شش فیلد

همه‌ی ادعاهای کلاینت (نام، پسوند، MIME، اندازه) فقط **برای مقایسه با بایت‌های واقعی** به‌کار
می‌روند؛ تصمیم نهایی را پالیسی می‌گیرد.

| فیلد | نوع | هدف |
|---|---|---|
| `FileStream` | `Stream` (الزامی) | بایت‌های واقعی فایل؛ می‌تواند non‑seekable باشد |
| `OriginalFileName` | `string` (الزامی) | پسوند اعلام‌شده + قواعد نام فایل روی همین بررسی می‌شود |
| `DeclaredMimeType` | `string?` | MIME ادعا‌شده توسط کلاینت؛ تطبیق با واقعیت → عدم تطابق = خطا |
| `DeclaredFileSize` | `long?` | اندازه‌ی ادعا‌شده؛ اگر با اندازه‌ی واقعی یکی نباشد → خطا |
| `Policy` | `FileUploadPolicy?` | قوانین؛ بدون آن `InvalidOperationException` پرتاب می‌شود |
| `CancellationToken` | `CancellationToken` | توکن پشتیبان؛ وقتی توکن خودِ متد نادیده باشد به‌کار می‌رود |

### `FileUploadPolicy` — پنج گروه، هر کدام یک هدف

| گروه | هدف | زیرخاصیت‌ها |
|---|---|---|
| `FileKinds` | **چه نوع فایلی مجاز است** | دسته‌ها، پسوندها، MIMEها، فرمت‌ها + سیاست فایل ناشناخته و عدم تطابق پسوند |
| `FileNames` | **نام فایل چه شکلی باشد** | حداکثر طول، اجازه‌ی بدون پسوند / چندپسوندی |
| `FileSizes` | **اندازه و مصرف حافظه** | حداکثر/حداقل اندازه، آستانه‌ی بافر RAM، پوشه‌ی فایل موقت |
| `Structures` | **بررسی ساختار واقعی container** | ساختار تصویر/PDF/آرشیو/Office، محدودیت ابعاد و pixel‑bomb، ماکرو |
| `MalwareScanning` | **اسکن بدافزار** | اجرا/رد/قبول در برابر خطا و نتیجه‌ی بی‌نتیجه |

> جزئیات کامل هر زیرخاصیت با پیش‌فرض‌ها → [پیکربندی پالیسی](#پیکربندی-پالیسی) ↓

---

## پیکربندی پالیسی

`FileUploadPolicy` یک رکورد (غیرقابل تغییر؛ با `with` مشتقات بسازید) با **۵ گروه named** است.
هر گروه در `Company.Security.FileUpload.Core.Models` تعریف شده و با `with` روی خودِ گروه
تغییر می‌کند:

```csharp
// تغییر یک زیرخاصیت: گروه را هم with کنید
var p2 = policy with { FileSizes = policy.FileSizes with { MaxFileSizeBytes = 20 * 1024 * 1024 } };
```

### `FileKinds` — نوع / پسوند / MIME

| زیرخاصیت | پیش‌فرض | هدف |
|---|---|---|
| `AllowedCategories` | `FileTypeCategory.All` | لیست مجاز دسته‌بندی‌ها (bit‑flag) |
| `AllowedExtensions` | خالی → همه | لیست مجاز پسوندها (`".png"` یا `"png"`) |
| `AllowedMimeTypes` | خالی → همه | لیست مجاز MIME types |
| `AllowListedFormats` | خالی → همه | لیست مجاز نام فرمت‌ها (`"PNG"`) |
| `UnknownFilePolicy` | `Reject` | فایل ناشناخته: `Reject`، `Quarantine`، یا `Allow` |
| `ExtensionMismatchPolicy` | `Reject` | پسوند ≠ نوع واقعی: `Reject` یا `Warn` |

> وقتی `AllowedCategories` و `AllowedExtensions` هر دو خالی باشند، پایپلاین هر فرمت
> تشخیص‌داده‌شده‌ای را قبول می‌کند. برای تولید، حداقل یک لیست مجاز را پر کنید.

### `FileNames` — قواعد نام

| زیرخاصیت | پیش‌فرض | معنی |
|---|---|---|
| `AllowFileWithoutExtension` | `false` | فایل بدون پسوند مجاز باشد |
| `AllowMultipleExtensions` | `false` | فایل‌هایی مانند `file.tar.gz` مجاز باشند |
| `MaxFileNameLength` | `255` | حداکثر طول نام فایل |

### `FileSizes` — اندازه و بافر موقت

| زیرخاصیت | پیش‌فرض | بررسی |
|---|---|---|
| `MaxFileSizeBytes` | 10 MB | حداکثر اندازه مطلق |
| `MinFileSizeBytes` | 0 | حداقل اندازه |
| `TempFileThresholdBytes` | 10 MB | سقف RAM برای بافر؛ بزرگ‌تر/نامعلوم → دیسک |
| `TempDirectory` | null | پوشه‌ی فایل موقت سفارشی؛ null → `Path.GetTempPath()` |

### `Structures` — اعتبارسنجی ساختار

| زیرخاصیت | پیش‌فرض | معنی |
|---|---|---|
| `RequireStructureValidation` | `true` | کلید اصلی اعتبارسنجی ساختار |
| `StructureReadLimitBytes` | 256 KB | پیش‌خواندن اعتبارسنجی ساختار |
| `MaxImageWidth` / `Height` | 0 (خاموش) | محدودیت ابعاد تصویر |
| `MaxPixelCount` | 0 (خاموش) | محدودیت تعداد پیکسل |
| `ArchiveMaxEntries` | 1000 | حداکثر entry در آرشیو |
| `ArchiveMaxDepth` | 5 | حداکثر عمق تو در تو |
| `ArchiveMaxExtractedSize` | 0 (خاموش) | حداکثر اندازه استخراج‌شده |
| `AllowMacroEnabledOfficeDocuments` | `false` | فایل‌های `.docm` با `vbaProject.bin` رد شوند |

### `MalwareScanning` — اسکنر بدافزار

| زیرخاصیت | پیش‌فرض | معنی |
|---|---|---|
| `RequireMalwareScan` | `false` | اجرای اسکنر وقتی اعتبارسنجی رد نشده |
| `RejectIfMalwareScanUnavailable` | `true` | اگر اسکنری نصب نباشد، رد شود |
| `MalwareScanErrorPolicy` | `Reject` | خطای اسکنر → رد یا قبول |
| `MalwareScanUnknownPolicy` | `Reject` | نتیجه نامعلوم اسکنر → رد یا قبول |

---

## تشخیص نوع

`IFileDetectionService.DetectAsync(stream, declaredExtension, declaredMimeType, ct)`
یک `FileTypeInfo` برمی‌گرداند:

```csharp
var detected = new FileTypeResolver().DetectAsync(stream, ct);
Console.WriteLine(detected.FormatName);                  // "PNG"
Console.WriteLine(detected.DetectedExtension);           // ".png"
Console.WriteLine(detected.DetectedMimeType);            // "image/png"
Console.WriteLine(detected.Category);                    // FileTypeCategory.Image
Console.WriteLine(detected.ExtensionMatchesSignature);   // declared vs واقعی
Console.WriteLine(detected.HasValidSignature);           // true
Console.WriteLine(detected.IsKnownFormat);               // true
```

لایه‌های تشخیص (FileTokenTypeResolver):
1. **بازبینی container** — RIFF → AVI/WAV/WEBP; EBML → MKV/WEBM; `ftyp` → MP4/MOV;
   ZIP → DOCX/XLSX/PPTX از طریق `[Content_Types].xml`; OLE‑CFB → DOC/XLS/PPT.
2. **کاتالوگ magic bytes** — `FileSignatureDetector` + `FileSignatures`.
3. **Text patterns** — `TextFormatDetector` برای `<?xml` و غیره.
4. **ناشناخته** — با `FormatName = "UNKNOWN"`، `IsKnownFormat = false`،
   `HasValidSignature = false` برمی‌گردد → تابع `UnknownFilePolicy`.

---

## اعتبارسنجی

`WithDefaultValidators()` این `IFileValidator`ها را ثبت می‌کند (همه در namespace
`Company.Security.FileUpload.Validation`):

| اعتبارسنج | چه چیزی را بررسی می‌کند |
|---|---|
| `FileNameValidator` | نام خالی / خیلی طولانی، path traversal، نام‌های رزرو شده، null bytes، کاراکترهای غیرمجاز، قوانین پسوند |
| `FileExtensionValidator` | لیست مجاز پسوندها، پسوند نداشتن |
| `FileSizeValidator` | خالی، خیلی بزرگ / خیلی کوچک (دقیق یا محدود، ایمن برای غیر seekable) |
| `FileSignatureValidator` | تشخیص سیگنچر ناشناخته، سیگنچر در برابر لیست مجاز، عدم تطابق پسوند vs سیگنچر |
| `FileContentValidator` | MIME اعلام‌شده vs واقعی، اندازه اعلام‌شده vs واقعی |
| `ImageStructureValidator` | تحلیل هدر تصویر، محدودیت ابعاد و تعداد پیکسل |
| `PdfStructureValidator` | هدر `%PDF-`، تریلر `%%EOF` |
| `ArchiveStructureValidator` | zip‑slip paths، تعداد entry، zip‑bomb ratio، عمق تو در تو، آرشیو خراب |
| `OfficeStructureValidator` | بخش‌های مورد نیاز OOXML، تشخیص ماکرو `vbaProject.bin` |
| `CompositeValidator` | اجرای مجموعه‌ای از اعتبارسنج‌ها و تجمیع نتایج |

### معنای تطبیق پسوند

`ExtensionResolver.Normalize("photo.png")` مقدار `"png"` برمی‌گرداند (بدون نقطه، lowercase).
مقایسه‌های لیست مجاز از `IsEquivalentExtension` استفاده می‌کنند بنابراین `".png"`، `"png"`،
و نام‌های مستعار (`jpeg`→`jpg`، `tif`→`tiff`، `htm`→`html`، `mpeg`→`mpg`) یکسان رفتار
می‌شوند.

---

## اسکنر بدافزار

`IMalwareScanner` را پیاده‌سازی کنید و به پایپلاین متصل کنید:

```csharp
public interface IMalwareScanner
{
    string ScannerName { get; }
    Task<MalwareScanResult> ScanAsync(Stream stream, CancellationToken ct = default);
}
```

نتیجه را از `MalwareScanResult.Clean(name)`، `.Infected(name, threat)`،
`.Error(name)`، یا `.Unknown(name)` برگردانید. پایپلاین وضعیت‌ها را بر اساس
`MalwareScanning.MalwareScanErrorPolicy` / `MalwareScanning.MalwareScanUnknownPolicy` نگاشت
می‌کند و وضعیت را در `FileValidationResult.MalwareScanResult` ثبت می‌کند.

---

## قابلیت توسعه

همه چیز بر اساس رابط است، بنابراین می‌توانید هر مرحله را جایگزین یا بسته‌بندی کنید:

- **تشخیص:** `IFileDetectionService` را پیاده‌سازی کنید، یا `FileSignatureDetector` را با
  ارسال `FileSignature`های سفارشی به سازنده‌اش گسترش دهید.
- **اعتبارسنجی:** `IFileValidator` را پیاده‌سازی کنید و از طریق `builder.AddValidator(...)`
  ثبت کنید (یا `WithDefaultValidators()` برای مجموعه استاندارد).
- **اسکنر:** `IMalwareScanner` را برای هر موتور AV پیاده‌سازی کنید.
- **پالیسی:** `FileUploadPolicy` یک رکورد با گروه‌های named است — با `with` روی هر گروه ترکیب کنید.

---

## مدل خطاها

`FileValidationResult`:

```csharp
IsValid                    // bool — نتیجه نهایی
Errors                     // IReadOnlyList<FileValidationError> — لیست خطاها
Warnings                   // IReadOnlyList<string> — هشدارها (در حالت Warn)
DetectedFileType           // FileTypeInfo? — نوع واقعی تشخیص‌داده‌شده
FileSizeBytes              // long — اندازه واقعی
MalwareScanResult          // MalwareScanStatus? — وضعیت اسکن بدافزار
ValidationDuration         // TimeSpan — مدت زمان بررسی
```

`FileValidationError` شامل `{ Code, Message, InnerException?, Metadata }` است.
`FileValidationErrorCode` خطاها را بر اساس حوزه گروه‌بندی می‌کند:

- `1xxx` — نام فایل
- `2xxx` — پسوند
- `3xxx` — اندازه
- `4xxx` — سیگنچر
- `5xxx` — MIME
- `6xxx` — ساختار (تصویر/PDF/ZIP/OOXML)
- `7xxx` — نوع ناشناخته
- `8xxx` — بدافزار
- `10xxx` — پالیسی
- `11xxx` — لغو درخواست

کتابخانه همچنین `FileValidationException` (شامل `ErrorCode`) و
`FileUploadSecurityException` برای خطاهای امنیتی سنگین پرتاب می‌کند.

---

## عملکرد و محدودیت‌ها

- اعتبارسنجی ساختار حداکثر `Structures.StructureReadLimitBytes` (پیش‌فرض **256 KB**) می‌خواند.
- Streamهای غیر seekable تا `FileSizes.MaxFileSizeBytes + 1` بافر می‌شوند؛ رشد بیشتر به عنوان
  `FileTooLarge` تلقی می‌شود.
- بازرسی آرشیو خواندن‌های uncompressed را محدود می‌کند و هدر ZIP را روی stream ای که به
  موقعیت اصلی بازگردانده می‌شود بررسی می‌کند.

---

## پوشش OWASP

| الزام OWASP File Upload | محل پیاده‌سازی | پوشش تست |
|---|---|---|
| اعتبارسنجی نوع فایل از محتوا (magic bytes) | `FileSignatureDetector`, `FileTypeResolver` | `ValidPng_Accepted` |
| به پسوند فایل اعتماد نکنید | `PolicyEngine`, `FileSignatureValidator` | `PngBytesNamedJpg_Rejected_ExtensionMismatch` |
| به Content-Type / MIME اعتماد نکنید | `FileContentValidator`, `MimeDetector` | `FakeMime_Rejected_MimeMismatch` |
| لیست مجاز پسوندها | `FileExtensionValidator`, `PolicyEngine` | `MultipleExtension_Rejected` |
| کنترل فایل بدون پسوند / چند پسوند | `FileNameValidator`, `FileExtensionValidator` | `NoExtension_Rejected` |
| رد فایل‌های ناشناخته (fail closed) | `PolicyEngine` (`UnknownFilePolicy`) | `UnknownFile_Rejected` |
| محدودیت‌های اندازه (شامل فایل خالی) | `FileSizeValidator`, `PolicyEngine` | `FileTooLarge_Rejected`, `EmptyFile_Rejected_FileEmpty` |
| اعتبارسنجی ساختار (واقعی، نه فقط magic bytes) | `ImageStructureValidator`, `PdfStructureValidator`, `OfficeStructureValidator` | `TruncatedFile_Rejected_StructureInvalid`, `SignatureValidButStructureCorrupt_Rejected` |
| zip‑slip / path traversal داخل آرشیوها | `ArchiveStructureValidator` | `ZipWithMaliciousEntryPath_Rejected` |
| zip‑bomb / محدودیت نسبت decompression | `ArchiveStructureValidator` | `ZipBomb_Rejected` |
| محدودیت تعداد entry و عمق آرشیو | `ArchiveStructureValidator` | `ZipTooManyEntries_Rejected`, `ZipNestedTooDeep_Rejected` |
| اسکنر بدافزار | `IMalwareScanner`, pipeline | `MalwareScanTests` (clean/infected/error/unknown) |
| جلوگیری از path traversal در نام فایل | `FileNameValidator`, `ExtensionResolver` | `PathTraversalFileName_Rejected` |
| تشخیص آفیس با ماکرو | `OfficeStructureValidator` | `OfficeStructureValidator` tests |
| محدودیت ابعاد / pixel‑bomb تصویر | `ImageStructureValidator`, `ImageDimensionParser` | `ImageTooLargeDimensions_Rejected`, `ImagePixelCountExceeded_Rejected` |
| لغو و محدودیت‌های منابع | کل پایپلاین + اعتبارسنج‌ها | `CancellationRequested_Throws` |

---

## ساخت و تست

```powershell
# ساخت کتابخانه
dotnet build "Company.Security.FileUpload.slnx" -c Release

# اجرای تست‌ها
dotnet test "Company.Security.FileUpload.Tests" -c Debug
```

نیازمندی: .NET 10 SDK. کتابخانه روی `net10.0` هدف دارد و فقط به BCL وابسته است.

---

## ساختار پروژه

```
Company.Security.FileUpload.slnx
Company.Security.FileUpload/
  Core/
    Constants/FileSignatures.cs        # کاتالوگ magic bytes
    Enums/…                            # کدها خطا، دسته‌بندی‌ها، سیاست‌ها
    Interfaces/…                       # IFileDetectionService, IFileValidator,
                                       # IMalwareScanner
    Models/…                           # FileUploadPolicy, FileTypeInfo,
                                       # FileValidationResult, FileUploadRequest, …
    Policies/PolicyEngine.cs           # مotor پالیسی fail-closed
    Exceptions/…                       # FileValidationException, FileUploadSecurityException
  Detection/                           # ExtensionResolver, FileSignatureDetector,
                                       # TextFormatDetector, MimeDetector, FileTypeResolver
  Validation/                          # اعتبارسنج‌های نام/پسوند/اندازه/امضا/محتوا + ساختار
                                       # (تصویر، PDF، آرشیو، آفیس)، StreamHelper
  Pipeline/FileUploadPipeline.cs       # هماهنگ‌کننده اصلی
  FileUploadPipelineBuilder.cs         # ساخت ترکیبی
Company.Security.FileUpload.Tests/     # مجموعه تست xUnit (مبتنی بر OWASP)
```

---

## مجوز

پروژه اختصاصی / داخلی. شرایط مجوز سازمان خودتان را قبل از استفاده مجدد ببینید.