# Security Review Architecture Analysis - Company.Security.FileUpload

## Validation Pipeline Architecture

### Data Flow Diagram (Text Representation)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FileUploadRequest                                 │
│  FileStream (client-supplied)                                        │
│  OriginalFileName (client-supplied)                                  │
│  DeclaredMimeType (client-supplied)                                  │
│  DeclaredFileSize (client-supplied)                                  │
│  Policy (consumer-configured, REQUIRED)                              │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    EnsureSeekableAsync                               │
│  • If CanSeek: pass through                                          │
│  • If !CanSeek: buffer to memory up to MaxFileSizeBytes + 1           │
│  • Restore original position if seekable                             │
│  • Return: seekable stream (possibly new MemoryStream)               │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    DetectAsync (IFileDetectionService)               │
│  Layer 1: TryDetectContainerRefined                                    │
│    • RIFF: AVI, WAV, WEBP (form type at bytes 8-12)                   │
│    • EBML: MKV, WEBM (EBML header + webm check)                      │
│    • MP4/MOV: ftyp box at offset 4                                    │
│    • ZIP: reads [Content_Types].xml for DOCX/XLSX/PPTX                │
│    • OLE-CFB: WordDocument/Workbook/PowerPoint detection               │
│  Layer 2: FileSignatureDetector.DetectAsync                            │
│    • 8KB read limit                                                    │
│    • Magic bytes catalog: 35+ entries (JPEG, PNG, GIF, BMP, TIFF,      │
│      WEBP, SVG, MKV, MP3, FLAC, OGG, PDF, XML, ZIP, 7Z, TAR, GZIP,     │
│      OLE-CFB, EXE, RAR)                                               │
│    • Text patterns: XML (<?xml), SVG (<svg), JSON ({/[), CSV           │
│  Layer 3: TextFormatDetector.Detect                                    │
│    • XML detection                                                     │
│    • SVG detection (<svg)                                              │
│    • JSON detection ({ or [ start)                                     │
│    • CSV vs TEXT detection (comma + newline)                          │
│  Layer 4: Unknown Fallback                                             │
│    • IsKnownFormat = false, FormatName = "UNKNOWN"                     │
│    • Triggers UnknownFilePolicy (default: Reject)                     │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Validator Execution                                 │
│  Fixed order via WithDefaultValidators():                              │
│  1. FileNameValidator — path traversal, reserved names, invalid chars   │
│  2. FileExtensionValidator — allowlist check, missing extension          │
│  3. FileSizeValidator — empty, too large / too small                   │
│  4. FileSignatureValidator — signature detection, extension mismatch     │
│  5. FileContentValidator — declared MIME/size vs actual                 │
│  6. ImageStructureValidator — dimensions, pixel count                   │
│  7. PdfStructureValidator — %PDF- header, %%EOF trailer                │
│  8. ArchiveStructureValidator — ZIP: path, count, ratio, depth          │
│  9. OfficeStructureValidator — OOXML parts, macro detection            │
│  10. CompositeValidator — aggregates all results                       │
│  11. (Implementation-specific additions possible)                     │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    PolicyEngine.Evaluate                               │
│  • Unknown file handling: UnknownFilePolicy (Reject/Allow/Quarantine)  │
│  • Category check: (AllowedCategories & detectedType.Category) == 0     │
│  • Extension allowlist: Contains(detectedType.DetectedExtension)        │
│  • MIME allowlist: Contains(detectedType.DetectedMimeType)              │
│  • Format allowlist: Contains(detectedType.FormatName)                │
│  • Extension mismatch: declared vs detected (IsEquivalentExtension)     │
│  • Size limits: MaxFileSizeBytes, MinFileSizeBytes                     │
│  • Returns: FileValidationResult with errors, warnings                 │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Malware Scan (optional)                           │
│  • Only if: policy.RequireMalwareScan == true AND validation passed    │
│  • Calls: IMalwareScanner.ScanAsync(stream)                           │
│  • Maps: Clean → pass, Infected → reject, Error → per policy,         │
│          Unknown → per policy                                          │
│  • Records: FileValidationResult.MalwareScanResult                     │
└─────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FileValidationResult                              │
│  • IsValid: bool                                                       │
│  • Errors: IReadOnlyList<FileValidationError>                        │
│  • Warnings: IReadOnlyList<string>                                   │
│  • DetectedFileType: FileTypeInfo?                                    │
│  • FileSizeBytes: long                                                 │
│  • MalwareScanResult: MalwareScanStatus?                              │
│  • ValidationDuration: TimeSpan                                      │
│  • Metadata: IReadOnlyDictionary<string, object>                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

| Boundary | Source | Data Type | Trust Status | Enforcement |
|----------|--------|-----------|--------------|-------------|
| Client Input | User/Client | File stream, filename, MIME type, size | **Never trusted** | Validated at every pipeline stage |
| Detection Signals | Library internal | Magic bytes, container structure, text patterns | **Signals only** | Used for classification, not final acceptance |
| Policy Configuration | Consumer | AllowedCategories, AllowedExtensions, AllowedMimeTypes, AllowListedFormats, behavioral policies | **Enforced as configured** | Library enforces exactly what's configured |
| Malware Scanner | External plug-in | Scan result (Clean/Infected/Error/Unknown) | **Mapped per policy** | Library maps per policy.MalwareScanErrorPolicy / MalwareScanUnknownPolicy |
| Stream State | Internal | Position, CanSeek, length | **Managed internally** | Position restoration after each stage; consumers should not rely on specific position |

### Security-Critical Components

1. **PolicyEngine.Evaluate()** — Final acceptance boundary
   - Checks all allowlists and behavioral policies
   - Last chance to reject before result finalization
   - Error codes: FileTypeUnknown (7000), FileTypeNotAllowed (7001), ExtensionMismatch (2003), FileTooLarge (3000), FileTooSmall (3001), MimeNotAllowed (5000)

2. **FileSignatureDetector.DetectAsync()** — 8KB signature matching
   - Reads at most 8KB from stream for magic byte detection
   - Priority-based best match from 35+ catalog entries
   - Offset-based matching; short files handled by checking prefix.Length
   - Vulnerability: Short file handling — if file < 8KB, only available bytes are checked

3. **FileTypeResolver.TryDetectContainerRefined()** — Container inspection
   - RIFF: reads bytes 8-12 for form type (AVI, WAV, WEBP)
   - EBML: reads header for webm/MKV detection
   - MP4/MOV: reads ftyp box at offset 4 (brand bytes)
   - ZIP: reads [Content_Types].xml for DOCX/XLSX/PPTX resolution
   - OLE-CFB: reads first 8 bytes for Word/Excel/PowerPoint detection

4. **ArchiveStructureValidator** — ZIP security hardening
   - Path traversal detection: entries with `../` paths rejected
   - Zip-bomb detection: compression ratio limits
   - Entry count limit: configurable ArchiveMaxEntries (default 1000)
   - Nesting depth limit: configurable ArchiveMaxDepth (default 5)

5. **FileNameValidator** — Filename security
   - Path traversal: `..`, `/`, `\`, `:` detected via LooksLikePathTraversal()
   - Reserved Windows names: CON, PRN, AUX, NUL, COM1-9, LPT1-9
   - Null bytes: `\0` detection
   - Invalid characters: Path.GetInvalidFileNameChars() + control chars

### Configuration Flow

```
Consumer → FileUploadPolicy (record with 30+ properties)
         → FileUploadPipelineBuilder (fluent API)
         → FileUploadPipeline (immutable after build)
         → ProcessAsync(request) → FileValidationResult
```

### External Integrations

| Integration | Library Responsibility | Consumer Responsibility |
|------------|----------------------|----------------------|
| Malware Scanner | IMalwareScanner interface, scan result mapping | Implement scanner, configure UseMalwareScanner(), set scan policies |
| File Storage | **REMOVED** (library focuses on validation only) | Implement IFileStorage or use external storage |
| HTTP Response | **NOT supported** by library | Add headers: X-Content-Type-Options: nosniff, Content-Disposition |
| CDN/WAF | **NOT supported** by library | Configure at infrastructure level |
| Database Storage | **NOT supported** by library | Consumer handles DB operations |
| Rate Limiting | **NOT supported** by library | Consumer middleware/attribute |

### Thread Safety & Reusability

- **Stateless validators:** All `IFileValidator` implementations are stateless; `WithDefaultValidators()` creates new instances per pipeline build
- **PolicyEngine.With():** Clears warnings on each call; mutable `_warnings` list but reset on `With()` call
- **Detection services:** `FileTypeResolver` and `FileSignatureDetector` are stateless; can be shared across requests
- **Pipeline reuse:** `FileUploadPipeline` can be reused across requests (immutable state after build)
- **Cross-request state:** None; all state is either in the request/response or explicitly configured in policy
- **Configuration leakage:** Prevented — each `With(policy)` call resets warnings and sets new policy

### Dependency Structure

```
Company.Security.FileUpload (net10.0, BCL only)
├── System.IO.Compression (ZipArchive for ZIP parsing)
├── System.Buffers.Binary (BinaryPrimitives for endian reading)
├── System.Text (Encoding for ASCII/UTF-8)
├── System.Runtime.CompilerServices (ValueTask for async I/O)
└── Zero external NuGet packages

Company.Security.FileUpload.Tests (net10.0)
├── coverlet.collector (6.0.4) — code coverage
├── Microsoft.NET.Test.Sdk (17.14.1) — test SDK
├── xunit (2.9.3) — unit testing framework
├── xunit.runner.visualstudio (3.1.4) — VS test runner
└── ProjectReference → Company.Security.FileUpload
```

### Key Design Decisions

1. **Fail-closed by default:** `UnknownFilePolicy = Reject`, `RejectIfMalwareScanUnavailable = true`, `ExtensionMismatchPolicy = Reject`
2. **No external NuGet dependencies:** Library targets `net10.0` using only BCL; zero trust chain from external packages
3. **Single entry point:** `ProcessAsync(FileUploadRequest, CancellationToken)` — one way to validate
4. **Extension normalization:** `Normalize()` returns extension WITHOUT leading dot (e.g., `"png"` not `".png"`); `IsEquivalentExtension()` handles dot/alias normalization
5. **Malware scan optional:** Only runs when `RequireMalwareScan == true` AND validation passes
6. **Archive validation on detection only:** Library detects ZIP containers and resolves OOXML (DOCX/XLSX/PPTX) but does NOT extract or validate content beyond structure
7. **Filename hardening in library:** Path traversal, reserved names, null bytes, invalid chars detected; storage name generation left to consumer
8. **Policy as record (immutable):** Use `with` to derive variants; `With(policy)` method on PolicyEngine for chaining