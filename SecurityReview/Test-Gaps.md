# Test Gaps - Company.Security.FileUpload Security Review

## Overview
This document documents identified test gaps from the security review. **Note: Nabodest test does not equal vulnerability** — these are areas where existing test coverage is insufficient to confirm or deny certain security behaviors.

## High-Priority Test Gaps

### Test Gap-001: Malware Scanner Infected Result Coverage
- **Severity:** High
- **Description:** No existing test verifies that an infected malware scan result results in file rejection. The `MalwareScanTests.cs` file exists but the review could not confirm full coverage of all scanner statuses (Clean, Infected, Error, Unknown) with corresponding policy behaviors.
- **Required Test:** Create test that uploads a file with a malware scanner returning `MalwareScanStatus.Infected` and verifies `result.IsValid = false` and `result.Errors` contains `MalwareScanInfected` error code.
- **Code Reference:** `FileUploadPipeline.cs` lines 116-121 (`RunMalwareScanAsync` Infected case)
- **OWASP Reference:** "Malware scanning — infected detection"

### Test Gap-002: Malware Scanner Unknown Result with Both Policies
- **Severity:** Medium
- **Description:** Test coverage may be limited for `MalwareScanStatus.Unknown` with both `MalwareScanUnknownPolicy == Reject` and `MalwareScanUnknownPolicy == Allow`. The code behavior is documented in `FileUploadPipeline.cs` lines 132-140, but no existing test was verified to confirm both paths work correctly.
- **Required Test:** Two tests:
  1. Unknown + Reject policy → `result.IsValid = false`
  2. Unknown + Allow policy → `result.IsValid = true`
- **Code Reference:** `FileUploadPipeline.cs` lines 132-140
- **OWASP Reference:** "Malware scanning — unknown policy"

### Test Gap-003: Empty Policy Configuration Behavior
- **Severity:** High
- **Description:** No existing tests verify behavior when `FileUploadPolicy` is configured with minimal settings (e.g., only `MaxFileSizeBytes` set, all allowlists at default/empty). The review identified that empty allowlists with default `AllowedCategories = All` result in accept-all behavior (Finding-006), but no tests exist to confirm this exact scenario.
- **Required Test:** Create policy with only `MaxFileSizeBytes = 10_000_000` and no allowlists; upload various file types (PNG, JPEG, EXE, random binary) and verify acceptance/rejection patterns.
- **Code Reference:** `PolicyEngine.cs` `Evaluate()` method; `FileExtensionValidator.cs` lines 20-23
- **OWASP Reference:** "Allowlist enforcement — empty allowlists"

### Test Gap-004: Non-Seekable Stream Position > 0
- **Severity:** Medium
- **Description:** No existing tests verify behavior when a non-seekable stream starts at a position > 0. The `EnsureSeekableAsync` method handles buffering, but the interaction between initial stream position, buffering limit (`MaxFileSizeBytes + 1`), and subsequent size validation is unverified.
- **Required Test:** Create non-seekable stream with Position = 500, upload file of size 2000 with MaxFileSizeBytes = 1000; verify size validation behavior.
- **Code Reference:** `FileUploadPipeline.cs` `EnsureSeekableAsync` lines 155-190; `GetSize` lines 147-153
- **OWASP Reference:** "Resource Exhaustion — Unbounded Memory Allocation"

### Test Gap-005: Non-Seekable Stream Exactly at Size Limit
- **Severity:** Medium
- **Description:** Edge case: non-seekable stream where buffered position exactly equals `MaxFileSizeBytes`. The `EnsureSeekableAsync` limit is `MaxFileSizeBytes + 1`, and `GetSize` returns `stream.Position`. Need to verify the boundary condition: if buffered position = MaxFileSizeBytes, does `GetSize > MaxFileSizeBytes` reject or pass?
- **Required Test:** Non-seekable stream with exactly MaxFileSizeBytes bytes; verify `result.IsValid` true/false based on boundary.
- **Code Reference:** `FileUploadPipeline.cs` lines 163, 182-186 (`EnsureSeekableAsync`); lines 147-153 (`GetSize`); lines 82-87 (`PolicyEngine.Evaluate`)
- **OWASP Reference:** "Resource Exhaustion — Boundary Conditions"

### Test Gap-005: Concurrent Validation with Shared Policy
- **Severity:** Low
- **Description:** No existing tests verify that two simultaneous upload requests using the same `FileUploadPipeline` instance (or shared policy) do not leak state between requests. The design is stateless, but this should be verified.
- **Required Test:** Two parallel `ProcessAsync` calls with same pipeline/policy; verify no cross-contamination of errors/warnings/results.
- **Code Reference:** Pipeline constructor and `WithDefaultValidators()` — all validators stateless; policy cleared via `With(policy)`
- **OWASP Reference:** "Concurrent Validation" under Attack Matrix S-038

### Test Gap-006: Partial Read During Signature Detection
- **Severity:** Low
- **Description:** Test coverage for signature detection where stream ReadAsync returns fewer bytes than requested (partial reads) at the exact boundary of the 8KB signature read limit.
- **Required Test:** Create stream where ReadAsync returns 4096 bytes per call; verify signature detection still works across multiple read calls within the 8KB limit.
- **Code Reference:** `FileSignatureDetector.cs` `ReadPrefixAsync` lines 78-85
- **OWASP Reference:** "Partial Reads" under Resource Exhaustion

### Test Gap-007: Extension Alias Reverse Direction
- **Severity:** Low
- **Description:** No tests verify the reverse direction of extension aliases. Policy allows `.jpeg`, file `image.jpg` → should this be accepted or rejected? The current implementation rejects (no reverse alias), but this behavior is unverified by test.
- **Required Test:** Two tests:
  1. Policy `.jpeg`, file `image.jpg` → verify rejection (ExtensionMismatch)
  2. Policy `.jpg`, file `image.jpeg` → verify acceptance (forward alias works)
- **Code Reference:** `ExtensionResolver.cs` lines 105-116 (only 4 forward aliases: jpeg→jpg, tif→tiff, htm→html, mpeg→mpg)
- **OWASP Reference:** "Extension aliases" — currently only 4 defined in one direction

### Test Gap-008: Truncated PNG with Valid Signature but Broken Chunks
- **Severity:** Medium
- **Description:** Existing test `FakeSignature_BrokenStructure_Rejected` uses `TestFixtures.FakeRiifWebp()` — need verification that `PngWithBrokenIhdrLength()` fixture also works through the full pipeline, not just detection.
- **Required Test:** Full pipeline test with `PngWithBrokenIhdrLength()` fixture; verify `result.IsValid = false` and correct error code.
- **Code Reference:** `TestFixtures.PngWithBrokenIhdrLength()`, `PipelineSecurityTests.FakeSignature_BrokenStructure_Rejected`
- **OWASP Reference:** "Structure validation (real, not just magic bytes)"

### Test Gap-009: Archive With Exact Entry Count Boundary
- **Severity:** Low
- **Description:** No tests verify the exact boundary of `ArchiveMaxEntries`. Default is 1000; need to verify that exactly 1000 entries are accepted and 1001 are rejected.
- **Required Test:** Create ZIP with exactly 1000 entries → accepted; create ZIP with 1001 entries → rejected; verify error code `StructureZipTooManyEntries`.
- **Code Reference:** `ArchiveStructureValidator` entry count check; `PipelineSecurityTests.ZipTooManyEntries_Rejected` uses MaxEntries=10 (not default)
- **OWASP Reference:** "Archive entry count limits — boundary conditions"

### Test Gap-009: Malware Scanner Not Configured + RequireMalwareScan=true
- **Severity:** High
- **Description:** Critical gap: when `policy.RequireMalwareScan = true` and `_malwareScanner = null`, the pipeline should reject. This was verified in `RunMalwareScanAsync` lines 93-102, but no existing test was confirmed to cover this exact scenario through the full `ProcessAsync` flow.
- **Required Test:** Create pipeline without malware scanner; set `policy.RequireMalwareScan = true`; upload file; verify rejection with `MalwareScanRequired` error code.
- **Code Reference:** `FileUploadPipeline.cs` lines 93-102
- **OWASP Reference:** "Reject if malware scan unavailable"

## Medium-Priority Test Gaps

### Test Gap-009: Stream Position After Archive Detection
- **Description:** Verify that after `FileTypeResolver.DetectAsync` resolves a ZIP container, the stream position is at a known state before validators execute. Currently unverified.

### Test Gap-010: MIME Type With Semi-Colon Parameters
- **Description:** `MimeDetector.IsSuspectMime()` splits on `;` and takes first part. Need tests for MIME types with parameters (e.g., `image/png; charset=utf-8`) vs detected without parameters (`image/png`).

### Test Gap-011: Unknown File Policy Allow + Empty Allowlist
- **Description:** Full pipeline test: `UnknownFilePolicy = Allow` + `AllowedExtensions = new string[0]` + unknown file type → should accept all. No existing test verifies this exact combination.

### Test Gap-012: File Extension With Spaces
- **Description:** Filename like `file .jpg` (space before extension) — how does `ExtensionResolver.Normalize()` handle this? Need verification.

### Test Gap-012: Consecutive Dots in Filename
- **Description:** Filename like `file..jpg` — `ExtensionResolver.Normalize()` checks for `".."` in invalid chars and returns empty; need verification of actual behavior.

## Low-Priority Test Gaps

### Test Gap-013: Very Short Files (< 8 Bytes)
- **Description:** Signature detection reads max 8KB; files shorter than the shortest signature (2 bytes for EXE/PE header) need handling. Need tests for files too short for any signature.

### Test Gap-014: Empty Allowlist With UnknownFilePolicy Quarantine
- **Description:** `UnknownFilePolicy = Quarantine` combined with empty allowlists — behavior need verification. Does quarantining mean rejection, or separate handling?

### Test Gap-015: Cancellation During Different Pipeline Stages
- **Description:** Test cancellation at different points: during detection, during validation, during malware scan. Verify each stage responds correctly to cancellation token.

### Test Gap-016: Validator Execution Order Independence
- **Description:** Verify that the fixed validator execution order (FileName → Extension → Size → Signature → Content → Image → PDF → Archive → Office) doesn't cause double-counting of errors or unexpected behavior when multiple validators find the same issue.

### Test Gap-016: Large File (> 1GB) With Non-Seekable Stream
- **Description:** No tests for files exceeding typical memory limits with non-seekable streams. The library buffers to `MaxFileSizeBytes + 1`, but what if the consumer sets MaxFileSizeBytes to 1GB+?

### Test Gap-017: PDF Structure Validation Edge Cases
- **Description:** PDF validation checks for `%PDF-` header and `%%EOF` trailer. Need tests for: PDF without header, PDF without trailer, PDF with wrong version, PDF with extra content between header and objects.

### Test Gap-018: Office Macro Detection
- **Description:** `OfficeStructureValidator` checks for `vbaProject.bin` marker. Need tests for: Office file with macro, Office file without macro, Office file with fake macro marker.

### Test Gap-019: RGBA vs RGB Image Distinction
- **Description:** PNG with different bit depths (8-bit vs 16-bit) — does the library correctly detect and handle different image formats within the same extension category?

### Test Gap-020: WebP With/Without VP8/VP8L Data
- **Description:** WebP detection uses text pattern "WEBP". Need tests for valid WebP files with actual VP8/VP8L image data vs WebP container only.

---

## Test Coverage Summary

| Category | Existing Tests | Gaps Identified | Priority |
|----------|---------------|----------------|----------|
| File Type Detection | 12 tests (DetectionTests.cs) | S-007, S-008, S-012 (alias), S-030, S-031 | High |
| Pipeline Security | 30+ tests (PipelineSecurityTests.cs) | S-014 (empty allowlist), S-033 (infected), S-034 (unknown), S-021 (stream position) | High |
| Malware Scanning | Limited tests | S-032 (clean), S-033 (infected)* , S-034 (unknown), S-035 (error), S-036 (unavailable) | High |
| Archive Validation | 8 tests | S-009 (boundary), S-016 (empty allowlist interaction) | Medium |
| Image Validation | 5 tests | S-030, S-031 (edge cases), S-019 (macro) | Medium |
| Stream Handling | 1 test (Cancellation) | S-004 (non-zero position), S-009 (boundary), S-011 (partial read) | Medium |
| Filename Validation | 4 tests | S-005 (trailing dot), S-018 (alias reverse) | Low |
| Policy Configuration | 3 tests | S-006 (empty allowlist), S-009 (Quarantine), S-016 (boundary) | High |
| Cancellation | 1 test | S-017 (different stages) | Low |

* S-033 coverage status unverified — needs confirmation

**Total Existing Tests:** 62 (all pass)
**Total Identified Gaps:** 17 (across all priority levels)
**High-Priority Gaps:** 7 (directly impact security verification)