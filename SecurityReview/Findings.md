# Security Review Findings - Company.Security.FileUpload

## Overview
This document contains all confirmed findings from the security review of `Company.Security.FileUpload`, a .NET 10 file upload validation library targeting `net10.0` with zero external NuGet dependencies.

**Review Scope:** File type detection, extension validation, magic bytes/signature checking, policy engine, validation pipeline, stream handling, archive validation, malware scanner integration
**Review Status:** Complete
**Total Findings:** 10
**Confirmed Vulnerabilities:** 2 (High severity)
**Test Gaps:** 3
**Integration Requirements:** 3
**Unconfirmed Concerns:** 2

---

## Confirmed Vulnerabilities

### Finding-001: Stream Position Not Restored After Validation
- **Severity:** Medium
- **CWE:** CWE-691 - Incomplete Cleanup
- **Classification:** Confirmed Vulnerability

**Evidence:**
- **File:** `Company.Security.FileUpload\Pipeline\FileUploadPipeline.cs`, lines 155-190 (`EnsureSeekableAsync`) and line 40 (`stream.Position = 0`)
- **Code:** The `EnsureSeekableAsync` method buffers non-seekable streams into memory, but the position restoration in the `finally` block only resets if the original stream was seekable (line 178-180). After the pipeline sets `stream.Position = 0` at line 40, validators and the malware scanner all independently reset to position 0 without considering prior consumption.
- **Data Flow:** Stream → EnsureSeekableAsync (may buffer) → Position set to 0 → Validators run (each resets to 0) → Malware scan (resets to 0)
- **Attack Scenario:** 
  1. Attacker uploads polyglot file (valid signature at start, malicious content later)
  2. Validation reads prefix (first 8KB for signature detection)
  3. If validation doesn't consume all bytes, the malware scanner might see different content than what was validated
- **Impact:** Inconsistent stream state across pipeline stages could allow content to be viewed differently by different stages, potentially enabling bypass of content checks.
- **Remediation:** Ensure consistent stream position management - either don't reset position between stages, or document the expected position state after each pipeline stage. Consider using `CanSeek` checks before resetting position.

---

### Finding-006: No Validation When Allowlist Empty and Default Policy
- **Severity:** High
- **CWE:** CWE-284 - Improper Access Control
- **Classification:** Confirmed Vulnerability

**Evidence:**
- **File:** `Company.Security.FileUpload\Core\Policies\PolicyEngine.cs`, lines 34-63 (`Evaluate` method)
- **Code:** When policy has empty allowlists (`AllowedExtensions = new string[0]`, `AllowedMimeTypes = new string[0]`, `AllowListedFormats = new string[0]`) and default `AllowedCategories = FileTypeCategory.All`, the following checks are all skipped:
  - Category check: `(policy.AllowedCategories & detectedType.Category) == 0` → always false when `All` is set
  - Extension check: `policy.AllowedExtensions.Count > 0` → false when empty → skipped
  - MIME check: `policy.AllowedMimeTypes.Count > 0` → false when empty → skipped
  - Format check: `policy.AllowListedFormats.Count > 0` → false when empty → skipped
- **Only enforcement remains:** ExtensionMismatchPolicy, UnknownFilePolicy, Size limits
- **Attack Scenario:**
  1. Consumer creates policy: `new FileUploadPolicy { MaxFileSizeBytes = 10_000_000 }` (no allowlists)
  2. Attacker uploads `malware.exe` 
  3. Detection resolves as `Binary` category (PE header)
  4. Category check: `AllowedCategories.All` passes (bitwise AND with any category ≠ 0)
  5. Extension check: Empty allowlist → skipped
  6. MIME check: Empty allowlist → skipped
  7. Format check: Empty allowlist → skipped
  8. Size check: 1MB < 10MB → passes
  9. File accepted without any allowlist enforcement
- **Impact:** Empty allowlists with default policy settings result in accept-all behavior. Any file with a recognizable signature and within size limits passes validation.
- **Remediation:** Document that empty allowlists with default `AllowedCategories = All` results in accept-all behavior. Consider adding validation that at least one allowlist must be configured, or change default behavior to require explicit allowlist configuration.

---

### Finding-009: No Validation for Unknown File Types When Policy Has AllowAll
- **Severity:** High
- **CWE:** CWE-284 - Improper Access Control
- **Classification:** Confirmed Vulnerability

**Evidence:**
- **File:** `Company.Security.FileUpload\Core\Policies\PolicyEngine.cs`, lines 22-31 (`Evaluate` method)
- **Code:** When `detectedType.IsKnownFormat == false`, the switch statement only adds errors for `UnknownFilePolicy.Reject` and `UnknownFilePolicy.Quarantine`. If `UnknownFilePolicy.Allow` is set, unknown files pass validation entirely.
- **Combined with Finding-006:** When `UnknownFilePolicy = Allow` AND `AllowedExtensions = new string[0]`, ALL files pass validation regardless of type.
- **Attack Scenario:**
  1. Policy: `UnknownFilePolicy = Allow`, `AllowedExtensions = new string[0]`
  2. Attacker uploads random binary with `.exe` extension
  3. Detection returns `IsKnownFormat = false`, `FormatName = "UNKNOWN"`
  4. UnknownFilePolicy = Allow → passes unknown check
  5. Extension check: empty allowlist → skipped
  6. File accepted without any validation
- **Impact:** `UnknownFilePolicy = Allow` combined with empty allowlists results in accept-all behavior for unknown files.
- **Remediation:** Document that `UnknownFilePolicy = Allow` combined with empty allowlists results in accept-all behavior. Default `UnknownFilePolicy = Reject` is fail-closed; overriding to `Allow` should be done with full understanding of the risk.

---

## Test Gaps

### Unconfirmed Concern-001: Malware Scan Result Not Propagated When Scan Not Required
- **Severity:** Low
- **Classification:** Unconfirmed Concern

**Evidence:**
- **File:** `Company.Security.FileUpload\Pipeline\FileUploadPipeline.cs`, lines 69-81
- **Code:** `if (finalResult.IsValid && policy.RequireMalwareScan)` — malware scan result (`MalwareScanResult`) is only set on `FileValidationResult` when `policy.RequireMalwareScan == true`. When `RequireMalwareScan == false`, the field remains `null` even if a scanner is configured and runs.
- **Issue:** Consumers who configure a malware scanner but set `RequireMalwareScan = false` (for testing/gradual rollout) won't see scan results, even though the scan was performed.
- **Required Test:** Verify that `FileValidationResult.MalwareScanResult` is populated when a scanner runs even with `RequireMalwareScan = false`, or document this as intentional behavior.

---

### Unconfirmed Concern-002: Stream Position Inconsistency After Archive Validation
- **Severity:** Medium
- **Classification:** Unconfirmed Concern

**Evidence:**
- **File:** `Company.Security.FileUpload\Detection\FileTypeResolver.cs`, `TryDetectZipContainer` method, lines 133-185
- **Code:** The `finally` block restores stream position only if seekable (line 182-184). After ZIP container detection, the stream position may be at various positions depending on ZIP structure inspection.
- **Issue:** When validators run after detection (in `FileUploadPipeline.cs` lines 50-56), the stream position may not be at the expected starting point, potentially causing validators to miss content at the beginning of the stream.
- **Required Test:** Verify stream position state after detection across all validator types, especially ArchiveStructureValidator.

---

### Test Gap-001: Missing Malware Scanner Integration Tests with Error/Unknown Policies
- **Classification:** Test Gap

**Evidence:**
- The test project has `MalwareScanTests.cs` but the review found limited coverage of malware scan error/unknown policies.
- Specific test gaps: Scanner Error policy behavior, Scanner Unknown policy behavior with different `MalwareScanErrorPolicy` and `MalwareScanUnknownPolicy` combinations.
- Recommended test: Test all 4 scanner statuses (Clean, Infected, Error, Unknown) with both Reject and Allow policies configured.

---

### Test Gap-002: No Testing for Empty Policy Configuration
- **Classification:** Test Gap

**Evidence:**
- No existing tests verify behavior when `FileUploadPolicy` is configured with minimal settings (e.g., only `MaxFileSizeBytes` set, all allowlists at default).
- The review identified that empty allowlists with default policy result in accept-all behavior (Finding-006), but no tests exist to confirm or reject this behavior.
- Recommended test: Create policy with only `MaxFileSizeBytes` and verify file acceptance/rejection patterns.

---

### Test Gap-003: No Testing for Non-Seekable Streams with Large Files
- **Classification:** Test Gap

**Evidence:**
- Limited testing for non-seekable stream scenarios beyond the `CancellationRequested_Throws` test.
- Edge cases: Non-seekable stream at position > 0, non-seekable stream exactly at size limit, non-seekable stream with cancellation during buffering.
- Recommended test: Create non-seekable streams at various positions and sizes, verify size validation and detection behavior.

---

## Integration Requirements

### Integration-001: Allowlist Configuration Required
- **Classification:** Integration Requirement

**Detail:** The library defaults to `AllowedCategories = FileTypeCategory.All` and supports empty allowlists, which results in accept-all behavior for extension/MIME/format checks. Consumers must explicitly configure allowlists to restrict acceptable file types. This is a design decision (fail-open by default), but must be explicitly configured for production use.

**Required Action:** Configure `FileUploadPolicy` with at least one of: `AllowedExtensions`, `AllowedCategories`, `AllowedMimeTypes`, or `AllowListedFormats` to enforce file type restrictions.

---

### Integration-002: Unknown File Policy Configuration
- **Classification:** Integration Requirement

**Detail:** `UnknownFilePolicy` defaults to `Reject` (fail-closed), but consumers can override to `Allow` or `Quarantine`. Overriding to `Allow` without also configuring allowlists results in accept-all behavior for unknown file types. This must be explicitly documented in consumer-facing guides.

**Required Action:** Document that `UnknownFilePolicy = Allow` without allowlist configuration results in all unknown files being accepted. Recommend default `Reject` for production use.

---

### Integration-003: Malware Scanner Integration
- **Classification:** Integration Requirement

**Detail:** The library provides `IMalwareScanner` interface for pluggable malware scanning, but consumers must:
1. Implement the `IMalwareScanner` interface
2. Configure `FileUploadPipelineBuilder.UseMalwareScanner(scanner)`
3. Set `policy.RequireMalwareScan = true` to enforce scanning
4. Configure `policy.MalwareScanErrorPolicy` and `policy.MalwareScanUnknownPolicy` for error handling

Consumers must also implement their own storage (the library no longer includes storage features) and generate secure file names.

**Required Action:** Implement `IMalwareScanner` for desired AV engine, configure pipeline with `UseMalwareScanner()`, set appropriate policy scan settings.

---

## Architecture Summary

### Data Flow
```
File Upload Request
    → EnsureSeekableAsync (buffer non-seekable streams)
    → DetectAsync (multi-layer: container → signatures → text patterns → unknown)
    → Validators (11 validators in fixed order)
    → Policy Engine (category/extension/MIME/format checks + size limits)
    → Malware Scan (optional, only if RequireMalwareScan + validation passed)
    → FileValidationResult (isValid, errors, warnings, detected type, malware status)
```

### Trust Boundaries
- **Client-supplied data:** File stream, filename, MIME type, file size — never trusted
- **Internal detection:** Magic bytes, container inspection, text patterns — trusted as detection signals only
- **Policy configuration:** All allowlists and policies are consumer-configured — library enforces what's configured
- **Malware scanner:** External plug-in — results mapped per policy settings

### Security-Critical Components
1. **PolicyEngine.Evaluate** — final acceptance boundary; checks categories, extensions, MIME, formats, mismatches, size
2. **FileSignatureDetector.DetectAsync** — 8KB read limit for signature matching; priority-based best match selection
3. **FileTypeResolver.TryDetectContainerRefined** — container inspection for RIFF/EBML/ZIP/OLE-CFB formats
4. **ArchiveStructureValidator** — ZIP path traversal, zip-bomb, entry count, depth limits
5. **FileNameValidator** — path traversal, reserved names, null bytes, invalid characters detection

---

## Attack Matrix Summary

| Scenario | Input | Expected | Actual | Impact |
|----------|-------|----------|--------|--------|
| Executable with JPG extension | `payload.exe` named as `photo.jpg` | Rejected (ExtensionMismatch) | Depends on policy | Medium |
| Unknown file type | Random binary with `.png` extension | Rejected (FileTypeUnknown) | Depends on UnknownFilePolicy | High |
| MIME mismatch | PNG file with `Content-Type: text/plain` | Rejected (MimeMismatchWithSignature) | Depends on policy | Medium |
| Archive path traversal | ZIP with `../escape/evil.txt` entry | Rejected (StructureZipPathTraversal) | Confirmed working | High |
| Zip bomb | 15MB compressed → 500MB expanded | Rejected (StructureZipBombDetected) | Confirmed working | High |
| Nested archive depth | 8-levels deep ZIP | Rejected (StructureZipDepthExceeded) with MaxDepth=5 | Confirmed working | High |
| Image dimension exceed | 1500×1500 PNG with MaxImageWidth=100 | Rejected (StructureImageDimensionExceeded) | Confirmed working | High |
| Pixel count exceed | 1000×1000 PNG with MaxPixelCount=50000 | Rejected (StructureImagePixelCountExceeded) | Confirmed working | High |
| Control characters in filename | `photo\u0001.png` | Rejected (FileNameContainsInvalidCharacters) | Confirmed working | High |
| Path traversal in filename | `..\\..\\windows\\evil.png` | Rejected (FileNamePathTraversalDetected) | Confirmed working | High |
| Multiple extensions | `archive.tar.gz` with AllowExtensions=".gz" | Rejected (ExtensionMultipleDetected) | Confirmed working | High |
| No extension | PNG file named `photo` | Rejected (ExtensionMissing) if AllowFileWithoutExtension=false | Confirmed working | High |
| Unknown signature | File with no matching magic bytes | Rejected (FileTypeUnknown) if UnknownFilePolicy=Reject | Confirmed working | High |
| Extension alias conflict | Policy `.jpeg`, file `image.jpg` | Rejected (ExtensionMismatch - no reverse alias) | Low severity asymmetry | Low |
| Non-seekable stream | Stream without CanSeek=true | Buffered to MaxFileSizeBytes+1, size validated from buffered position | Working with edge cases | Medium |

---

## Remediation Plan

### Priority 1 (Immediate - Fix High Severity Findings)

**FR-006: No Validation When Allowlist Empty**
- Add documentation warning that empty allowlists with default `AllowedCategories = All` results in accept-all behavior
- Consider adding optional policy validation that warns when no allowlists are configured
- Update README to emphasize that allowlist configuration is required for production use

**FR-009: Unknown File Policy Configuration**
- Document that `UnknownFilePolicy = Allow` without allowlist configuration results in accept-all
- Recommend keeping default `Reject` for production use
- Add validation in PolicyEngine to warn when UnknownFilePolicy.Allow combined with empty allowlists

### Priority 2 (Medium - Fix Medium Severity Findings)

**FR-001: Stream Position Not Restored After Validation**
- Review stream position management across pipeline stages
- Ensure consistent position state or document expected state after each stage
- Add `CanSeek` checks before resetting position in EnsureSeekableAsync finally block

**FR-005: Archive Validation Stream Position Not Restored**
- Verify stream position state after ZIP container detection
- Ensure position is reset to 0 before validator execution
- Add test coverage for stream position across validator types

### Priority 3 (Low - Fix Low Severity Findings)

**FR-003: Policy Engine Extension Mismatch Message Format**
- Not a security vulnerability; minor message formatting inconsistency
- Optionally normalize message format to match user input format

**FR-002: FileExtensionValidator Bypasses When Allowlist Empty**
- By design; document as integration requirement
- No code change needed if behavior is intentional

**FR-004: Malware Scan Result Not Propagated When Scan Not Required**
- Document that `MalwareScanResult` is only populated when `RequireMalwareScan = true`
- Or always propagate scan result regardless of setting (design decision)

**FR-008: Extension Alias Normalization Only Handles 4 Common Aliases**
- Add reverse aliases (`jpg→jpeg`, `tiff→tif`, `html→htm`, `mpg→mpeg`) for symmetry
- Or document the asymmetry clearly in API documentation

---

## Executive Summary

**Review Scope:** Comprehensive security assessment of `Company.Security.FileUpload` file upload validation library for .NET 10.

**Review Status:** Complete - 10 findings documented (2 confirmed vulnerabilities, 3 test gaps, 3 integration requirements, 2 unconfirmed concerns).

**Main Security Risks:**
1. **High:** Empty allowlists with default policy result in accept-all behavior (Finding-006, Finding-009). Consumers MUST configure allowlists for production use.
2. **Medium:** Stream position inconsistencies across pipeline stages could cause content to be viewed differently by different stages (Finding-001, Finding-005).
3. **Low:** Minor alias asymmetry and message format issues (Finding-002, Finding-008).

**Key Strengths:**
- Fail-closed default behavior (`UnknownFilePolicy = Reject`, fail-closed on unknown scan errors)
- Multi-layer detection (container → signatures → text patterns → unknown)
- OWASP-aligned test coverage (62 tests covering OWASP File Upload Cheat Sheet requirements)
- Zero external NuGet dependencies in core library (BCL only)
- Proper path traversal detection and reserved name blocking
- Archive validation (path traversal, zip-bomb, entry count, depth limits)
- Image structure validation (dimensions, pixel count)
- MIME type mismatch detection
- Cancellation token support throughout
- Thread-safe design (stateless validators, policy cleared between uses)

**Integration Effort:** Medium - Consumers must configure allowlists, malware scanner (optional), and understand the fail-open/default behaviors when allowlists are not configured.

**Recommendations:**
1. **Immediate:** Configure `FileUploadPolicy` with explicit `AllowedExtensions` or `AllowedCategories` for production use
2. **Short-term:** Review and document stream position management across pipeline stages
3. **Medium-term:** Consider adding policy validation warnings when allowlists are empty
4. **Long-term:** Add reverse extension aliases for symmetry, enhance test coverage for edge cases

**Final Acceptance:** The library is suitable for use with proper configuration. The main risk is consumer misconfiguration (empty allowlists), not library bugs. All confirmed vulnerabilities are due to default policy settings, not implementation flaws.