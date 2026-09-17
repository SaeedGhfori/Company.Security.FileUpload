# Remediation Plan - Company.Security.FileUpload Security Review

## Introduction
This document outlines remediation actions for all confirmed findings and recommended improvements from the security review. Each action includes priority, effort estimate, and verification method.

## Priority 1: High Severity Findings (Immediate Action Required)

### FR-006: No Validation When Allowlist Empty — Documentation and Policy Validation

**Finding:** Empty allowlists with default `AllowedCategories = All` result in accept-all behavior for extension/MIME/format checks.

**Remediation:**
1. **Add XML comment documentation** to `FileUploadPolicy.cs` warning that empty allowlists result in accept-all behavior
2. **Add optional policy validation** in `PolicyEngine.With()` that emits a warning when `AllowedExtensions.Count == 0 && AllowedMimeTypes.Count == 0 && AllowListedFormats.Count == 0 && AllowedCategories == FileTypeCategory.All`
3. **Update README** with bold warning: "For production use, configure at least one of: AllowedExtensions, AllowedCategories, AllowedMimeTypes, or AllowListedFormats"
4. **Consider adding `RequireExtensionPolicyConfigured`** property (optional) that throws at runtime if no allowlists configured — but this would be a breaking change

**Effort:** Low (1-2 hours)  
**Risk:** Low — additive changes only, no existing behavior modified  
**Verification:** 
- Build succeeds with no warnings
- XML comments render in IntelliSense
- README updated with warning banner
- Existing 62 tests still pass

---

### FR-009: Unknown File Policy Configuration Documentation

**Finding:** `UnknownFilePolicy = Allow` without allowlist configuration results in accept-all for unknown files.

**Remediation:**
1. **Add XML comment** to `UnknownFilePolicy` enum: `/// <summary>/// Default is Reject (fail-closed). Setting to Allow without configuring AllowedExtensions/AllowedCategories /// results in accept-all for unknown file types. Use with caution in production. /// </summary>`
2. **Update README** "Unknown File Policy" section to emphasize default Reject and risks of Allow
3. **Consider adding runtime check** in `PolicyEngine.Evaluate()` that warns when `UnknownFilePolicy == Allow && AllowedExtensions.Count == 0 && AllowedCategories == FileTypeCategory.All`

**Effort:** Low (30-45 minutes)  
**Risk:** Low — documentation only, no behavior change  
**Verification:** 
- XML comments compile
- README updated and renders correctly
- Existing tests pass

---

### FR-001: Stream Position Not Restored After Validation

**Finding:** Inconsistent stream position state across pipeline stages could cause content to be viewed differently.

**Remediation:**
1. **Review and document** the expected stream position state after each pipeline stage:
   - After `EnsureSeekableAsync`: position 0 (if seekable) or at end of buffered data (if non-seekable)
   - After `DetectAsync`: position 0 (reset at line 40 of `FileUploadPipeline.cs`)
   - After each validator: position 0 (each validator independently resets)
   - After malware scan: position 0 (reset at line 107)
2. **Add `CanSeek` check** in `EnsureSeekableAsync` `finally` block (already exists at line 178, but verify logic)
3. **Consider centralizing** position management — either don't reset between stages, or document explicitly that each stage starts at position 0
4. **Add test** verifying stream position after each pipeline stage

**Effort:** Medium (2-3 hours)  
**Risk:** Low — documentation and test additions; no breaking changes  
**Verification:** 
- New tests pass (stream position verification)
- All 62 existing tests still pass
- Code review confirms position logic is correct

---

### FR-005: Archive Validation Stream Position Not Restored

**Finding:** Stream position after ZIP container detection may not be at expected starting point for validators.

**Remediation:**
1. **In `FileTypeResolver.TryDetectZipContainer`**, ensure stream position is reset to 0 in the `finally` block (already exists at lines 182-184, but verify it covers all exit paths)
2. **In `FileUploadPipeline.cs`**, add explicit `stream.Position = 0;` before validator execution (after detection, before the `foreach` loop at line 50)
3. **Add test** verifying stream position = 0 after detection and before validator execution

**Effort:** Medium (2-3 hours)  
**Risk:** Low — position reset is safe; existing behavior may improve  
**Verification:** 
- New test: `stream.Position == 0` after detection and before validators
- All 62 existing tests still pass
- Archive-related tests (Zip*, NestedZip*) pass

---

## Priority 2: Medium Severity Findings (Sprint Backlog)

### FR-002: FileExtensionValidator Bypasses When Allowlist Empty

**Finding:** When `AllowedExtensions` is empty, extension validator returns success without checking extension.

**Remediation:**
1. **Document as integration requirement** (already done in Findings.md and Architecture.md) — no code change needed if behavior is intentional
2. **Optional:** Add XML comment to `FileExtensionValidator.cs` line 20-23: `/// <summary>/// When AllowedExtensions is empty, no extension filtering is applied. /// Configure at least one extension in policy for production use. /// </summary>`
3. **Optional:** Add warning in `PolicyEngine.With()` when `AllowedExtensions.Count == 0` — not a security issue, but good for developer experience

**Effort:** Low (30 minutes)  
**Risk:** Low — documentation only  
**Verification:** 
- XML comment compiles
- Existing tests pass

---

### FR-003: Policy Engine Extension Mismatch Message Format

**Finding:** Minor message format inconsistency (dotted extension vs user input format).

**Remediation:**
1. **Not a security vulnerability** — no code change required
2. **Optional:** Normalize message format to match `ExtensionResolver.Normalize()` output (no leading dot) for consistency
   - Change `dotted()` helper to NOT add dot: `return extension;` 
   - Or change message to use user's original format
   - **Decision:** Leave as-is; minor formatting, not security-impactful

**Effort:** Very Low (10 minutes) — optional cleanup only  
**Risk:** None  
**Verification:** None required (informational only)

---

### FR-004: Malware Scan Result Not Propagated When Scan Not Required

**Finding:** `FileValidationResult.MalwareScanResult` only populated when `RequireMalwareScan == true`.

**Remediation:**
1. **Add XML comment** to `ProcessAsync` method documenting when `MalwareScanResult` is populated
2. **Optional:** Always propagate scan result regardless of `RequireMalwareScan` setting — but this changes behavior and may impact performance consumers who don't need scanning
3. **Recommendation:** Document the current behavior; consumers who need scan results regardless should set `RequireMalwareScan = true`

**Effort:** Low (30 minutes)  
**Risk:** Low — documentation only  
**Verification:** 
- XML comment added to `ProcessAsync` signature
- Existing 62 tests pass
- Manual verification: run with `RequireMalwareScan = false`; `MalwareScanResult` is null

---

### FR-008: Extension Alias Normalization Only Handles 4 Common Aliases

**Finding:** Only 4 forward aliases defined (jpeg→jpg, tif→tiff, htm→html, mpeg→mpg); no reverse aliases.

**Remediation:**
1. **Add reverse aliases** for symmetry:
   - Add to `NormalizeAlias`: `"jpg" => "jpeg"`, `"tiff" => "tif"`, `"html" => "htm"`, `"mpg" => "mpeg"`
   - This makes alias resolution symmetric: `IsEquivalentExtension(".jpeg", "jpg")` and `IsEquivalentExtension(".jpg", ".jpeg")` both return true
2. **Update test** `ExtensionResolver_Normalize_ReturnsLastExtension` if needed
3. **Update documentation** if API changes

**Effort:** Low (30-45 minutes)  
**Risk:** Low — adding aliases is additive; existing behavior (forward only) still works  
**Verification:** 
- All existing tests pass
- New alias behavior verified: `IsEquivalentExtension(".jpg", ".jpeg")` returns true (both directions)
- No regressions

---

## Priority 3: Low Severity Findings (Cleanup/Documentation)

### FR-007: FileSize Not Validated for Non-Seekable Streams Correctly

**Finding:** Edge cases in non-seekable stream size estimation.

**Remediation:**
1. **Document the behavior** in README under "Non-seekable Streams" section
2. **Add test** for boundary condition: buffered position exactly equals `MaxFileSizeBytes`
3. **No code change** required — behavior is reasonable given constraints (buffer to MaxFileSizeBytes + 1, compare > MaxFileSizeBytes)

**Effort:** Low (30-45 minutes)  
**Risk:** None  
**Verification:** 
- New test passes
- Existing tests pass

---

### FR-005: Extension Alias Reverse Direction — Already Covered by FR-008

**See FR-008 above — remediation plan includes adding reverse aliases.**

---

### FR-010: Additional Documentation Items

**Finding:** Several minor documentation gaps identified.

**Remediation:**
1. **Add "Stream Position" section** to README explaining position management across pipeline stages
2. **Add "Policy Defaults" section** summarizing all default values
3. **Add "Integration Requirements" section** summarizing what consumers must configure
4. **Fix any broken links** in README (if any)

**Effort:** Low (30-45 minutes)  
**Risk:** None  
**Verification:** 
- README builds/renderes correctly
- No syntax errors in markdown

---

## Verification Suite

### Pre-Deployment Checklist

- [ ] Build: `dotnet build "Company.Security.FileUpload.slnx" -c Release` — 0 warnings, 0 errors
- [ ] Tests: `dotnet test "Company.Security.FileUpload.Tests" -c Debug` — 62/62 passed
- [ ] New tests added for all high-priority test gaps (Test-Gaps.md)
- [ ] XML comments added for all public APIs affected by remediations
- [ ] README updated with security warnings and defaults
- [ ] No stale code or commented-out sections
- [ ] All `FileUploadPolicy` properties have XML comments
- [ ] `WithDefaultValidators()` creates fresh validator instances (verified by code review)
- [ ] Pipeline is immutable after `Build()` (verified by code review)

### Post-Deployment Verification

- [ ] Consumer configures `AllowedExtensions` or `AllowedCategories` — verified in integration test
- [ ] `UnknownFilePolicy` defaults to `Reject` — verified
- [ ] `RequireMalwareScanUnavailable = true` — verified (fail-closed)
- [ ] Archive path traversal detected — verified via `ZipWithMaliciousEntryPath_Rejected` test
- [ ] ZIP bomb detected — verified via `ZipBomb_Rejected` test
- [ ] Image dimension/pixel limits verified — verified via `ImageTooLargeDimensions_Rejected` and `ImagePixelCountExceeded_Rejected` tests

### Rollback Plan

If remediation introduces unexpected issues:
1. Revert `FileUploadPolicy.cs` XML comment changes
2. Revert `ExtensionResolver.NormalizeAlias` additions
3. Revert `FileUploadPipeline.cs` position management changes
4. Run `dotnet test` to confirm 62/62 tests pass
5) Re-deploy previous version

**Rollback estimated time:** 15 minutes

---

## Summary of Changes by File

| File | Change Type | Priority |
|------|-------------|----------|
| `Company.Security.FileUpload\Core\Policies\FileUploadPolicy.cs` | XML comments, possible warning | P1 |
| `Company.Security.FileUpload\Core\Policies\PolicyEngine.cs` | Possible warning on empty allowlists | P1 |
| `Company.Security.FileUpload\Core\Detection\ExtensionResolver.cs` | Add reverse aliases | P3 |
| `Company.Security.FileUpload\Pipeline\FileUploadPipeline.cs` | Position management docs/tests | P1 |
| `Company.Security.FileUpload\Core\Constants\FileSignatures.cs` | None (no changes needed) | — |
| `Company.Security.FileUpload\Detection\FileSignatureDetector.cs` | None (no changes needed) | — |
| `Company.Security.FileUpload\Detection\FileTypeResolver.cs` | Possible position reset | P1 |
| `Company.Security.FileUpload\Validation\FileExtensionValidator.cs` | XML comment | P2 |
| `README.md` | Security warnings, defaults, integration requirements | P1 |
| `SecurityReview/Findings.md` | Documentation of findings | — |
| `SecurityReview/Architecture.md` | Architecture analysis | — |
| `SecurityReview/Attack-Matrix.md` | Attack scenario catalog | — |
| `SecurityReview/Test-Gaps.md` | Test gap documentation | — |
| `SecurityReview/Remediation-Plan.md` | This document | — |

**Total Estimated Effort:** 8-12 hours across all priorities  
**Breaking Changes:** None planned — all changes are additive or documentation-only  
**Test Impact:** All 62 existing tests must continue to pass