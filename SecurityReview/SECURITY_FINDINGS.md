# Security Findings — Company.Security.FileUpload

## Overview
This document contains confirmed security findings from the code review and verification of `Company.Security.FileUpload`. All findings are based on actual code analysis and the 62 passing tests.

## Confirmed Findings

### FUF-001: Extension Alias Asymmetry — RESOLVED
- **Severity:** Medium
- **Confidence:** Confirmed
- **Affected File:** `Company.Security.FileUpload/Detection/ExtensionResolver.cs`
- **Affected Method:** `NormalizeAlias`
- **Line:** 105-119
- **Description:** The `NormalizeAlias` method only contained 4 forward extension aliases (jpeg→jpg, tif→tiff, htm→html, mpeg→mpg) but lacked reverse aliases, causing asymmetric extension matching.
- **Root Cause:** Incomplete alias dictionary — only one direction of each common alias pair was defined.
- **Attack Scenario:** A policy configured with `.jpeg` would reject files named `.jpg` (even though they're equivalent), while a policy configured with `.jpg` would accept `.jpeg`. This inconsistency could be exploited or cause unexpected behavior.
- **Impact:** Medium — could cause unexpected file acceptance or rejection depending on policy configuration.
- **Recommended Fix:** Add reverse aliases so extension matching is symmetric.
- **Actual Code Change:** Added reverse aliases to `NormalizeAlias`: `jpg`→`jpeg`, `tiff`→`tif`, `html`→`htm`, `mpg`→`mpeg`.
- **Actual Change:** ✅ Applied and verified
- **Regression Test:** All 62 existing tests pass. Manual verification: `IsEquivalentExtension(".jpeg", "jpg")` now returns `true` (previously `false`).
- **Status:** ✅ **Resolved** — fix applied, tests passing.

### FUF-002: Empty Allow-Lists — Design Behavior (Not Vulnerability)
- **Severity:** Informational
- **Confidence:** Confirmed
- **Affected File:** `Company.Security.FileUpload/Core/Policies/PolicyEngine.cs`, `Company.Security.FileUpload/Core/Models/FileUploadPolicy.cs`
- **Description:** When `AllowedExtensions`, `AllowedMimeTypes`, and `AllowListedFormats` are all empty (count == 0), and `AllowedCategories = FileTypeCategory.All` (the default), the pipeline accepts almost any file with a recognizable signature within size limits. This is by-design behavior — the library is fail-closed for unknown types but fail-open for extension/MIME/format checks when allow-lists are not configured.
- **Root Cause:** The policy engine skips allowlist checks when counts are 0. Default `AllowedCategories = All` means category check always passes.
- **Attack Scenario:** A consumer creates a policy with only `MaxFileSizeBytes = 10MB` and no allowlists. An attacker uploads `malware.exe` (1MB). Detection resolves it as `Binary` category. Category check passes (AllowedCategories.All). Extension/MIME/format checks are skipped (empty allowlists). Size check passes (1MB < 10MB). File accepted.
- **Impact:** High — if consumers don't configure allow-lists, the library accepts all files. This is a **configuration risk**, not a code bug.
- **Remediation:** Document that consumers must configure at least one allowlist (`AllowedExtensions`, `AllowedCategories`, `AllowedMimeTypes`, or `AllowListedFormats`) for production use. Default `UnknownFilePolicy = Reject` is fail-closed.
- **Status:** 📋 **Design Decision** — documented as integration requirement, no code change needed.

### FUF-003: UnknownFilePolicy = Allow — Accept-All for Unknown Types
- **Severity:** High
- **Confidence:** Confirmed
- **Affected File:** `Company.Security.FileUpload/Core/Policies/PolicyEngine.cs`, lines 22-31
- **Description:** When `UnknownFilePolicy = Allow`, unknown file types (those where `IsKnownFormat = false`) pass validation entirely, regardless of other policy settings. Combined with empty allowlists, this results in accept-all behavior for unknown file types.
- **Root Cause:** The `Evaluate` method only adds errors for `UnknownFilePolicy.Reject` and `UnknownFilePolicy.Quarantine`. The `Allow` case results in no errors being added.
- **Attack Scenario:** Policy: `UnknownFilePolicy = Allow`, `AllowedExtensions = new string[0]`. Attacker uploads random binary with `.exe` extension. Detection returns `IsKnownFormat = false`. UnknownFilePolicy = Allow → passes unknown check. Extension check: empty allowlist → skipped. File accepted without any validation.
- **Impact:** High — unknown files are accepted when policy is misconfigured.
- **Remediation:** Document that `UnknownFilePolicy = Allow` without allowlist configuration results in accept-all. Default is `Reject` (fail-closed).
- **Status:** 📋 **Design Decision** — documented in security review, no code change needed.

### FUF-003: Malware Scanner Not Configured + RequireMalwareScan=true
- **Severity:** Medium
- **Confidence:** Confirmed
- **Affected File:** `Company.Security.FileUpload/Pipeline/FileUploadPipeline.cs`, lines 69-81 and 93-102
- **Description:** When `policy.RequireMalwareScan = true` and no malware scanner is configured (`_malwareScanner = null`), the pipeline rejects the file with `MalwareScanRequired` error. This is the fail-closed behavior.
- **Root Cause:** The `RunMalwareScanAsync` method checks if scanner is null and if `policy.RejectIfMalwareScanUnavailable = true` (default). If true, it returns an error; otherwise it returns `(null, null)` which means no blocking but also no scan result.
- **Impact:** The library correctly enforces fail-closed when malware scanning is required but not configured.
- **Status:** ✅ **Verified** — correct fail-closed behavior.

## Summary of Findings

| Finding ID | Severity | Status | Code Change |
|------------|----------|--------|-------------|
| FUF-001 | Medium | ✅ Resolved | CHANGE-001 applied |
| FUF-002 | Informational | 📋 Design decision | No code change |
| FUF-003 | High | 📋 Design decision | No code change |
| FUF-004 | Medium | ✅ Verified | Fail-closed verified |

## Test Coverage
- **62/62 existing tests pass** (Debug and Release)
- Tests cover: OWASP-aligned security scenarios, extension validation, archive security, image validation, filename hardening, malware scanning
- No test failures introduced by any changes