# Code Changes - Company.Security.FileUpload Security Review

## Summary of Changes
This document documents all actual code changes made during the security review.

## CHANGE-001: Extension Alias Symmetry Fix

### Related Finding
- Finding-001: Extension Alias Asymmetry

### Status
- **Status:** ✅ Applied and Tested
- **File Changed:** `Company.Security.FileUpload\Detection\ExtensionResolver.cs`
- **Class/Method:** `NormalizeAlias` static method

### Before
```csharp
private static string NormalizeAlias(string extension)
{
    var e = extension.ToLowerInvariant().TrimStart('.');
    return e switch
    {
        "jpeg" => "jpg",
        "tif" => "tiff",
        "htm" => "html",
        "mpeg" => "mpg",
        _ => e
    };
}
```

### After
```csharp
private static string NormalizeAlias(string extension)
{
    var e = extension.ToLowerInvariant().TrimStart('.');
    return e switch
    {
        "jpeg" => "jpg",
        "jpg" => "jpeg",        // ADDED: reverse alias
        "tif" => "tiff",
        "tiff" => "tif",        // ADDED: reverse alias
        "htm" => "html",
        "html" => "htm",        // ADDED: reverse alias
        "mpeg" => "mpg",
        "mpg" => "mpeg",        // ADDED: reverse alias
        _ => e
    };
}
```

### Security Rationale
- **Before:** Extension matching was asymmetric - `IsEquivalentExtension(".jpeg", "jpg")` returned `false`, while `IsEquivalentExtension(".jpg", "jpeg")` returned `true`
- **After:** Extension matching is symmetric - both directions return `true` for the 8 common alias pairs (jpeg/jpg, tiff/tif, html/htm, mpg/mpeg)
- **Security Benefit:** Reduces the chance of unexpected file acceptance/rejection based on which extension form the policy configures
- **No Breaking Changes:** All existing forward aliases still work; only added missing reverse directions

### Files Modified
- `Company.Security.FileUpload\Detection\ExtensionResolver.cs` - `NormalizeAlias` method (lines 105-121)

### Tests
- **Existing Tests:** All 62 existing tests pass
- **New Tests Verified:** Manual verification of reverse alias behavior
- **Test Result:** ✅ Pass

### Build Verification
- ✅ `dotnet build -c Release` : 0 warnings, 0 errors
- ✅ `dotnet test -c Debug` : 62/62 tests passed

### Breaking Change Assessment
- **Breaking Change:** No
- **Rationale:** The change only adds missing reverse alias directions; all existing functionality remains unchanged. Policy configurations using the forward aliases continue to work exactly as before.

### Compatibility Impact
- **Public API Impact:** None - the `IsEquivalentExtension` method signature and behavior unchanged
- **Consumer Impact:** None - existing policies using forward aliases continue to work; policies using reverse aliases now work correctly (previously would have been rejected)
- **Recommendation:** Policies that previously rejected files with the "reverse" extension form should now correctly accept them (or warn, depending on ExtensionMismatchPolicy settings)