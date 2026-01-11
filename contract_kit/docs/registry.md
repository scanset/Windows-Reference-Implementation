# CTN Type Reference: `registry`

## Overview

Validates Windows Registry keys and values.

**OVAL Equivalent:** `registry_test`, `registry_object`, `registry_state`

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `hive` | string | Yes | Registry hive | `HKEY_LOCAL_MACHINE`, `HKLM` |
| `key` | string | Yes | Registry key path (without hive) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| `name` | string | Yes | Value name | `CurrentBuildNumber` |

### Behaviors

| Behavior | Values | Default | Description |
|----------|--------|---------|-------------|
| `executor` | `reg`, `powershell` | `reg` | Collection method |

---

## Collected Data Fields (Output)

| Field | Type | Executor | Description |
|-------|------|----------|-------------|
| `exists` | boolean | Both | Whether the key/value exists |
| `type` | string | `reg` only | Registry type: `reg_sz`, `reg_dword`, `reg_qword`, `reg_binary`, `reg_expand_sz`, `reg_multi_sz` |
| `value` | string | Both | Raw string value (normalized to decimal for DWORD/QWORD) |

**Notes:**
- `powershell` executor does not return `type` field
- `value` is always returned as string, even for `REG_DWORD`
- DWORD/QWORD hex values (e.g., `0x1`) are automatically converted to decimal (e.g., `1`)

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `exists` | boolean | `=`, `!=` | `exists` | Key/value existence |
| `type` | string | `=`, `!=`, `ieq` | `type` | Registry value type |
| `value` | string | `=`, `!=`, `contains`, `starts`, `ends`, `pattern_match`, `ieq` | `value` | String comparison |
| `value_int` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | `value` (parsed) | Integer comparison (for DWORD/QWORD) |
| `value_version` | version | `=`, `!=`, `>`, `<`, `>=`, `<=` | `value` (parsed) | Version comparison |

### Existence Short-Circuit Behavior

When `exists` is specified in a STATE, the executor uses short-circuit evaluation:

| Scenario | `exists` in STATE | Key Status | Behavior |
|----------|-------------------|------------|----------|
| **1** | `exists boolean = true` | Key missing | **FAIL immediately**, skip type/value checks |
| **2** | `exists boolean = true` | Key exists | Continue to type/value checks |
| **3** | `exists boolean = false` | Key missing | **PASS immediately**, skip other checks |
| **4** | `exists boolean = false` | Key exists | **FAIL** (key should not exist) |
| **5** | Not specified | Key missing | Check type/value (will fail with verbose errors) |

**Recommendation:** Always include `exists boolean = true` when validating keys that must exist. This provides:
- Clean, single-line failure messages
- Better performance (no unnecessary field checks)
- Clear intent in policy definition

---

## Command Execution

### `reg` executor (default)

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
```

**Output:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    CurrentBuildNumber    REG_SZ    26100
```

### `powershell` executor

```powershell
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber
```

**Output:**
```
26100
```

---

## ESP Examples

### Basic registry check (with existence)

```esp
OBJECT build_number
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
    name `CurrentBuildNumber`
OBJECT_END

STATE minimum_build
    exists boolean = true
    type string = `reg_sz`
    value_version version >= `19045`
STATE_END

CTN registry
    TEST at_least_one all
    STATE_REF minimum_build
    OBJECT_REF build_number
CTN_END
```

### DWORD integer comparison

```esp
OBJECT telemetry_setting
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Policies\Microsoft\Windows\DataCollection`
    name `AllowTelemetry`
OBJECT_END

STATE telemetry_disabled
    exists boolean = true
    type string = `reg_dword`
    value_int int <= `1`
STATE_END

CTN registry
    TEST at_least_one all
    STATE_REF telemetry_disabled
    OBJECT_REF telemetry_setting
CTN_END
```

### Check that a key does NOT exist

```esp
OBJECT dangerous_setting
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Policies\Dangerous`
    name `EnableBadThing`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN registry
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF dangerous_setting
CTN_END
```

### With PowerShell executor

```esp
OBJECT edition_id
    hive `HKLM`
    key `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
    name `EditionId`
    behavior executor powershell
OBJECT_END

STATE is_enterprise
    exists boolean = true
    value string = `EnterpriseS`
STATE_END

CTN registry
    TEST at_least_one all
    STATE_REF is_enterprise
    OBJECT_REF edition_id
CTN_END
```

---

## Finding Output Examples

### Key does not exist (with `exists boolean = true`)

```json
{
  "finding_id": "finding-188847d6e3287d6c",
  "severity": "high",
  "title": "registry validation failed",
  "description": "Registry validation failed:\n  - Registry 'bitlocker_minimum_pin': Registry key/value does not exist",
  "expected": { "exists": "Boolean(true)" },
  "actual": { "exists": "Boolean(false)" },
  "field_path": "CTN_registry"
}
```

### Key exists with wrong value

```json
{
  "finding_id": "finding-188847d6e628148c",
  "severity": "high",
  "title": "registry validation failed",
  "description": "Registry validation failed:\n  - Registry 'telemetry_setting': value_int check failed: got 3, expected <= 1",
  "expected": { "exists": "Boolean(true)", "type": "String(\"reg_dword\")", "value_int": "String(\"1\")" },
  "actual": { "exists": "Boolean(true)", "type": "String(\"reg_dword\")", "value_int": "String(\"3\")" },
  "field_path": "CTN_registry"
}
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Key does not exist | `ObjectNotFound` | `exists` = false, counted as missing for existence check |
| Value does not exist in key | `ObjectNotFound` | `exists` = false, counted as missing for existence check |
| Access denied | `AccessDenied` | Error state, object exists but inaccessible |
| Invalid hive name | `InvalidConfiguration` | Configuration error |
| Command timeout | `CollectionFailed` | Error state |

---

## OVAL to ESP Mapping

| OVAL Element | ESP Equivalent |
|--------------|----------------|
| `registry_object/hive` | `OBJECT.hive` |
| `registry_object/key` | `OBJECT.key` |
| `registry_object/name` | `OBJECT.name` |
| `registry_state/type` | `STATE.type` |
| `registry_state/value` (int) | `STATE.value_int` |
| `registry_state/value` (string) | `STATE.value` |
| `check_existence="all_exist"` | `TEST all all` + `exists boolean = true` |
| `check_existence="at_least_one_exists"` | `TEST at_least_one all` |
| `check_existence="none_exist"` | `exists boolean = false` |
| `operation="equals"` | `=` |
| `operation="greater than or equal"` | `>=` |
| `operation="pattern match"` | `pattern_match` |