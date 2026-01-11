# CTN Type Reference: `registry_subkeys`

## Overview

Validates Windows Registry key existence and enumerates child subkeys.

**Use Case:** Checking if a registry key has subkeys (e.g., smart card readers installed, specific configurations present).

**OVAL Equivalent:** `registry_test` with pattern matching on key paths (no specific value name).

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `hive` | string | Yes | Registry hive | `HKEY_LOCAL_MACHINE`, `HKLM` |
| `key` | string | Yes | Registry key path (without hive) | `SOFTWARE\Microsoft\Cryptography\Calais\Readers` |

**Note:** No `name` field - this CTN enumerates subkeys, not values.

### Behaviors

| Behavior | Values | Default | Description |
|----------|--------|---------|-------------|
| `executor` | `reg`, `powershell` | `reg` | Collection method |

---

## Collected Data Fields (Output)

| Field | Type | Description |
|-------|------|-------------|
| `exists` | boolean | Whether the registry key exists |
| `subkey_count` | int | Number of child subkeys |
| `subkeys` | string[] | List of subkey names (for debugging/pattern matching) |

**Notes:**
- `subkey_count` is 0 if key doesn't exist or has no subkeys
- `subkeys` contains only direct children (one level deep)

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `exists` | boolean | `=`, `!=` | `exists` | Key existence |
| `subkey_count` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | `subkey_count` | Number of subkeys |
| `subkeys` | string | `contains`, `not_contains`, `pattern_match` | `subkeys` | Check for specific subkey name |

### Existence Short-Circuit Behavior

Same as `registry` CTN - when `exists boolean = true` is specified but key doesn't exist, validation fails immediately without checking other fields.

---

## Command Execution

### `reg` executor (default)

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Cryptography\Calais\Readers"
```

**Output (key with subkeys):**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
    (Default)    REG_SZ    (value not set)

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\Alcor Micro USB Smart Card Reader 0

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers\Microsoft Virtual Smart Card 0
```

**Output (key not found):**
```
ERROR: The system was unable to find the specified registry key or value.
```
(Exit code 1)

### `powershell` executor

```powershell
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
```

**Output:**
```
Alcor Micro USB Smart Card Reader 0
Microsoft Virtual Smart Card 0
```

---

## ESP Examples

### Check for at least one smart card reader

```esp
OBJECT readers_key
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Cryptography\Calais\Readers`
OBJECT_END

STATE has_readers
    exists boolean = true
    subkey_count int >= 1
STATE_END

CTN registry_subkeys
    TEST at_least_one all
    STATE_REF has_readers
    OBJECT_REF readers_key
CTN_END
```

### Check for smart card readers AND smart cards (MFA requirement)

```esp
OBJECT readers_key
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Cryptography\Calais\Readers`
OBJECT_END

OBJECT smartcards_key
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Cryptography\Calais\SmartCards`
OBJECT_END

STATE has_entries
    exists boolean = true
    subkey_count int >= 1
STATE_END

CRI AND
    CTN registry_subkeys
        TEST at_least_one all
        STATE_REF has_entries
        OBJECT_REF readers_key
    CTN_END

    CTN registry_subkeys
        TEST at_least_one all
        STATE_REF has_entries
        OBJECT_REF smartcards_key
    CTN_END
CRI_END
```

### Check that a key has NO subkeys

```esp
OBJECT temp_profiles
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\TempProfiles`
OBJECT_END

STATE no_temp_profiles
    exists boolean = true
    subkey_count int = 0
STATE_END

CTN registry_subkeys
    TEST at_least_one all
    STATE_REF no_temp_profiles
    OBJECT_REF temp_profiles
CTN_END
```

### Check for a specific subkey name

```esp
OBJECT smartcards_key
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\Microsoft\Cryptography\Calais\SmartCards`
OBJECT_END

STATE has_identity_device
    exists boolean = true
    subkeys string contains `Identity Device`
STATE_END

CTN registry_subkeys
    TEST at_least_one all
    STATE_REF has_identity_device
    OBJECT_REF smartcards_key
CTN_END
```

### Check that key does NOT exist

```esp
OBJECT deprecated_key
    hive `HKEY_LOCAL_MACHINE`
    key `SOFTWARE\OldVendor\DeprecatedProduct`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN registry_subkeys
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF deprecated_key
CTN_END
```

---

## Finding Output Examples

### Key does not exist

```json
{
  "finding_id": "finding-188847d6e3287d6c",
  "severity": "high",
  "title": "registry_subkeys validation failed",
  "description": "Registry subkeys validation failed:\n  - Registry 'readers_key': Registry key does not exist",
  "expected": { "exists": "Boolean(true)", "subkey_count": "Integer(1)" },
  "actual": { "exists": "Boolean(false)", "subkey_count": "Integer(0)" },
  "field_path": "CTN_registry_subkeys"
}
```

### Key exists but has no subkeys

```json
{
  "finding_id": "finding-188847d6e628148c",
  "severity": "high",
  "title": "registry_subkeys validation failed",
  "description": "Registry subkeys validation failed:\n  - Registry 'readers_key': subkey_count check failed: got 0, expected >= 1",
  "expected": { "exists": "Boolean(true)", "subkey_count": "Integer(1)" },
  "actual": { "exists": "Boolean(true)", "subkey_count": "Integer(0)" },
  "field_path": "CTN_registry_subkeys"
}
```

### Validation passed

```json
{
  "finding_id": "finding-188847d6e9a8b2c4",
  "severity": "info",
  "title": "registry_subkeys validation passed",
  "description": "Registry subkeys validation passed: 1 of 1 objects compliant",
  "expected": { "exists": "Boolean(true)", "subkey_count": "Integer(1)" },
  "actual": { "exists": "Boolean(true)", "subkey_count": "Integer(3)" },
  "field_path": "CTN_registry_subkeys"
}
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Key does not exist | N/A | `exists` = false, `subkey_count` = 0 |
| Key exists, no subkeys | N/A | `exists` = true, `subkey_count` = 0 |
| Access denied | `AccessDenied` | Error state, collection fails |
| Invalid hive name | `InvalidConfiguration` | Configuration error |
| Command timeout | `CollectionFailed` | Error state |

---

## Comparison: `registry` vs `registry_subkeys`

| Feature | `registry` | `registry_subkeys` |
|---------|------------|-------------------|
| Purpose | Check specific named value | Enumerate child keys |
| `name` field | Required | Not used |
| Returns `value` | Yes | No |
| Returns `type` | Yes (reg executor) | No |
| Returns `subkey_count` | No | Yes |
| Returns `subkeys` | No | Yes |
| Use case | Check if setting = X | Check if readers/devices exist |

---

## OVAL to ESP Mapping

This CTN type handles OVAL definitions that use:
- `registry_object` with `key operation="pattern match"` 
- Tests checking for existence of subkeys under a parent key

| OVAL Pattern | ESP Equivalent |
|--------------|----------------|
| `key operation="pattern match"` with regex for child keys | `subkey_count int >= 1` |
| Check for at least one matching subkey | `exists boolean = true` + `subkey_count int >= 1` |
| `check_existence="none_exist"` for key | `exists boolean = false` |
