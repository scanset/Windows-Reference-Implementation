# CTN Type Reference: `file_metadata`

## Overview

Fast metadata collection via `stat()` for file permissions, ownership, group, existence, and size validation.

**Platform:** Linux, macOS, Windows
**Use Case:** Security compliance validation of file permissions and ownership

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `path` | string | Yes | File system path (absolute or relative) | `/etc/sudoers`, `C:\Windows\System32\config\SAM` |
| `type` | string | No | Resource type indicator (informational only) | `file` |

### Notes

- Supports VAR resolution in paths
- Both absolute and relative paths accepted
- Use forward slashes (`/`) or backslashes (`\`) appropriate to target platform

---

## Collected Data Fields (Output)

### Portable Fields (All Platforms)

| Field | Type | Description |
|-------|------|-------------|
| `exists` | boolean | Whether file exists |
| `readable` | boolean | Whether file is readable by current process |
| `writable` | boolean | Whether file is writable by current process |
| `file_size` | int | File size in bytes |
| `is_directory` | boolean | Whether the path is a directory |
| `file_owner` | string | File owner identifier (UID on Unix, SID on Windows) |
| `file_group` | string | File group identifier (GID on Unix, SID on Windows) |

### Linux/macOS Only

| Field | Type | Description |
|-------|------|-------------|
| `file_mode` | string | File permissions in 4-digit octal format (e.g., `0644`) |

**Note:** Returns empty string on Windows.

### Windows Only

| Field | Type | Description |
|-------|------|-------------|
| `is_readonly` | boolean | Read-only attribute set |
| `is_hidden` | boolean | Hidden attribute set |
| `is_system` | boolean | System file attribute set |

**Note:** These fields return `false` on Linux/macOS.

---

## State Fields (Validation)

### Portable Fields (All Platforms)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `exists` | boolean | `=`, `!=` | `exists` | Whether file exists |
| `readable` | boolean | `=`, `!=` | `readable` | Whether file is readable |
| `writable` | boolean | `=`, `!=` | `writable` | Whether file is writable |
| `size` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | `file_size` | File size in bytes |
| `is_directory` | boolean | `=`, `!=` | `is_directory` | Whether path is a directory |
| `owner_id` | string | `=`, `!=` | `file_owner` | Owner identifier (UID or SID) |
| `group_id` | string | `=`, `!=` | `file_group` | Group identifier (GID or SID) |

### Linux/macOS Only

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `permissions` | string | `=`, `!=` | `file_mode` | File permissions in octal format |

### Windows Only

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `is_readonly` | boolean | `=`, `!=` | `is_readonly` | Read-only attribute |
| `is_hidden` | boolean | `=`, `!=` | `is_hidden` | Hidden attribute |
| `is_system` | boolean | `=`, `!=` | `is_system` | System file attribute |

---

## Owner/Group Identifier Reference

### Linux/macOS (UID/GID)

| Identifier | Meaning |
|------------|---------|
| `0` | root |
| `1000` | First regular user (typically) |

### Windows (SID)

| SID | Meaning |
|-----|---------|
| `S-1-5-18` | Local System |
| `S-1-5-19` | Local Service |
| `S-1-5-20` | Network Service |
| `S-1-5-32-544` | Administrators group |
| `S-1-5-32-545` | Users group |
| `S-1-5-32-546` | Guests group |

**Note:** Windows may also return `DOMAIN\Username` format if SID lookup succeeds.

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `filesystem` |
| Collection Mode | Metadata |
| Required Capabilities | `file_access` |
| Expected Collection Time | ~5ms |
| Memory Usage | ~1MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## ESP Examples

### Portable: Check file exists and is readable

```esp
OBJECT config_file
    path `/etc/myapp/config.yml`
OBJECT_END

STATE must_be_accessible
    exists boolean = true
    readable boolean = true
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF must_be_accessible
    OBJECT_REF config_file
CTN_END
```

### Portable: Check file is NOT writable

```esp
OBJECT sensitive_file
    path `/etc/passwd`
OBJECT_END

STATE not_world_writable
    exists boolean = true
    writable boolean = false
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF not_world_writable
    OBJECT_REF sensitive_file
CTN_END
```

### Portable: File size validation

```esp
OBJECT log_file
    path `/var/log/audit/audit.log`
OBJECT_END

STATE not_empty
    exists boolean = true
    size int > `0`
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF not_empty
    OBJECT_REF log_file
CTN_END
```

### Portable: Check file does NOT exist

```esp
OBJECT dangerous_file
    path `/etc/dangerous.conf`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF dangerous_file
CTN_END
```

### Linux: Basic permissions check

```esp
OBJECT sudoers_file
    path `/etc/sudoers`
OBJECT_END

STATE secure_permissions
    exists boolean = true
    permissions string = `0440`
    owner_id string = `0`
    group_id string = `0`
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF secure_permissions
    OBJECT_REF sudoers_file
CTN_END
```

### Linux: Multiple files with same requirements

```esp
OBJECT passwd_file
    path `/etc/passwd`
OBJECT_END

OBJECT shadow_file
    path `/etc/shadow`
OBJECT_END

STATE root_owned
    exists boolean = true
    owner_id string = `0`
STATE_END

CTN file_metadata
    TEST all all
    STATE_REF root_owned
    OBJECT_REF passwd_file
    OBJECT_REF shadow_file
CTN_END
```

### Windows: Check system file ownership

```esp
OBJECT sam_file
    path `C:\Windows\System32\config\SAM`
OBJECT_END

STATE system_owned
    exists boolean = true
    owner_id string = `S-1-5-18`
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF system_owned
    OBJECT_REF sam_file
CTN_END
```

### Windows: Check file is not hidden

```esp
OBJECT config_file
    path `C:\ProgramData\MyApp\config.ini`
OBJECT_END

STATE visible_config
    exists boolean = true
    is_hidden boolean = false
    readable boolean = true
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF visible_config
    OBJECT_REF config_file
CTN_END
```

### Windows: System file attributes

```esp
OBJECT boot_file
    path `C:\Windows\System32\ntoskrnl.exe`
OBJECT_END

STATE protected_system_file
    exists boolean = true
    is_system boolean = true
    is_readonly boolean = true
STATE_END

CTN file_metadata
    TEST at_least_one all
    STATE_REF protected_system_file
    OBJECT_REF boot_file
CTN_END
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| File does not exist | N/A | `exists` = false, other fields empty/default |
| Permission denied (stat) | `AccessDenied` | Error state |
| Invalid path | `InvalidObjectConfiguration` | Configuration error |
| Path field missing | `InvalidObjectConfiguration` | Configuration error |

---

## Platform Notes

### Linux / macOS (Unix)

- Uses `stat()` system call
- `permissions` returned as 4-digit octal (e.g., `0644`)
- `owner_id`/`group_id` returned as numeric UID/GID strings
- Windows-specific fields (`is_readonly`, `is_hidden`, `is_system`) return `false`

### Windows

- Uses Win32 API (`GetFileAttributesW`, `GetSecurityInfo`)
- `permissions` returns empty string (not applicable)
- `owner_id`/`group_id` returned as SID strings (e.g., `S-1-5-18`) or `DOMAIN\User` format
- Full support for Windows attribute fields

---

## Security Considerations

- No elevated privileges required for most files
- Some system files may require root/admin access to stat
- Does not read file content (use `file_content` for that)
- SID lookup may fail for orphaned files; raw SID returned in that case

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| `file_content` | Content validation (more expensive) |
| `json_record` | Structured JSON file validation |

---

## Migration Notes

### Renamed Fields (from previous versions)

| Old Field | New Field | Notes |
|-----------|-----------|-------|
| `owner` | `owner_id` | Clarifies this is an identifier, not a name |
| `group` | `group_id` | Clarifies this is an identifier, not a name |

### New Fields

| Field | Version Added | Notes |
|-------|---------------|-------|
| `writable` | 1.1 | Portable write permission check |
| `is_directory` | 1.1 | Portable directory check |
| `is_readonly` | 1.1 | Windows-specific attribute |
| `is_hidden` | 1.1 | Windows-specific attribute |
| `is_system` | 1.1 | Windows-specific attribute |
