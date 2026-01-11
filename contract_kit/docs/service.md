# CTN Type Reference: `service`

## Overview

Validates Windows Service configuration and runtime state.

**Common STIG uses:**
- Ensure a service exists / does not exist
- Ensure a service is running / stopped
- Ensure a service startup type is correctly configured (e.g., Disabled)
- Validate service binary path for tampering detection
- Verify service type (own process vs shared)

**OVAL Equivalent:** `service_test`, `service_object`, `service_state`

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `name` | string | Yes | Service name (not DisplayName) | `W32Time`, `TermService`, `Spooler` |

### Behaviors

| Behavior | Values | Default | Description |
|----------|--------|---------|-------------|
| `executor` | `sc`, `powershell` | `sc` | Collection method |

**Notes:**
- Use the service name (e.g., `W32Time`) not the display name (e.g., "Windows Time")
- `sc` executor requires two commands (`sc query` + `sc qc`) but provides `service_type`
- `powershell` executor uses `Get-CimInstance` and can detect `DelayedAutoStart`

---

## Collected Data Fields (Output)

| Field | Type | Executor | Description |
|-------|------|----------|-------------|
| `exists` | boolean | Both | Whether the service exists |
| `state` | string | Both | Runtime state: `running`, `stopped`, `paused`, `start_pending`, `stop_pending`, `continue_pending`, `pause_pending`, `unknown` |
| `start_type` | string | Both | Startup type: `auto`, `auto_delayed`, `manual`, `disabled`, `boot`, `system`, `unknown` |
| `display_name` | string | Both | Display name (e.g., "Windows Time") |
| `path` | string | Both | Binary path / image path |
| `service_type` | string | Both | Type: `own_process`, `own_process_interactive`, `share_process`, `kernel_driver`, `file_system_driver`, `unknown` |

### Normalization Notes

**`state`** is normalized from:
- `sc query`: `RUNNING` → `running`, `STOPPED` → `stopped`, etc.
- PowerShell: `Running` → `running`, `Stopped` → `stopped`, etc.

**`start_type`** is normalized from:
- `sc qc`: `AUTO_START` → `auto`, `AUTO_START  (DELAYED)` → `auto_delayed`, `DEMAND_START` → `manual`, `DISABLED` → `disabled`
- PowerShell: `Automatic` + `DelayedAutoStart=True` → `auto_delayed`, `Automatic` → `auto`, `Manual` → `manual`, `Disabled` → `disabled`

**`service_type`** is normalized from:
- `sc qc`: `WIN32_OWN_PROCESS` → `own_process`, `WIN32_SHARE_PROCESS` → `share_process`, `WIN32_OWN_PROCESS (interactive)` → `own_process_interactive`
- PowerShell: `Own Process` → `own_process`, `Share Process` → `share_process`

---

## State Fields (Validation)

| Field | Type | Operations | Maps To | Description |
|-------|------|------------|---------|-------------|
| `exists` | boolean | `=`, `!=` | `exists` | Service existence |
| `state` | string | `=`, `!=`, `ieq` | `state` | Service runtime state |
| `start_type` | string | `=`, `!=`, `ieq` | `start_type` | Startup mode |
| `display_name` | string | `=`, `!=`, `contains`, `starts`, `ends`, `pattern_match`, `ieq` | `display_name` | Display name validation |
| `path` | string | `=`, `!=`, `contains`, `starts`, `ends`, `pattern_match`, `ieq` | `path` | Service binary path validation |
| `service_type` | string | `=`, `!=`, `ieq` | `service_type` | Service process type |

### Existence Short-Circuit Behavior

When `exists` is specified in a STATE, the executor uses short-circuit evaluation:

| Scenario | `exists` in STATE | Service Status | Behavior |
|----------|-------------------|----------------|----------|
| **1** | `exists boolean = true` | Missing | **FAIL immediately**, skip state/start_type checks |
| **2** | `exists boolean = true` | Exists | Continue to state/start_type checks |
| **3** | `exists boolean = false` | Missing | **PASS immediately**, skip other checks |
| **4** | `exists boolean = false` | Exists | **FAIL** (service should not exist) |
| **5** | Not specified | Missing | Check other fields (will fail with verbose errors) |

**Recommendation:** Always include `exists boolean = true` when validating services that must exist. This provides:
- Clean, single-line failure messages
- Better performance (no unnecessary field checks)
- Clear intent in policy definition

---

## Command Execution

### `sc` executor (default)

**Query runtime state:**
```cmd
sc.exe query "W32Time"
```

**Output:**
```
SERVICE_NAME: W32Time
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

**Query configuration:**
```cmd
sc.exe qc "W32Time"
```

**Output:**
```
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: W32Time
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\windows\system32\svchost.exe -k LocalService
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Time
        DEPENDENCIES       :
        SERVICE_START_NAME : NT AUTHORITY\LocalService
```

**Delayed auto-start example:**
```cmd
sc.exe qc "WSearch"
```

**Output (note the `(DELAYED)` suffix):**
```
        START_TYPE         : 2   AUTO_START  (DELAYED)
```

**Non-existent service:**
```cmd
sc.exe query "FakeService"
```

**Output:**
```
[SC] EnumQueryServicesStatus:OpenService FAILED 1060:
The specified service does not exist as an installed service.
```

### `powershell` executor

```powershell
Get-CimInstance -ClassName Win32_Service -Filter "Name='W32Time'" | Select-Object Name, State, StartMode, DisplayName, PathName, ServiceType, DelayedAutoStart
```

**Output:**
```
Name             : W32Time
State            : Running
StartMode        : Manual
DisplayName      : Windows Time
PathName         : C:\windows\system32\svchost.exe -k LocalService
ServiceType      : Share Process
DelayedAutoStart :
```

**Non-existent service returns empty/null (no error, no output).**

---

## ESP Examples

### Basic service check (with existence)

```esp
OBJECT time_service
    name `W32Time`
OBJECT_END

STATE service_running
    exists boolean = true
    state string = `running`
STATE_END

CTN service
    TEST at_least_one all
    STATE_REF service_running
    OBJECT_REF time_service
CTN_END
```

### Ensure service is disabled

```esp
OBJECT remote_registry
    name `RemoteRegistry`
OBJECT_END

STATE must_be_disabled
    exists boolean = true
    start_type string = `disabled`
STATE_END

CTN service
    TEST at_least_one all
    STATE_REF must_be_disabled
    OBJECT_REF remote_registry
CTN_END
```

### Check that a service does NOT exist

```esp
OBJECT dangerous_service
    name `TelnetServer`
OBJECT_END

STATE must_not_exist
    exists boolean = false
STATE_END

CTN service
    TEST at_least_one all
    STATE_REF must_not_exist
    OBJECT_REF dangerous_service
CTN_END
```

### Validate service binary path (anti-tampering)

```esp
OBJECT spooler_service
    name `Spooler`
OBJECT_END

STATE valid_spooler
    exists boolean = true
    state string = `running`
    path string = `C:\windows\System32\spoolsv.exe`
STATE_END

CTN service
    TEST at_least_one all
    STATE_REF valid_spooler
    OBJECT_REF spooler_service
CTN_END
```

### With PowerShell executor

```esp
OBJECT search_service
    name `WSearch`
    behavior executor powershell
OBJECT_END

STATE delayed_auto_start
    exists boolean = true
    start_type string = `auto_delayed`
STATE_END

CTN service
    TEST at_least_one all
    STATE_REF delayed_auto_start
    OBJECT_REF search_service
CTN_END
```

### Multiple services must be running (SET)

```esp
OBJECT firewall_svc
    name `MpsSvc`
OBJECT_END

OBJECT defender_svc
    name `WinDefend`
OBJECT_END

SET security_services union
    OBJECT_REF firewall_svc
    OBJECT_REF defender_svc
SET_END

STATE must_be_running
    exists boolean = true
    state string = `running`
STATE_END

CRI AND
    CTN service
        TEST all all
        STATE_REF must_be_running
        OBJECT
            SET_REF security_services
        OBJECT_END
    CTN_END
CRI_END
```

---

## Finding Output Examples

### Service does not exist (with `exists boolean = true`)

```json
{
  "finding_id": "finding-188847d6e3287d6c",
  "severity": "high",
  "title": "service validation failed",
  "description": "Service validation failed:\n  - Service 'telnet_service': Service does not exist",
  "expected": { "exists": "Boolean(true)" },
  "actual": { "exists": "Boolean(false)" },
  "field_path": "CTN_service"
}
```

### Service exists but wrong state

```json
{
  "finding_id": "finding-188847d6e628148c",
  "severity": "high",
  "title": "service validation failed",
  "description": "Service validation failed:\n  - Service 'remote_registry': state check failed: got running, expected = stopped",
  "expected": { "exists": "Boolean(true)", "state": "String(\"stopped\")" },
  "actual": { "exists": "Boolean(true)", "state": "String(\"running\")" },
  "field_path": "CTN_service"
}
```

### Service has wrong startup type

```json
{
  "finding_id": "finding-188847d6e628149a",
  "severity": "medium",
  "title": "service validation failed",
  "description": "Service validation failed:\n  - Service 'remote_registry': start_type check failed: got manual, expected = disabled",
  "expected": { "exists": "Boolean(true)", "start_type": "String(\"disabled\")" },
  "actual": { "exists": "Boolean(true)", "start_type": "String(\"manual\")" },
  "field_path": "CTN_service"
}
```

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Service does not exist | `ObjectNotFound` | `exists` = false, counted as missing for existence check |
| Access denied | `AccessDenied` | Error state, object exists but inaccessible |
| Command timeout | `CollectionFailed` | Error state |
| Invalid service name input | `InvalidConfiguration` | Configuration error |
| sc.exe not found | `CollectionFailed` | Error state |

### sc.exe Error Codes

| Exit Code | Meaning | Handling |
|-----------|---------|----------|
| 0 | Success | Parse output |
| 1060 | Service does not exist | Return `exists = false` |
| 5 | Access denied | Return `AccessDenied` error |

---

## OVAL to ESP Mapping

| OVAL Element | ESP Equivalent |
|--------------|----------------|
| `service_object/service_name` | `OBJECT.name` |
| `service_state/service_name` | (implicit from object) |
| `service_state/current_state` | `STATE.state` |
| `service_state/start_type` | `STATE.start_type` |
| `service_state/path` | `STATE.path` |
| `service_state/display_name` | `STATE.display_name` |
| `service_state/service_type` | `STATE.service_type` |
| `check_existence="all_exist"` | `TEST all all` + `exists boolean = true` |
| `check_existence="at_least_one_exists"` | `TEST at_least_one all` |
| `check_existence="none_exist"` | `exists boolean = false` |
| `operation="equals"` | `=` |
| `operation="not equal"` | `!=` |
| `operation="case insensitive equals"` | `ieq` |
| `operation="pattern match"` | `pattern_match` |

---

## Appendix: Normalization Tables

### State Values

| sc.exe (STATE line) | PowerShell (State) | Normalized |
|---------------------|-------------------|------------|
| `1  STOPPED` | `Stopped` | `stopped` |
| `2  START_PENDING` | `StartPending` | `start_pending` |
| `3  STOP_PENDING` | `StopPending` | `stop_pending` |
| `4  RUNNING` | `Running` | `running` |
| `5  CONTINUE_PENDING` | `ContinuePending` | `continue_pending` |
| `6  PAUSE_PENDING` | `PausePending` | `pause_pending` |
| `7  PAUSED` | `Paused` | `paused` |

### Start Type Values

| sc.exe (START_TYPE line) | PowerShell (StartMode + DelayedAutoStart) | Normalized |
|--------------------------|-------------------------------------------|------------|
| `0   BOOT_START` | N/A | `boot` |
| `1   SYSTEM_START` | N/A | `system` |
| `2   AUTO_START` | `Automatic` + `False` | `auto` |
| `2   AUTO_START  (DELAYED)` | `Automatic` + `True` | `auto_delayed` |
| `3   DEMAND_START` | `Manual` | `manual` |
| `4   DISABLED` | `Disabled` | `disabled` |

### Service Type Values

| sc.exe (TYPE line) | PowerShell (ServiceType) | Normalized |
|--------------------|--------------------------|------------|
| `1  KERNEL_DRIVER` | `Kernel Driver` | `kernel_driver` |
| `2  FILE_SYSTEM_DRIVER` | `File System Driver` | `file_system_driver` |
| `10  WIN32_OWN_PROCESS` | `Own Process` | `own_process` |
| `20  WIN32_SHARE_PROCESS` | `Share Process` | `share_process` |
| `110  WIN32_OWN_PROCESS (interactive)` | `Own Process` (interactive) | `own_process_interactive` |
