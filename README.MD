# LoaderPS - PowerShell Shellcode Loader Builder

A web-based tool for generating PowerShell shellcode loaders with selectable
encryption, injection technique, AMSI/ETW/EDR bypass, sandbox detection, and
cleanup options.

> **TRAINING TOOL ONLY** — Built for offensive-security coursework
> (OSEP-style labs) and authorized red-team engagements. Use only against
> systems you own or have written permission to test.

## Requirements

- Go 1.21+
- A modern browser (the UI is a single HTML page)
- A Windows host to run the *generated* loader (the generator itself runs anywhere)

## Build

### Linux

Native build:

```bash
go build -o LoaderPS .
```

Cross-compile for Windows from Linux:

```bash
GOOS=windows GOARCH=amd64 go build -o LoaderPS.exe .
```

### Windows

Native build (cmd or PowerShell):

```powershell
go build -o LoaderPS.exe .
```

Cross-compile for Linux from Windows:

```cmd
set GOOS=linux
set GOARCH=amd64
go build -o LoaderPS .
```

or in PowerShell:

```powershell
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o LoaderPS .
```

## Run

### Linux

```bash
./LoaderPS
```

### Windows

```powershell
.\LoaderPS.exe
```

The server listens on `http://localhost:8080`. Open it in a browser, fill the
form, click **Build PowerShell Loader**. The script is both returned as a
download and saved to `output/loader_<unix-nano>.ps1` (relative to the
working directory the server was started from).

## Generating a loader

1. **Shellcode** — paste a base64-encoded payload, or use the file picker to
   load a `.bin` (it's base64-encoded client-side). Invalid base64 is rejected
   with a 400.
2. **Encryption** — `None`, `AES-256-CBC`, or `XOR`. Keys are passed to the
   generator and embedded in the PS1; PowerShell decrypts at runtime before
   injection.
3. **Obfuscation** — `basic` wraps the script in `[Convert]::FromBase64String`
   + `Invoke-Expression`. `advanced` randomizes PowerShell variable names.
   `extreme` does both.
4. **Bypass options** — see *Techniques* below.
5. **Execution evasion** — fixed/random sleep, sandbox detection, window
   hiding, telemetry noise.
6. **Injection** — `CreateRemoteThread`, `QueueUserAPC` (EarlyBird), or
   `NtCreateThreadEx`. Target process is selected from a dropdown.
7. **Cleanup** — optional self-delete, event-log clear, history wipe, temp
   wipe, or all of the above.

## Techniques emitted

### AMSI bypass
| Option | Technique |
|---|---|
| `amsiInitFailed` | Reflection-set `AmsiUtils.amsiInitFailed = $true` (Matt Graeber). No P/Invoke needed. |
| `AmsiContext` | Corrupt `amsiContext` data + null `amsiSession` via reflection. |
| `ScanResult` | Patch `amsi!AmsiScanBuffer` prologue with `mov eax, E_INVALIDARG; ret`. |
| `PSLogPolicy` | Registry: disable `ScriptBlockLogging` + `ModuleLogging`. Requires admin. |

All bypass identifiers (`AmsiUtils`, `amsiContext`, etc.) are concatenated at
runtime (`'A' + 'msi' + 'Utils'`) so the bypass code itself doesn't carry the
literal strings that AMSI signatures match.

### ETW bypass
| Option | Technique |
|---|---|
| `etwPatch` | Patch `ntdll!EtwEventWrite` first byte → `0xC3` (RET). |
| `DisableETW` | `COMPLUS_ETWEnabled=0` env var (process-scoped). |
| `CLRProfiling` | Disable CLR profiling via env vars. |
| `DisableTracing` | `logman stop` on common sessions. Requires admin. |

### EDR bypass
| Option | Technique |
|---|---|
| `KillAV` | `Stop-Process` against ~25 known AV/EDR service names. Best-effort; protected processes will refuse. Loud. |
| `PEBPatch` | Clear `PEB!BeingDebugged` + `PEB!NtGlobalFlag` via `NtQueryInformationProcess` (anti-debug evasion). |

### Injection
| Option | Behavior |
|---|---|
| `CreateRemoteThread` | Uses an existing target process if one is running; otherwise spawns one suspended, patches EP with `JMP $`, injects, then restores EP. |
| `QueueUserAPC` | Always spawns target suspended (EarlyBird). Queues an APC pointing at the shellcode, then resumes the main thread so the APC fires on its first alertable wait. |
| `NtCreateThreadEx` | Like CRT but uses the undocumented ntdll function — works on existing or freshly-spawned target. |

### Execution evasion
- **Sandbox detection** — checks `Win32_ComputerSystemProduct`, services, running processes, and `Win32_ComputerSystem.Manufacturer` for VM/analyzer indicators. Runs *after* AMSI bypass so the indicator strings (`VirtualBox`, `Wireshark`, etc.) aren't scanned by an unpatched AMSI.
- **Sleep masking / delay** — fixed 60s/300s/900s/3600s or random 60–600s jitter.
- **Hide window** — `ShowWindowAsync(SW_HIDE)` on the parent console.
- **Telemetry noise** — short sleep + GC to perturb timing/heap fingerprints.

### Cleanup
| Option | What it removes |
|---|---|
| `selfDelete` | The loader file itself (post-execution). |
| `clearEventLog` | System / Application / Security event logs. |
| `deleteHistory` | PSReadLine history file + in-memory history. |
| `wipeTemp` | `%TEMP%` and `%TMP%`. |
| `allCleanup` | All four. |

## Generated-script anatomy

Generated PS1 files are emitted in this order:

1. **AMSI bypass** (must run before any `Add-Type` so the C# isn't scanned)
2. **ETW bypass**
3. **EDR bypass**
4. **Sandbox detection** (deferred to here so flagged strings are safe)
5. Telemetry noise / sleep / hide-window
6. **Shellcode load** (`FromBase64String`, decrypted if applicable)
7. **Win32/ntdll P/Invoke prelude** — one `Add-Type` block defining
   `STARTUPINFO`, `PROCESS_INFORMATION`, `PBI` structs and `PL`/`NT` classes
   with `OpenProcess`, `CreateProcess`, `VirtualAllocEx`, `WriteProcessMemory`,
   `ReadProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread`, `ResumeThread`,
   `WaitForSingleObject`, `CloseHandle`, `NtQueryInformationProcess`,
   `NtCreateThreadEx`, `NtQueueApcThread`. Class names are suffixed with a
   per-build random ID so re-running in the same session doesn't collide.
8. **Process spawn / open** — existing process for CRT/NCT, fresh suspended
   spawn for QUA. `OpenProcess` failures (e.g. svchost without elevation)
   produce a clear error and `exit 1`.
9. **Injection** — method-specific
10. **Cleanup** (if enabled)

Comments and blank lines are stripped post-generation. The stripper is
string- and here-string-aware, so the C# inside `$_tpl = @'...'@` is
preserved verbatim.

## Output

Each build is saved to `output/loader_<unix-nano>.ps1`. Nanosecond resolution
means concurrent builds don't collide.

To run a built loader:

```powershell
powershell -ExecutionPolicy Bypass -File loader.ps1
```

The script is instrumented with `Write-Host` markers (`[*]`, `[+]`, `[!]`)
so you can tell exactly which step ran or failed.

## Project structure

```
.
├── main.go              # HTTP server, embeds templates/
├── handlers/
│   └── handlers.go      # /build POST: form -> options -> generator -> file + download
├── models/
│   └── options.go       # BuildOptions struct (form schema)
├── utils/
│   └── generator.go     # PS script assembly, encryption, obfuscation, comment stripper
├── templates/
│   └── index.html       # Single-page form UI
└── output/              # Generated loaders land here
```

## Notes / caveats

- The AMSI bypasses included are public techniques. Three of them
  (`amsiInitFailed`, `AmsiContext`, `ScanResult`) are signature-detected by
  fully-patched Windows 11 + cloud-delivered Defender. They tend to work
  fine on the Windows 10 lab images shipped with OSEP-style courses.
  Mileage will vary; rotate techniques if one stops working.
- `KillAV` will not touch Defender, CrowdStrike, SentinelOne, or other
  ELAM-protected EDRs on a real system. It's intentionally loud.
- `svchost.exe` as a target only works via the existing-process path
  (svchost requires `-k <service>` args to stay alive when spawned fresh).
  Opening an existing svchost requires admin/SeDebugPrivilege.
- The loader waits for the shellcode thread (`WaitForSingleObject INFINITE`)
  before exiting — appropriate for synchronous payloads and C2 beacons that
  migrate before returning. Inject-and-forget payloads will keep the loader
  alive until the target process exits.

## Legal

Unauthorized use against systems you don't own or have permission to test is
illegal in most jurisdictions. This repository is for training and authorized
testing only.
