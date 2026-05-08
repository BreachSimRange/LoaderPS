# LoaderPS - PowerShell Shellcode Loader Builder

A web-based tool for generating PowerShell shellcode loaders with various injection techniques, encryption, and evasion options.

>  **TRAINING TOOL ONLY** - This loader was created exclusively for offensive security training. Use only in authorized lab environments.

## Features

- **Encryption:** AES-256-CBC, XOR
- **Obfuscation:** Variable randomization, Base64 encoding
- **Injection Methods:** CreateRemoteThread, QueueUserAPC, NtCreateThreadEx
- **Bypass Options:** AMSI, ETW, EDR
- **Evasion:** Sandbox detection, execution delay, sleep masking, window hiding
- **Cleanup:** Self-delete, clear event logs, wipe history/temp files

## Requirements

- Go 1.21+

## Installation
```bash
git clone https://github.com/BreachSimRange/LoaderPS.git
cd LoaderPS
mkdir output
```

## Compilation

### Linux
```bash
# Build for Linux
go build -o LoaderPS main.go

# Build for Windows (cross-compile)
GOOS=windows GOARCH=amd64 go build -o LoaderPS.exe main.go
```

### Windows
```powershell
# Build for Windows
go build -o LoaderPS.exe main.go

# Build for Linux (cross-compile)
set GOOS=linux
set GOARCH=amd64
go build -o LoaderPS main.go
```

## Usage

### Linux
```bash
# Run directly
go run main.go

# Or run compiled binary
./LoaderPS
```

### Windows
```powershell
# Run directly
go run main.go

# Or run compiled binary
.\LoaderPS.exe
```

Then open `http://localhost:8080` in your browser.

## Generating a Loader

1. Enter shellcode (Base64) or upload a `.bin` file
2. Select encryption method and key (optional)
3. Choose injection technique and target process
4. Enable desired bypass/evasion options
5. Click **Build PowerShell Loader**
6. Generated scripts are saved to the `output/` directory


---

**BreachSimRange**

© 2026 BreachSimRange - Training Build v1.0
