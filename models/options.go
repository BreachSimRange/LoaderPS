package models

type BuildOptions struct {

	Shellcode string

	Encrypt       bool
	EncryptType   string
	AESKey        string
	XORKey        string
	Obfuscate          bool
	ObfuscationLevel   string 
	AMSIBypass     bool
	AMSIBypassType string 
	ETWBypass     bool
	ETWBypassType string 
	EDRBypassType string
	SleepMasking      bool
	ExecutionDelay    int 
	HideWindow        bool
	TelemetryNoise    bool
	SandboxDetection bool
	InjectionMethod string
	TargetProc      string
	CleanupMethod string
}
