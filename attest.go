package mkcw

// AttestationRequest is the body of the request which we use for registering
// this confidential workload with the attestation server.
type attestationRequest struct {
	WorkloadID        string `json:"workload_id"`
	LaunchMeasurement string `json:"launch_measurement"`
	Passphrase        string `json:"passphrase"`
	TeeConfig         string `json:"tee_config"` // JSON-encoded teeConfig? or specific to the type of TEE?
}

// teeConfig contains information about a trusted execution environment.
type teeConfig struct {
	Flags teeConfigFlags `json:"flags"`
	MinFW teeConfigMinFW `json:"minfw"`
}

// teeConfigFlags is ...?
type teeConfigFlags struct {
	Bits int `json:"bits"` // 63
}

// teeConfigFlagMinFW corresponds to a minimum version of the kernel+initrd
// combination that should be booted.
type teeConfigMinFW struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}
