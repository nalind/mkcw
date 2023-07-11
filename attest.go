package mkcw

// AttestationRequest is the type of the request which we use for registering
// this confidential workload with the attestation server.
type AttestationRequest struct {
	WorkloadID        string `json:"workload_id"`
	LaunchMeasurement string `json:"launch_measurement"`
	Passphrase        string `json:"passphrase"`
	TeeConfig         string `json:"tee_config"` // JSON-encoded TeeConfig
}

// TeeConfig contains information about a trusted execution environment.
type TeeConfig struct {
	Flags TeeConfigFlags `json:"flags"`
	MinFW TeeConfigMinFW `json:"minfw"`
}

// TeeConfigFlags is ...?
type TeeConfigFlags struct {
	Bits int `json:"bits"` // 63
}

// TeeConfigFlagMinFW corresponds to a minimum version of the kernel+initrd
// combination that should be booted.
type TeeConfigMinFW struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}
