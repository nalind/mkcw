package types

// RegistrationRequest is the body of the request which we use for registering
// this confidential workload with the attestation server.
// https://github.com/virtee/reference-kbs/blob/10b2a4c0f8caf78a077210b172863bbae54f66aa/src/main.rs#L83
type RegistrationRequest struct {
	WorkloadID        string `json:"workload_id"`
	LaunchMeasurement string `json:"launch_measurement"`
	Passphrase        string `json:"passphrase"`
	TeeConfig         string `json:"tee_config"` // JSON-encoded teeConfig? or specific to the type of TEE?
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
