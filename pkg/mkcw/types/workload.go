package types

// WorkloadConfig is the data type which is encoded and stored in /krun-sev.json in an image.
// https://github.com/containers/libkrun/blob/57c59dc5359bdeeb8260b3493e9f63d3708f9ab9/src/vmm/src/resources.rs#L57
type WorkloadConfig struct {
	Type           TeeType `json:"tee"`
	TeeData        string  `json:"tee_data"` // Type == SEV: JSON-encoded sevWorkloadData, SNP: ...? others?
	WorkloadID     string  `json:"workload_id"`
	CPUs           int     `json:"cpus"`
	Memory         int     `json:"ram_mib"`
	AttestationURL string  `json:"attestation_url"`
}

// SevWorkloadData contains the path to the SEV certificate chain and optionally,
// the attestation server's public key(?)
// https://github.com/containers/libkrun/blob/d31747aa92cf83df2abaeb87e2a83311c135d003/src/vmm/src/linux/tee/amdsev.rs#L222
type SevWorkloadData struct {
	VendorChain             string `json:"vendor_chain"`
	AttestationServerPubkey string `json:"attestation_server_pubkey"`
}

// SnpWorkloadData contains the required CPU generation name.
// https://github.com/virtee/oci2cw/blob/1502d5be33c2fa82d49aaa95781bbab2aa932781/examples/tee-config-snp.json
type SnpWorkloadData struct {
	Generation string `json:"gen"` // "milan"
}

const (
	// SEV is a known trusted execution environment type: AMD-SEV
	SEV TeeType = "sev"
	// SNP is a known trusted execution environment type: AMD-SNP
	SNP TeeType = "snp"
)

// TeeType is a supported trusted execution environment type.
type TeeType string