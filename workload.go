package mkcw

// workloadConfig is the data type which is encoded and stored in /krun-sev.json in an image.
type workloadConfig struct {
	Type           TeeType `json:"tee"`
	TeeData        string  `json:"tee_data"` // Type == SEV: JSON-encoded sevWorkloadData, SNP: ...? others?
	WorkloadID     string  `json:"workload_id"`
	CPUs           int     `json:"cpus"`
	Memory         int     `json:"ram_mib"`
	AttestationURL string  `json:"attestation_url"`
}

// sevWorkloadData contains the path to the SEV certificate chain and optionally,
// the attestation server's public key(?)
type sevWorkloadData struct {
	VendorChain             string `json:"vendor_chain"`
	AttestationServerPubkey string `json:"attestation_server_pubkey"`
}

const (
	// SEV is a known trusted execution environment type: AMD-SEV
	SEV TeeType = "sev"
	// SNP is a known trusted execution environment type: AMD-SNP
	SNP TeeType = "snp"
)

// TeeType is a supported trusted execution environment type.
type TeeType string
