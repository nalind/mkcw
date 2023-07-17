package mkcw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"

	"github.com/sirupsen/logrus"
)

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

// SendRegistrationRequest registers a workload with the specified decryption
// passphrase
func SendRegistrationRequest(workloadConfig WorkloadConfig, diskEncryptionPassphrase string, ignoreAttestationErrors bool, logger *logrus.Logger) error {
	if workloadConfig.AttestationURL == "" {
		return errors.New("attestation URL not provided")
	}

	// Measure the execution environment.
	measurement, err := GenerateMeasurement(workloadConfig)
	if err != nil {
		return err
	}

	// Build the workload registration (attestation) request body.
	var teeConfigBytes []byte
	switch workloadConfig.Type {
	case SEV, SNP:
		teeConfig := TeeConfig{
			Flags: TeeConfigFlags{
				Bits: 63,
			},
			MinFW: TeeConfigMinFW{
				Major: 0,
				Minor: 0,
			},
		}
		teeConfigBytes, err = json.Marshal(teeConfig)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("don't know how to generate tee_config for %q TEEs", workloadConfig.Type)
	}

	registrationRequest := RegistrationRequest{
		WorkloadID:        workloadConfig.WorkloadID,
		LaunchMeasurement: measurement,
		TeeConfig:         string(teeConfigBytes),
		Passphrase:        diskEncryptionPassphrase,
	}
	registrationRequestBytes, err := json.Marshal(registrationRequest)
	if err != nil {
		return err
	}

	// Register the workload.
	url := path.Join(workloadConfig.AttestationURL, "/kbs/v0/register_workload")
	requestContentType := "application/json"
	requestBody := bytes.NewReader(registrationRequestBytes)
	resp, err := http.Post(url, requestContentType, requestBody)
	if resp != nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		if resp.StatusCode != http.StatusAccepted {
			logger.Warnf("received status %d (%q) while registering workload", resp.StatusCode, resp.Status)
		}
	}
	if err != nil {
		if !ignoreAttestationErrors {
			return err
		}
		logger.Warnf("while registering workload: %v", err)
	}
	return nil
}
