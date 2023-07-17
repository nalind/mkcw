package mkcw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"

	"github.com/nalind/mkcw/pkg/mkcw/types"
	"github.com/sirupsen/logrus"
)

type RegistrationRequest = types.RegistrationRequest
type TeeConfig = types.TeeConfig
type TeeConfigFlags = types.TeeConfigFlags
type TeeConfigMinFW = types.TeeConfigMinFW

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
