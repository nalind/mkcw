package mkcw

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/nalind/mkcw/pkg/mkcw/types"
	"github.com/sirupsen/logrus"
)

type (
	RegistrationRequest = types.RegistrationRequest
	TeeConfig           = types.TeeConfig
	TeeConfigFlags      = types.TeeConfigFlags
	TeeConfigMinFW      = types.TeeConfigMinFW
)

type attestationError struct {
	err error
}

func (a attestationError) Error() string {
	return fmt.Sprintf("registering workload: %v", a.err)
}

type httpError struct {
	statusCode int
}

func (h httpError) Error() string {
	if statusText := http.StatusText(h.statusCode); statusText != "" {
		return fmt.Sprintf("received server status %d (%q)", h.statusCode, statusText)
	}
	return fmt.Sprintf("received server status %d", h.statusCode)
}

// SendRegistrationRequest registers a workload with the specified decryption
// passphrase with the service whose location is part of the WorkloadConfig.
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
	case SEV, SEV_NO_ES, SNP:
		var cbits types.TeeConfigFlagBits
		switch workloadConfig.Type {
		case SEV:
			cbits = types.SEV_CONFIG_NO_DEBUG |
				types.SEV_CONFIG_NO_KEY_SHARING |
				types.SEV_CONFIG_ENCRYPTED_STATE |
				types.SEV_CONFIG_NO_SEND |
				types.SEV_CONFIG_DOMAIN |
				types.SEV_CONFIG_SEV
		case SEV_NO_ES:
			cbits = types.SEV_CONFIG_NO_DEBUG |
				types.SEV_CONFIG_NO_KEY_SHARING |
				types.SEV_CONFIG_NO_SEND |
				types.SEV_CONFIG_DOMAIN |
				types.SEV_CONFIG_SEV
		case SNP:
			cbits = types.SNP_CONFIG_SMT |
				types.SNP_CONFIG_MANDATORY |
				types.SNP_CONFIG_MIGRATE_MA |
				types.SNP_CONFIG_DEBUG
		default:
			panic("internal error") // shouldn't happen
		}
		teeConfig := TeeConfig{
			Flags: TeeConfigFlags{
				Bits: cbits,
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
	parsedUrl, err := url.Parse(workloadConfig.AttestationURL)
	if err != nil {
		return err
	}
	parsedUrl.Path = path.Join(parsedUrl.Path, "/kbs/v0/register_workload")
	if err != nil {
		return err
	}
	url := parsedUrl.String()
	requestContentType := "application/json"
	requestBody := bytes.NewReader(registrationRequestBytes)
	resp, err := http.Post(url, requestContentType, requestBody)
	if resp != nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		switch resp.StatusCode {
		default:
			if !ignoreAttestationErrors {
				return &attestationError{&httpError{resp.StatusCode}}
			}
			logger.Warn(attestationError{&httpError{resp.StatusCode}}.Error())
		case http.StatusOK, http.StatusAccepted:
			// great!
		}
	}
	if err != nil {
		if !ignoreAttestationErrors {
			return &attestationError{err}
		}
		logger.Warn(attestationError{err}.Error())
	}
	return nil
}

// GenerateMeasurement generates the runtime measurement using the CPU count,
// memory size, and the firmware shared library, whatever it's called, wherever
// it is.
func GenerateMeasurement(workloadConfig WorkloadConfig) (string, error) {
	cpuString := fmt.Sprintf("%d", workloadConfig.CPUs)
	memoryString := fmt.Sprintf("%d", workloadConfig.Memory)
	var prefix string
	switch workloadConfig.Type {
	case SEV:
		prefix = "SEV-ES"
	case SEV_NO_ES:
		prefix = "SEV"
	case SNP:
		prefix = "SNP"
	default:
		return "", fmt.Errorf("don't know which measurement to use for TEE type %q", workloadConfig.Type)
	}

	sharedLibraryDirs := append([]string{
		"/usr/local/lib64",
		"/usr/local/lib",
		"/lib64",
		"/lib",
		"/usr/lib64",
		"/usr/lib",
	}, strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":")...)
	libkrunfwNames := []string{
		"libkrunfw-sev.so.3",
		"libkrunfw-sev.so",
	}
	for _, sharedLibraryDir := range sharedLibraryDirs {
		if sharedLibraryDir == "" {
			continue
		}
		for _, libkrunfw := range libkrunfwNames {
			candidate := filepath.Join(sharedLibraryDir, libkrunfw)
			if _, err := os.Lstat(candidate); err == nil {
				var stdout, stderr bytes.Buffer
				cmd := exec.Command("krunfw_measurement", "-c", cpuString, "-m", memoryString, candidate)
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil {
					if stderr.Len() > 0 {
						err = fmt.Errorf("krunfw_measurement: %s: %w", strings.TrimSpace(stderr.String()), err)
					}
					return "", err
				}
				scanner := bufio.NewScanner(&stdout)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, prefix+":") {
						return strings.TrimSpace(strings.TrimPrefix(line, prefix+":")), nil
					}
				}
				return "", fmt.Errorf("no line starting with %q found in output from krunfw_measurement", prefix+":")
			}
		}
	}
	return "", fmt.Errorf("none of %v found in %v: %w", libkrunfwNames, sharedLibraryDirs, os.ErrNotExist)
}
