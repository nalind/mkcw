package mkcw

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nalind/mkcw/pkg/mkcw/types"
)

type WorkloadConfig = types.WorkloadConfig
type SevWorkloadData = types.SevWorkloadData
type SnpWorkloadData = types.SnpWorkloadData
type TeeType = types.TeeType

const (
	maxWorkloadConfigSize = 1024 * 1024
	// SEV is a known trusted execution environment type: AMD-SEV
	SEV = types.SEV
	// SNP is a known trusted execution environment type: AMD-SNP
	SNP = types.SNP
)

// ReadWorkloadConfigFromImage reads the workload configuration from the
// specified disk image file
func ReadWorkloadConfigFromImage(path string) (WorkloadConfig, error) {
	// Read the last 12 bytes, which should be "KRUN" followed by a 64-bit
	// little-endian length.  The (length) bytes immediately preceding
	// these hold the JSON-encoded workloadConfig.
	var wc WorkloadConfig
	f, err := os.Open(path)
	if err != nil {
		return wc, err
	}
	defer f.Close()

	// Read those last 12 bytes.
	finalTwelve := make([]byte, 12)
	if _, err = f.Seek(12, os.SEEK_END); err != nil {
		return wc, err
	}
	if n, err := f.Read(finalTwelve); err != nil || n != len(finalTwelve) {
		if err != nil {
			return wc, err
		}
		return wc, fmt.Errorf("short read (expected 12 bytes at the end of %q, got %d)", path, n)
	}
	if magic := string(finalTwelve[0:4]); magic != "KRUN" {
		return wc, fmt.Errorf("expected magic string KRUN in %q, found %q)", path, magic)
	}
	length := binary.LittleEndian.Uint64(finalTwelve[4:])
	if length > maxWorkloadConfigSize {
		return wc, fmt.Errorf("workload config in %q is %d bytes long, which seems unreasonable (max allowed %d)", path, length, maxWorkloadConfigSize)
	}

	// Read and decode the config.
	configBytes := make([]byte, length)
	if _, err = f.Seek(int64(length)+12, os.SEEK_END); err != nil {
		return wc, err
	}
	if n, err := f.Read(configBytes); err != nil || n != len(configBytes) {
		if err != nil {
			return wc, err
		}
		return wc, fmt.Errorf("short read (expected %d bytes near the end of %q, got %d)", len(configBytes), path, n)
	}
	err = json.Unmarshal(configBytes, &wc)
	return wc, err
}

// WriteWorkloadConfigToImage writes the workload configuration to the
// specified disk image file, overwriting a previous configuration if it's
// asked to and it finds one
func WriteWorkloadConfigToImage(imageFile *os.File, workloadConfigBytes []byte, overwrite bool) error {
	// Read those last 12 bytes to check if there's a configuration there already, which we should overwrite.
	var overwriteOffset int64
	if overwrite {
		finalTwelve := make([]byte, 12)
		if _, err := imageFile.Seek(12, os.SEEK_END); err != nil {
			return err
		}
		if n, err := imageFile.Read(finalTwelve); err != nil || n != len(finalTwelve) {
			if err != nil {
				return err
			}
			return fmt.Errorf("short read (expected 12 bytes at the end of %q, got %d)", imageFile.Name(), n)
		}
		if magic := string(finalTwelve[0:4]); magic == "KRUN" {
			length := binary.LittleEndian.Uint64(finalTwelve[4:])
			if length < maxWorkloadConfigSize {
				overwrite = true
				overwriteOffset = int64(length + 12)
			}
		}
	}

	// Append the krun configuration to a new buffer.
	var formatted bytes.Buffer
	nWritten, err := formatted.Write(workloadConfigBytes)
	if err != nil {
		return err
	}
	if nWritten != len(workloadConfigBytes) {
		return fmt.Errorf("short write appending configuration to buffer: %d != %d", nWritten, len(workloadConfigBytes))
	}
	// Append the magic string to the buffer.
	krunMagic := "KRUN"
	nWritten, err = formatted.WriteString(krunMagic)
	if err != nil {
		return err
	}
	if nWritten != len(krunMagic) {
		return fmt.Errorf("short write appending krun magic to buffer: %d != %d", nWritten, len(krunMagic))
	}
	// Append the 64-bit little-endian length of the workload configuration to the buffer.
	workloadConfigLengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(workloadConfigLengthBytes, uint64(len(workloadConfigBytes)))
	nWritten, err = formatted.Write(workloadConfigLengthBytes)
	if err != nil {
		return err
	}
	if nWritten != len(workloadConfigLengthBytes) {
		return fmt.Errorf("short write appending configuration length to buffer: %d != %d", nWritten, len(workloadConfigLengthBytes))
	}

	// Write the buffer to the file, either at the very end, or where a
	// configuration that we're overwriting started.
	if _, err = imageFile.Seek(overwriteOffset, os.SEEK_END); err != nil {
		return err
	}
	nWritten, err = imageFile.Write(formatted.Bytes())
	if err != nil {
		return err
	}
	if nWritten != formatted.Len() {
		return fmt.Errorf("short write writing configuration to disk image: %d != %d", nWritten, formatted.Len())
	}
	offset, err := imageFile.Seek(overwriteOffset, os.SEEK_CUR)
	if err != nil {
		return err
	}
	if err = imageFile.Truncate(offset); err != nil {
		return err
	}
	return nil
}

// GenerateMeasurement generates the measurement using the CPU count, memory size, and the firmware shared library, whatever it's called, wherever it is
func GenerateMeasurement(workloadConfig WorkloadConfig) (string, error) {
	cpuString := fmt.Sprintf("%d", workloadConfig.CPUs)
	memoryString := fmt.Sprintf("%d", workloadConfig.Memory)
	var prefix string
	switch workloadConfig.Type {
	case SEV:
		prefix = "SEV-ES"
	case SNP:
		prefix = "SNP"
	default:
		return "", fmt.Errorf("don't know which measurement to use for TEE type %q", workloadConfig.Type)
	}

	sharedLibraryDirs := []string{
		"/usr/local/lib64",
		"/usr/local/lib",
		"/lib64",
		"/lib",
		"/usr/lib64",
		"/usr/lib",
	}
	libkrunfwNames := []string{
		"/usr/lib64/libkrunfw-sev.so.3",
		"/usr/lib64/libkrunfw-sev.so",
		"/usr/lib64/libkrunfw-sev.so.3.11.0",
	}
	for _, sharedLibraryDir := range append(sharedLibraryDirs, strings.Split(os.Getenv("LD_LIBRARY_PATH"), ":")...) {
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
