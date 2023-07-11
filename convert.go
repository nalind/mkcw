package mkcw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/containers/buildah"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/ioutils"
	"github.com/nalind/lukstool"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

type ConvertImageOptions struct {
	// Required parameters.
	InputImage string

	// If supplied, we'll tag the resulting image with the specified name.
	Tag         string
	OutputImage types.ImageReference

	// If supplied, we'll register the workload with this server.
	// Practically necessary if DiskEncryptionPassphrase is not set, in
	// which case we'll generate one and throw it away after.
	AttestationURL string

	// Used to measure the environment.  If left unset (0), defaults will be applied.
	CPUs       int
	Memory     int
	Filesystem string

	// Can be manually set.  If left unset (""), reasonable values will be used.
	IgnoreChainRetrievalErrors bool
	IgnoreAttestationErrors    bool
	WorkloadID                 string
	DiskEncryptionPassphrase   string
	BaseImage                  string
	Logger                     *logrus.Logger
}

const (
	certificateChainFilename = "sev.chain"
	defaultCPUs              = 2
	defaultMemory            = 512
	defaultFilesystem        = "ext4"
)

// ConvertImage takes the rootfs and configuration from one image, generates a
// LUKS-encrypted disk image that more or less includes them both, and puts the
// result into a new container image.
// Returns the new image's ID and digest on success, along with a canonical
// reference for it if a repository name was specified.
func ConvertImage(ctx context.Context, systemContext *types.SystemContext, store storage.Store, options ConvertImageOptions) (string, reference.Canonical, digest.Digest, error) {
	// Apply our defaults if some options aren't set.
	attestationURL := options.AttestationURL
	nCPUs := options.CPUs
	if nCPUs == 0 {
		nCPUs = defaultCPUs
	}
	memory := options.Memory
	if memory < defaultMemory {
		memory = defaultMemory
	}
	filesystem := options.Filesystem
	if filesystem == "" {
		filesystem = defaultFilesystem
	}
	logger := options.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}

	// Now create the target working container, pulling the base image if
	// there is one and it isn't present.
	builderOptions := buildah.BuilderOptions{
		FromImage:     options.BaseImage,
		SystemContext: systemContext,
		Logger:        logger,
	}
	target, err := buildah.NewBuilder(ctx, store, builderOptions)
	if err != nil {
		return "", nil, "", fmt.Errorf("creating container from target image: %w", err)
	}
	defer target.Delete()
	targetDir, err := target.Mount("")
	if err != nil {
		return "", nil, "", fmt.Errorf("mounting target container: %w", err)
	}
	if err := os.Mkdir(filepath.Join(targetDir, "tmp"), os.ModeSticky|0o777); err != nil && !errors.Is(err, os.ErrExist) {
		return "", nil, "", fmt.Errorf("creating tmp in target container: %w", err)
	}

	// Copy the entrypoint in.
	if entrypoint, err := os.Open("entrypoint"); err == nil {
		if targetEntrypoint, err := os.OpenFile(filepath.Join(targetDir, "entrypoint"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700); err == nil {
			io.Copy(targetEntrypoint, entrypoint)
			targetEntrypoint.Close()
		}
		entrypoint.Close()
	}

	// Save the certificates for the container image's root dir.
	vendorChain := "/" + certificateChainFilename
	cmd := exec.Command("sevctl", "export", "-f", filepath.Join(targetDir, certificateChainFilename))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		vendorChain = ""
		if !options.IgnoreChainRetrievalErrors {
			return "", nil, "", fmt.Errorf("retrieving SEV certificate chain: %v: %w", strings.TrimSpace(stderr.String()), err)
		}
		if stderr.Len() != 0 {
			logger.Warnf("sevctl: %s: %v", strings.TrimSpace(stderr.String()), err)
		} else {
			logger.Warnf("sevctl: %v", err)
		}
	}

	// Mount the source image, pulling it first if necessary.
	builderOptions = buildah.BuilderOptions{
		FromImage:     options.InputImage,
		SystemContext: systemContext,
		Logger:        logger,
	}
	source, err := buildah.NewBuilder(ctx, store, builderOptions)
	if err != nil {
		return "", nil, "", fmt.Errorf("creating container from source image: %w", err)
	}
	defer source.Delete()
	sourceInfo := buildah.GetBuildInfo(source)
	if err != nil {
		return "", nil, "", fmt.Errorf("retrieving info about source image: %w", err)
	}
	sourceImageID := sourceInfo.FromImageID
	sourceSize, err := store.ImageSize(source.FromImageID)
	if err != nil {
		return "", nil, "", fmt.Errorf("computing size of source image: %w", err)
	}
	if sourceSize < 0 {
		sourceSize = 1024 * 1024 * 1024 // wild guess, but probably better than nothing
	}
	sourceDir, err := source.Mount("")
	if err != nil {
		return "", nil, "", fmt.Errorf("mounting source container: %w", err)
	}

	// Write part of the config blob where the krun init process will be looking for it.
	// The oci2cw tool used `buildah inspect` output, but init is just looking for
	// fields that have the right names in any object, and the image config will
	// have that, so let's try encoding it directly.
	var imageConfigBytes []byte
	if imageConfigBytes, err = json.Marshal(sourceInfo.OCIv1.Config); err != nil {
		return "", nil, "", err
	}
	if err = ioutils.AtomicWriteFile(filepath.Join(sourceDir, ".krun_config.json"), imageConfigBytes, 0o600); err != nil {
		return "", nil, "", err
	}

	// Create a blank disk image that we hope will be big enough.
	plain := filepath.Join(targetDir, "plain.img")
	plainFile, err := os.Create(plain)
	if err != nil {
		return "", nil, "", err
	}
	size := sourceSize * 5 / 4
	if size%4096 != 0 {
		size += 4096 - (size % 4096)
	}
	err = plainFile.Truncate(size)
	plainFile.Close()
	if err != nil {
		return "", nil, "", err
	}

	// Format the blank image and populate it with the rootfs's content.
	logger.Log(logrus.DebugLevel, "generating plaintext disk image")
	_, stderrString, err := makeFS(sourceDir, plain, filesystem)
	if err != nil {
		return "", nil, "", fmt.Errorf("%s: %w", stderrString, err)
	}
	plainFile, err = os.Open(plain)
	if err != nil {
		return "", nil, "", err
	}
	defer func() {
		if plainFile != nil {
			plainFile.Close()
		}
	}()

	// Choose an encryption passphrase if we weren't supplied with one.
	diskEncryptionPassphrase := options.DiskEncryptionPassphrase
	if diskEncryptionPassphrase == "" {
		logger.Log(logrus.DebugLevel, "generating encryption passpharase")
		diskEncryptionPassphrase, err = generateDiskEncryptionPassphrase()
		if err != nil {
			return "", nil, "", err
		}
	}

	// Encrypt the disk image for inclusion in the container image.
	encrypted := filepath.Join(targetDir, "disk.img")
	encryptedFile, err := os.Create(encrypted)
	if err != nil {
		return "", nil, "", err
	}
	logger.Log(logrus.DebugLevel, "encrypting disk image")
	header, encrypt, blockSize, err := lukstool.EncryptV1([]string{diskEncryptionPassphrase}, "")
	defer encryptedFile.Close()
	n, err := encryptedFile.Write(header)
	if err != nil {
		return "", nil, "", err
	}
	if n != len(header) {
		return "", nil, "", fmt.Errorf("wrote %d bytes of header intead of %d bytes", n, len(header))
	}
	wrapper := lukstool.EncryptWriter(encrypt, encryptedFile, blockSize)
	_, err = io.Copy(wrapper, plainFile)
	if err != nil {
		return "", nil, "", err
	}
	err = wrapper.Close()
	if err != nil {
		return "", nil, "", err
	}
	plainFile.Close()
	plainFile = nil
	if err := os.Remove(plain); err != nil {
		return "", nil, "", err
	}

	// Build the krun configuration file that we store in the container image and on the disk image.
	logger.Log(logrus.DebugLevel, "generating workload configuration")
	teeData := SEVWorkloadData{
		VendorChain:             vendorChain,
		AttestationServerPubkey: "",
	}
	teeDataBytes, err := json.Marshal(teeData)
	if err != nil {
		return "", nil, "", err
	}
	workloadID := options.WorkloadID
	if workloadID == "" {
		rawImageID, err := hex.DecodeString(sourceImageID)
		if err != nil {
			rawImageID = []byte(sourceImageID)
		}
		// add some randomness so that the attestation server can tell
		// the difference between multiple images based on the same
		// source image
		randomizedBytes := make([]byte, 32)
		if _, err := rand.Read(randomizedBytes); err != nil {
			return "", nil, "", err
		}
		workloadID = digest.Canonical.FromBytes(append(append([]byte{}, rawImageID...), randomizedBytes...)).Encoded()
	}
	workloadConfig := WorkloadConfig{
		Type:           SEV,
		WorkloadID:     workloadID,
		CPUs:           nCPUs,
		Memory:         memory,
		AttestationURL: attestationURL,
		TeeData:        string(teeDataBytes),
	}
	workloadConfigBytes, err := json.Marshal(workloadConfig)
	if err != nil {
		return "", nil, "", err
	}
	// Store the krun configuration in the container image.
	if err = ioutils.AtomicWriteFile(filepath.Join(targetDir, ".krun-sev.json"), workloadConfigBytes, 0o600); err != nil {
		return "", nil, "", err
	}

	// Append the krun configuration to the disk image.
	nWritten, err := encryptedFile.Write(teeDataBytes)
	if err != nil {
		return "", nil, "", err
	}
	if nWritten != len(teeDataBytes) {
		return "", nil, "", fmt.Errorf("short write appending configuration to disk image: %d != %d", nWritten, len(teeDataBytes))
	}
	// Append the magic string to the disk image.
	krunMagic := "KRUN"
	nWritten, err = encryptedFile.Write([]byte(krunMagic))
	if err != nil {
		return "", nil, "", err
	}
	if nWritten != len(krunMagic) {
		return "", nil, "", fmt.Errorf("short write appending krun magic to disk image: %d != %d", nWritten, len(krunMagic))
	}
	// Append the 64-bit little-endian length of the krun configuration to the disk image.
	teeDataLengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(teeDataLengthBytes, uint64(len(teeDataBytes)))
	nWritten, err = encryptedFile.Write(teeDataLengthBytes)
	if err != nil {
		return "", nil, "", err
	}
	if nWritten != len(teeDataLengthBytes) {
		return "", nil, "", fmt.Errorf("short write appending configuration length to disk image: %d != %d", nWritten, len(teeDataLengthBytes))
	}

	// Measure the execution environment.
	measurement, err := generateMeasurement(workloadConfig)
	if err != nil {
		return "", nil, "", err
	}

	// Build the workload registration (attestation) request body.
	teeConfig := TeeConfig{
		Flags: TeeConfigFlags{
			Bits: 63,
		},
		MinFW: TeeConfigMinFW{
			Major: 0,
			Minor: 0,
		},
	}
	teeConfigBytes, err := json.Marshal(teeConfig)
	if err != nil {
		return "", nil, "", err
	}
	attestationRequest := AttestationRequest{
		WorkloadID:        workloadConfig.WorkloadID,
		LaunchMeasurement: measurement,
		TeeConfig:         string(teeConfigBytes),
		Passphrase:        diskEncryptionPassphrase,
	}
	attestationRequestBytes, err := json.Marshal(attestationRequest)
	if err != nil {
		return "", nil, "", err
	}

	// Register the workload.
	if attestationURL != "" {
		url := path.Join(attestationURL, "/kbs/v0/register_workload")
		requestContentType := "application/json"
		requestBody := bytes.NewReader(attestationRequestBytes)
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
			if !options.IgnoreAttestationErrors {
				return "", nil, "", err
			}
			logger.Warnf("while registering workload: %v", err)
		}
	}

	// Commit the image.
	logger.Log(logrus.DebugLevel, "committing disk image")
	target.ClearAnnotations()
	target.ClearEnv()
	target.ClearLabels()
	target.ClearOnBuild()
	target.ClearPorts()
	target.ClearVolumes()
	target.SetCmd(nil)
	target.SetComment("")
	target.SetDomainname("")
	target.SetEntrypoint([]string{"/entrypoint"})
	target.SetHealthcheck(nil)
	target.SetHostname("")
	target.SetMaintainer("")
	target.SetShell(nil)
	target.SetUser("")
	target.SetWorkDir("")
	commitOptions := buildah.CommitOptions{
		SystemContext:  systemContext,
		OmitHistory:    true,
		AdditionalTags: []string{options.Tag},
	}
	return target.Commit(ctx, options.OutputImage, commitOptions)

}

// generate a random disk encryption password
func generateDiskEncryptionPassphrase() (string, error) {
	randomizedBytes := make([]byte, 32)
	if _, err := rand.Read(randomizedBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomizedBytes), nil
}

// generate the measurement using the CPU count, memory size, and the firmware shared library, whatever it's called, wherever it is
func generateMeasurement(workloadConfig WorkloadConfig) (string, error) {
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
						err = fmt.Errorf("%s: %w", stderr.String(), err)
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
