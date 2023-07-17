package mkcw

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/containers/buildah"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/ioutils"
	"github.com/nalind/lukstool"
	"github.com/nalind/mkcw/pkg/mkcw"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

type TeeConvertImageOptions struct {
	// Required parameters.
	InputImage string

	// If supplied, we'll tag the resulting image with the specified name.
	Tag         string
	OutputImage types.ImageReference

	// If supplied, we'll register the workload with this server.
	// Practically necessary if DiskEncryptionPassphrase is not set, in
	// which case we'll generate one and throw it away after.
	AttestationURL string

	// Used to measure the environment.  If left unset (0, ""), defaults will be applied.
	CPUs       int
	Memory     int
	Filesystem string

	// Can be manually set.  If left unset ("", false, nil), reasonable values will be used.
	TeeType                    mkcw.TeeType
	IgnoreChainRetrievalErrors bool
	IgnoreAttestationErrors    bool
	WorkloadID                 string
	DiskEncryptionPassphrase   string
	BaseImage                  string
	Logger                     *logrus.Logger

	// Passed through to buildah.BuilderOptions. Most settings won't make
	// sense to be made available here because we don't launch a process.
	ContainerSuffix     string
	PullPolicy          buildah.PullPolicy
	BlobDirectory       string
	SignaturePolicyPath string
	ReportWriter        io.Writer
	IDMappingOptions    *buildah.IDMappingOptions
	Format              string
	MaxPullRetries      int
	PullRetryDelay      time.Duration
	OciDecryptConfig    *encconfig.DecryptConfig
	MountLabel          string
}

const (
	teeCertificateChainFilename = "sev.chain"
	teeDefaultCPUs              = 2
	teeDefaultMemory            = 512
	teeDefaultFilesystem        = "ext4"
)

// TeeConvertImage takes the rootfs and configuration from one image, generates a
// LUKS-encrypted disk image that more or less includes them both, and puts the
// result into a new container image.
// Returns the new image's ID and digest on success, along with a canonical
// reference for it if a repository name was specified.
func TeeConvertImage(ctx context.Context, systemContext *types.SystemContext, store storage.Store, options TeeConvertImageOptions) (string, reference.Canonical, digest.Digest, error) {
	// Apply our defaults if some options aren't set.
	attestationURL := options.AttestationURL
	nCPUs := options.CPUs
	if nCPUs == 0 {
		nCPUs = teeDefaultCPUs
	}
	memory := options.Memory
	if memory < teeDefaultMemory {
		memory = teeDefaultMemory
	}
	filesystem := options.Filesystem
	if filesystem == "" {
		filesystem = teeDefaultFilesystem
	}
	logger := options.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	teeType := options.TeeType
	if teeType == "" {
		teeType = mkcw.SEV
	}

	// Now create the target working container, pulling the base image if
	// there is one and it isn't present.
	builderOptions := buildah.BuilderOptions{
		FromImage:     options.BaseImage,
		SystemContext: systemContext,
		Logger:        logger,

		ContainerSuffix:     options.ContainerSuffix,
		PullPolicy:          options.PullPolicy,
		BlobDirectory:       options.BlobDirectory,
		SignaturePolicyPath: options.SignaturePolicyPath,
		ReportWriter:        options.ReportWriter,
		IDMappingOptions:    options.IDMappingOptions,
		Format:              options.Format,
		MaxPullRetries:      options.MaxPullRetries,
		PullRetryDelay:      options.PullRetryDelay,
		OciDecryptConfig:    options.OciDecryptConfig,
		MountLabel:          options.MountLabel,
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
	vendorChain := "/" + teeCertificateChainFilename
	cmd := exec.Command("sevctl", "export", "-f", filepath.Join(targetDir, teeCertificateChainFilename))
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

		ContainerSuffix:     options.ContainerSuffix,
		PullPolicy:          options.PullPolicy,
		BlobDirectory:       options.BlobDirectory,
		SignaturePolicyPath: options.SignaturePolicyPath,
		ReportWriter:        options.ReportWriter,
		IDMappingOptions:    options.IDMappingOptions,
		Format:              options.Format,
		MaxPullRetries:      options.MaxPullRetries,
		PullRetryDelay:      options.PullRetryDelay,
		OciDecryptConfig:    options.OciDecryptConfig,
		MountLabel:          options.MountLabel,
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
	_, stderrString, err := mkcw.MakeFS(sourceDir, plain, filesystem)
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
		diskEncryptionPassphrase, err = mkcw.GenerateDiskEncryptionPassphrase()
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
	var teeDataBytes []byte
	switch teeType {
	case mkcw.SEV, mkcw.SNP:
		teeData := mkcw.SevWorkloadData{
			VendorChain:             vendorChain,
			AttestationServerPubkey: "",
		}
		teeDataBytes, err = json.Marshal(teeData)
		if err != nil {
			return "", nil, "", err
		}
	default:
		return "", nil, "", fmt.Errorf("don't know how to generate tee_data for %q TEEs", teeType)
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
	workloadConfig := mkcw.WorkloadConfig{
		Type:           teeType,
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
	if err = ioutils.AtomicWriteFile(filepath.Join(targetDir, "krun-sev.json"), workloadConfigBytes, 0o600); err != nil {
		return "", nil, "", err
	}

	// Append the krun configuration to the disk image.
	if err = mkcw.WriteWorkloadConfigToImage(encryptedFile, workloadConfigBytes, false); err != nil {
		return "", nil, "", err
	}
	if err = encryptedFile.Sync(); err != nil {
		return "", nil, "", err
	}

	// Register the workload.
	if attestationURL != "" {
		err = mkcw.SendRegistrationRequest(workloadConfig, diskEncryptionPassphrase, options.IgnoreAttestationErrors, logger)
		if err != nil {
			return "", nil, "", err
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
	target.SetCreatedBy(fmt.Sprintf(": convert for use with %q", teeType))
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
		AdditionalTags: []string{options.Tag},
	}
	return target.Commit(ctx, options.OutputImage, commitOptions)
}

type TeeRegisterImageOptions struct {
	// Required parameters.
	Image                    string
	DiskEncryptionPassphrase string

	// Can be manually set.  If left unset ( false, nil), reasonable values will be used.
	IgnoreChainRetrievalErrors bool
	Logger                     *logrus.Logger

	// Passed through to buildah.BuilderOptions. Most settings won't make
	// sense to be made available here because we don't launch a processes.
	ContainerSuffix     string
	PullPolicy          buildah.PullPolicy
	BlobDirectory       string
	SignaturePolicyPath string
	ReportWriter        io.Writer
	IDMappingOptions    *buildah.IDMappingOptions
	Format              string
	MaxPullRetries      int
	PullRetryDelay      time.Duration
	OciDecryptConfig    *encconfig.DecryptConfig
	MountLabel          string
}

// TeeRegisterImage reads the workload ID and attestation URL from an image,
// verifies that the passed-in passphrase can be used to decrypt the image, and
// submits a fresh registration request to the attestation server.  This isn't
// expected to used often, but if a conversion fails at this step, and the
// error is treated as a warning, it will be necessary.
func TeeRegisterImage(ctx context.Context, systemContext *types.SystemContext, store storage.Store, options TeeRegisterImageOptions) error {
	if options.DiskEncryptionPassphrase == "" {
		return errors.New("decryption passphrase not provided")
	}
	logger := options.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	builderOptions := buildah.BuilderOptions{
		FromImage:     options.Image,
		SystemContext: systemContext,
		Logger:        logger,

		ContainerSuffix:     options.ContainerSuffix,
		PullPolicy:          options.PullPolicy,
		BlobDirectory:       options.BlobDirectory,
		SignaturePolicyPath: options.SignaturePolicyPath,
		ReportWriter:        options.ReportWriter,
		IDMappingOptions:    options.IDMappingOptions,
		Format:              options.Format,
		MaxPullRetries:      options.MaxPullRetries,
		PullRetryDelay:      options.PullRetryDelay,
		OciDecryptConfig:    options.OciDecryptConfig,
		MountLabel:          options.MountLabel,
	}
	source, err := buildah.NewBuilder(ctx, store, builderOptions)
	if err != nil {
		return fmt.Errorf("creating container from image: %w", err)
	}
	defer source.Delete()
	imageDir, err := source.Mount("")
	if err != nil {
		return fmt.Errorf("mounting container: %w", err)
	}
	imageFile := filepath.Join(imageDir, "disk.img")
	workloadConfig, err := mkcw.ReadWorkloadConfigFromImage(imageFile)
	if err != nil {
		return err
	}
	if err = mkcw.CheckLUKSPassphrase(imageFile, options.DiskEncryptionPassphrase); err != nil {
		return err
	}
	if err = mkcw.SendRegistrationRequest(workloadConfig, options.DiskEncryptionPassphrase, false, logger); err != nil {
		return err
	}
	return nil
}
