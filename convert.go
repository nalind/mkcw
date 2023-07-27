package mkcw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/containers/buildah"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/archive"
	"github.com/nalind/mkcw/pkg/mkcw"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

// TeeConvertImageOptions provides both required and optional bits of
// configuration for TeeConvertImage().
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
	CPUs   int
	Memory int

	// Can be manually set.  If left unset ("", false, nil), reasonable values will be used.
	TeeType                    mkcw.TeeType
	IgnoreChainRetrievalErrors bool
	IgnoreAttestationErrors    bool
	WorkloadID                 string
	DiskEncryptionPassphrase   string
	Slop                       string
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

// TeeConvertImage takes the rootfs and configuration from one image, generates a
// LUKS-encrypted disk image that more or less includes them both, and puts the
// result into a new container image.
// Returns the new image's ID and digest on success, along with a canonical
// reference for it if a repository name was specified.
func TeeConvertImage(ctx context.Context, systemContext *types.SystemContext, store storage.Store, options TeeConvertImageOptions) (string, reference.Canonical, digest.Digest, error) {
	// Apply our defaults if some options aren't set.
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
	defer func() {
		if err := target.Delete(); err != nil {
			logrus.Warnf("deleting target container: %v", err)
		}
	}()
	targetDir, err := target.Mount("")
	if err != nil {
		return "", nil, "", fmt.Errorf("mounting target container: %w", err)
	}
	defer func() {
		if err := target.Unmount(); err != nil {
			logrus.Warnf("unmounting target container: %v", err)
		}
	}()
	if err := os.Mkdir(filepath.Join(targetDir, "tmp"), os.ModeSticky|0o777); err != nil && !errors.Is(err, os.ErrExist) {
		return "", nil, "", fmt.Errorf("creating tmp in target container: %w", err)
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
	defer func() {
		if err := source.Delete(); err != nil {
			logrus.Warnf("deleting source container: %v", err)
		}
	}()
	sourceInfo := buildah.GetBuildInfo(source)
	if err != nil {
		return "", nil, "", fmt.Errorf("retrieving info about source image: %w", err)
	}
	sourceImageID := sourceInfo.FromImageID
	sourceSize, err := store.ImageSize(sourceImageID)
	if err != nil {
		return "", nil, "", fmt.Errorf("computing size of source image: %w", err)
	}
	sourceDir, err := source.Mount("")
	if err != nil {
		return "", nil, "", fmt.Errorf("mounting source container: %w", err)
	}
	defer func() {
		if err := source.Unmount(); err != nil {
			logrus.Warnf("unmounting source container: %v", err)
		}
	}()

	// Generate a workload ID if one wasn't provided.
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

	// Generate the image contents.
	archiveOptions := mkcw.ArchiveOptions{
		AttestationURL:             options.AttestationURL,
		CPUs:                       options.CPUs,
		Memory:                     options.Memory,
		TempDir:                    targetDir,
		TeeType:                    options.TeeType,
		IgnoreChainRetrievalErrors: options.IgnoreChainRetrievalErrors,
		IgnoreAttestationErrors:    options.IgnoreAttestationErrors,
		ImageSize:                  sourceSize,
		WorkloadID:                 workloadID,
		DiskEncryptionPassphrase:   options.DiskEncryptionPassphrase,
		Slop:                       options.Slop,
		Logger:                     logger,
	}
	rc, workloadConfig, err := mkcw.Archive(sourceDir, &source.OCIv1, archiveOptions)
	if err != nil {
		return "", nil, "", fmt.Errorf("generating encrypted image content: %w", err)
	}
	if err = archive.Untar(rc, targetDir, &archive.TarOptions{}); err != nil {
		if err = rc.Close(); err != nil {
			logger.Warnf("cleaning up: %v", err)
		}
		return "", nil, "", fmt.Errorf("saving encrypted image content: %w", err)
	}
	if err = rc.Close(); err != nil {
		return "", nil, "", fmt.Errorf("cleaning up: %w", err)
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
	target.SetCreatedBy(fmt.Sprintf(": convert %q for use with %q", sourceImageID, workloadConfig.Type))
	target.SetDomainname("")
	target.SetEntrypoint([]string{"/entrypoint"})
	target.SetHealthcheck(nil)
	target.SetHostname("")
	target.SetMaintainer("")
	target.SetShell(nil)
	target.SetUser("")
	target.SetWorkDir("")
	commitOptions := buildah.CommitOptions{
		SystemContext: systemContext,
	}
	if options.Tag != "" {
		commitOptions.AdditionalTags = append(commitOptions.AdditionalTags, options.Tag)
	}
	return target.Commit(ctx, options.OutputImage, commitOptions)
}

// TeeRegisterImageOptions provides both required and optional bits of
// configuration for TeeRegisterImage().
type TeeRegisterImageOptions struct {
	// Required parameters.
	Image                    string
	DiskEncryptionPassphrase string

	// Can be manually set.  If left unset (false, nil), reasonable values will be used.
	Logger *logrus.Logger

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
	defer func() {
		if err := source.Delete(); err != nil {
			logrus.Warnf("deleting source container: %v", err)
		}
	}()
	imageDir, err := source.Mount("")
	if err != nil {
		return fmt.Errorf("mounting container: %w", err)
	}
	defer func() {
		if err := source.Unmount(); err != nil {
			logrus.Warnf("unmounting source container: %v", err)
		}
	}()
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
