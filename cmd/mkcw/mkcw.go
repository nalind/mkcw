package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/reexec"
	"github.com/containers/storage/pkg/unshare"
	"github.com/nalind/mkcw"
	mkcwtypes "github.com/nalind/mkcw/pkg/mkcw/types"
	"github.com/sirupsen/logrus"
)

func main() {
	if reexec.Init() {
		return
	}

	var options mkcw.TeeConvertImageOptions
	var logLevel, teeType string
	var help bool
	flag.StringVar(&logLevel, "log-level", "error", "logging level")
	flag.BoolVar(&help, "help", false, "print usage information")
	flag.StringVar(&teeType, "type", "sev", "type of trusted execution environment")
	flag.StringVar(&options.AttestationURL, "attestation-url", "", "location of attestation server")
	flag.IntVar(&options.CPUs, "cpu", 0, "number of expected virtual CPUs")
	flag.IntVar(&options.Memory, "memory", 0, "amount of memory expected (MB)")
	flag.StringVar(&options.WorkloadID, "workload-id", "", "workload ID (default: automatic)")
	flag.StringVar(&options.DiskEncryptionPassphrase, "passphrase", "", "encryption passphrase (default: automatic)")
	flag.StringVar(&options.BaseImage, "base-image", "", "alternate base image for final image")
	flag.StringVar(&options.MountLabel, "mount-label", "", "force SELinux mount label")
	flag.StringVar(&options.Slop, "slop", "", "extra space to add to the image size")
	flag.BoolVar(&options.IgnoreChainRetrievalErrors, "ignore-sevctl-errors", false, "ignore errors reading SEV certificate chain")
	flag.BoolVar(&options.IgnoreAttestationErrors, "ignore-attestation-errors", false, "ignore errors registering workload")
	flag.Parse()
	if help {
		flag.Usage()
		return
	}
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Fatalf("parsing log level %q: %v", logLevel, err)
	}
	logrus.SetLevel(level)
	flag.Usage = func() {
		fmt.Println("Usage: mkcw [options] imagename imagename")
		flag.PrintDefaults()
	}

	ctx := context.TODO()
	systemContext := &types.SystemContext{}
	if len(flag.Args()) < 1 {
		logrus.Error("no input image name specified")
		flag.Usage()
		return
	}
	if len(flag.Args()) < 2 {
		logrus.Error("no output image name specified")
		flag.Usage()
		return
	}
	if len(flag.Args()) > 2 {
		logrus.Error("unused arguments specified")
		flag.Usage()
		return
	}

	inputName := flag.Arg(0)
	outputName := flag.Arg(1)
	outputRef, err := alltransports.ParseImageName(outputName)
	if err == nil {
		outputName = ""
	} else {
		outputRef = nil
	}

	unshare.MaybeReexecUsingUserNamespace(true)

	storeOptions, err := storage.DefaultStoreOptionsAutoDetectUID()
	if err != nil {
		logrus.Fatalf("%v", err)
	}

	store, err := storage.GetStore(storeOptions)
	if err != nil {
		logrus.Fatalf("%v", err)
	}

	options.TeeType = mkcwtypes.TeeType(teeType)
	options.InputImage = inputName
	options.OutputImage = outputRef
	options.Tag = outputName
	options.ReportWriter = os.Stdout
	imageID, _, _, err := mkcw.TeeConvertImage(ctx, systemContext, store, options)
	if err != nil {
		logrus.Fatalf("%v", err)
	}
	fmt.Println(imageID)
}
