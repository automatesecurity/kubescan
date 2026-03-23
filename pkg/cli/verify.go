package cli

import (
	"flag"
	"fmt"
	"io"

	"kubescan/internal/bundle"
)

func RunVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: kubescan verify bundle --bundle <file> --key <public-key>")
		return 2
	}

	switch args[0] {
	case "bundle":
		return runVerifyBundle(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown verify target %q\n", args[0])
		return 2
	}
}

func runVerifyBundle(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)

	bundlePath := fs.String("bundle", "", "path to a signed bundle")
	keyPath := fs.String("key", "", "path to an Ed25519 public key")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *bundlePath == "" || *keyPath == "" {
		fmt.Fprintln(stderr, "--bundle and --key are required")
		return 2
	}

	signedBundle, err := bundle.LoadSignedBundle(*bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "load bundle: %v\n", err)
		return 1
	}
	if err := bundle.VerifyBundle(signedBundle, *keyPath); err != nil {
		fmt.Fprintf(stderr, "verify bundle: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "bundle verified: type=%s algorithm=%s\n", signedBundle.Metadata.Type, signedBundle.Metadata.Algorithm)
	return 0
}
