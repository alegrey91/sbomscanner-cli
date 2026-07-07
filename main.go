// sbomscanner-cli manages OCI artifacts built ad-hoc for sbomscanner.
//
// Commands:
//
//	get   Download KEV and/or EPSS CSVs into ~/.sbomscanner/data/.
//	pack  Bundle both CSVs as an OCI artifact into ~/.sbomscanner/layout/.
//	push  Publish an artifact from the local layout to a remote registry.
//
// This uses stdlib flag + a small manual dispatch instead of cobra.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	getcmd "github.com/sbomscanner/sbomscanner-cli/internal/get"
	packcmd "github.com/sbomscanner/sbomscanner-cli/internal/pack"
	pushcmd "github.com/sbomscanner/sbomscanner-cli/internal/push"
)

// version is stamped via -ldflags "-X main.version=<value>" at build time.
var version = "dev"

func usage(w io.Writer) {
	fmt.Fprintf(w, `sbomscanner-cli %s

Usage: sbomscanner-cli <command> [args...]

Commands:
  get     Download KEV/EPSS data files
  pack    Pack the data files into an OCI artifact (local layout)
  push    Push a packed artifact from the local layout to a remote registry

  version Print version and exit
  help    Print this help

Run 'sbomscanner-cli <command> -h' for command-specific help.
`, version)
}

// exit codes:
//
//	0 -- success
//	1 -- runtime error
//	2 -- usage error (matches flag.ExitOnError convention)
const (
	exitOK      = 0
	exitErr     = 1
	exitUsage   = 2
)

func main() {
	// Install a signal-aware context so long-running work (HTTP downloads,
	// OCI copies) responds to Ctrl+C / SIGTERM by cancelling in-flight I/O.
	// Deferred stop() restores default signal handling on clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := dispatch(ctx, os.Args[1:])
	os.Exit(code)
}

// dispatch is main() minus os.Exit, so it's easier to reason about. It never
// panics — errors funnel through the exit-code map.
func dispatch(ctx context.Context, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsage
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "get":
		return run(getcmd.Run(ctx, rest))
	case "pack":
		return run(packcmd.Run(ctx, rest))
	case "push":
		return run(pushcmd.Run(ctx, rest))
	case "version", "--version", "-v":
		fmt.Println(version)
		return exitOK
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage(os.Stderr)
		return exitUsage
	}
}

// run maps a subcommand error to an exit code. Any of the *cmd.ErrUsage
// sentinels is treated as a usage error (exit 2); everything else is exit 1.
func run(err error) int {
	if err == nil {
		return exitOK
	}
	if isUsageErr(err) {
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return exitErr
}

func isUsageErr(err error) bool {
	// Each subcommand package exports its own ErrUsage. Checking all three
	// avoids leaking a "usage" package that would only exist to be imported
	// in one place.
	return errors.Is(err, getcmd.ErrUsage) ||
		errors.Is(err, packcmd.ErrUsage) ||
		errors.Is(err, pushcmd.ErrUsage)
}
