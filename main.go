// sbomscanner-cli manages OCI artifacts built ad-hoc for sbomscanner.
//
// Commands:
//
//	get   Download KEV and/or EPSS CSVs into ~/.sbomscanner/data/.
//	pack  Bundle both CSVs as an OCI artifact into ~/.sbomscanner/layout/.
//	push  Publish an artifact from the local layout to a remote registry.
//
// Command dispatch is handled declaratively by github.com/urfave/cli/v3.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	getcmd "github.com/sbomscanner/sbomscanner-cli/internal/get"
	packcmd "github.com/sbomscanner/sbomscanner-cli/internal/pack"
	pushcmd "github.com/sbomscanner/sbomscanner-cli/internal/push"
)

// version is stamped via -ldflags "-X main.version=<value>" at build time.
var version = "dev"

func main() {
	// Install a signal-aware context so long-running work (HTTP downloads,
	// OCI copies) responds to Ctrl+C / SIGTERM by cancelling in-flight I/O.
	// Deferred stop() restores default signal handling on clean shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --version / -v (and the `version` subcommand) print the bare version.
	cli.VersionPrinter = func(*cli.Command) { fmt.Println(version) }

	root := &cli.Command{
		Name:    "sbomscanner-cli",
		Usage:   "Manage and distribute sbomscanner OCI artifacts",
		Version: version,
		Commands: []*cli.Command{
			getcmd.Command(),
			packcmd.Command(),
			pushcmd.Command(),
			versionCommand(),
		},
		// Reached only for a bare invocation or an unknown top-level command;
		// both are usage errors (exit 2).
		Action: rootNoCommand,
	}

	// Runtime errors self-exit via cli.Exit inside each command's Action, so
	// any error surfacing here is a flag-parse/usage error — map it to exit 2.
	if err := root.Run(ctx, os.Args); err != nil {
		os.Exit(2)
	}
}

func versionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print version and exit",
		Action: func(context.Context, *cli.Command) error {
			fmt.Println(version)
			return nil
		},
	}
}

func rootNoCommand(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Present() {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd.Args().First())
	}
	_ = cli.ShowAppHelp(cmd)
	return cli.Exit("", 2)
}
