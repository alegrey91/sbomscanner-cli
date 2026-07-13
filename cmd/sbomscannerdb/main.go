package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Runtime errors self-exit via cli.Exit inside each command's Action,
	// so any error surfacing here is a flag/argument-parse or usage error.
	// Print it (when non-empty) and map it to exit 2.
	if err := rootCommand().Run(ctx, os.Args); err != nil {
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return 2
	}
	return 0
}
