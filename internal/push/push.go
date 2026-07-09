// Package push implements the `sbomscanner-cli push` command.
//
// Behavior:
//
//   - Accept a destination reference of the form <registry>/<repo>:<tag>.
//   - Authenticate via ~/.docker/config.json (honoring DOCKER_CONFIG).
//     If no config file exists, exit non-zero.
//   - Open ~/.sbomscanner/layout/ and require the source tag to be present.
//     (Default source tag = destination tag; overridable with --source-tag.)
//   - oras.Copy from the local layout to the remote repository.
//
// Flags:
//
//	--skip-tls-verify   disable TLS certificate verification for the registry
//	--source-tag TAG    override the local tag to push (default: dest tag)
//	--plain-http        use HTTP instead of HTTPS (useful for local registries)
package push

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v3"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/sbomscanner/sbomscanner-cli/internal/paths"
)

const userAgent = "sbomscanner-cli"

// Command builds the `push` command.
func Command() *cli.Command {
	return &cli.Command{
		Name:      "push",
		Usage:     "Push a packed artifact from the local layout to a registry",
		ArgsUsage: "<registry>/<repo>:<tag>",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "skip-tls-verify", Usage: "skip TLS certificate verification"},
			&cli.BoolFlag{Name: "plain-http", Usage: "use HTTP instead of HTTPS"},
			&cli.StringFlag{Name: "source-tag", Usage: "local tag to push (default: destination tag)"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Len() != 1 {
				fmt.Fprintln(os.Stderr, "push: exactly one destination reference is required")
				return cli.Exit("", 2)
			}
			if err := run(ctx, cmd.Args().First(), cmd.Bool("skip-tls-verify"), cmd.Bool("plain-http"), cmd.String("source-tag")); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

// run executes `push` against the given destination reference and flags.
func run(ctx context.Context, ref string, skipTLS, plainHTTP bool, sourceTag string) error {
	dstRef, err := registry.ParseReference(ref)
	if err != nil {
		return fmt.Errorf("push: parse reference %q: %w", ref, err)
	}
	if err := dstRef.ValidateReferenceAsTag(); err != nil {
		return fmt.Errorf("push: destination must be a tag reference (not a digest): %w", err)
	}

	srcTag := sourceTag
	if srcTag == "" {
		srcTag = dstRef.Reference
	}

	// Load Docker credentials. The spec requires ~/.docker/config.json (or the
	// DOCKER_CONFIG override) to exist. NewStoreFromDocker returns an error
	// when neither exists — surface it verbatim so the user sees the path.
	if err := requireDockerConfig(); err != nil {
		return err
	}
	credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return fmt.Errorf("push: load docker config: %w", err)
	}

	// Open the local OCI layout and confirm the source tag exists BEFORE we
	// touch the network. This gives a clear error instead of a confusing
	// "reference not found" mid-copy.
	layoutDir, err := paths.LayoutDir()
	if err != nil {
		return err
	}
	if _, statErr := os.Stat(layoutDir); statErr != nil {
		return fmt.Errorf("push: OCI layout %s not found (run `pack` first): %w", layoutDir, statErr)
	}
	srcStore, err := oci.New(layoutDir)
	if err != nil {
		return fmt.Errorf("push: open OCI layout %s: %w", layoutDir, err)
	}
	srcDesc, err := srcStore.Resolve(ctx, srcTag)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return fmt.Errorf("push: tag %q not found in local layout %s (run `pack` first)", srcTag, layoutDir)
		}
		return fmt.Errorf("push: resolve local tag %q: %w", srcTag, err)
	}

	// Build the remote repository client.
	repo, err := remote.NewRepository(dstRef.String())
	if err != nil {
		return fmt.Errorf("push: build remote client: %w", err)
	}
	repo.PlainHTTP = plainHTTP
	repo.Client = buildAuthClient(credStore, skipTLS)

	// oras.Copy resolves srcTag in the source, walks the graph, and pushes
	// missing blobs/manifests to the destination, tagging with dstRef.Reference
	// at the remote end. Progress hooks let us print each blob/manifest as it
	// lands.
	copyOpts := oras.DefaultCopyOptions
	copyOpts.PreCopy = func(ctx context.Context, desc ocispec.Descriptor) error {
		fmt.Fprintf(os.Stderr, "pushing %s %s (%d bytes)\n", desc.MediaType, desc.Digest, desc.Size)
		return nil
	}
	copyOpts.OnCopySkipped = func(ctx context.Context, desc ocispec.Descriptor) error {
		fmt.Fprintf(os.Stderr, "skipped (already present) %s %s\n", desc.MediaType, desc.Digest)
		return nil
	}

	pushedDesc, err := oras.Copy(ctx, srcStore, srcTag, repo, dstRef.Reference, copyOpts)
	if err != nil {
		return fmt.Errorf("push: copy to remote: %w", err)
	}

	fmt.Printf("pushed %s to %s (source tag %q, digest %s)\n",
		srcDesc.Digest, dstRef.String(), srcTag, pushedDesc.Digest)
	return nil
}

// requireDockerConfig checks that a docker config.json file exists at either
// $DOCKER_CONFIG/config.json or ~/.docker/config.json. This is a strict
// pre-flight check demanded by the spec — we don't want the operation to
// proceed anonymously if the file is absent.
func requireDockerConfig() error {
	// Mirror the resolution NewStoreFromDocker does internally.
	if dc := os.Getenv("DOCKER_CONFIG"); dc != "" {
		p := dc + string(os.PathSeparator) + "config.json"
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("push: docker config not found at %s: %w", p, err)
		}
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("push: resolve home directory: %w", err)
	}
	p := home + string(os.PathSeparator) + ".docker" + string(os.PathSeparator) + "config.json"
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("push: docker config not found at %s: %w", p, err)
	}
	return nil
}

// buildAuthClient wires the credentials store into an auth.Client backed by
// a retry-capable transport. TLS verification is toggled by skipTLS.
func buildAuthClient(credStore credentials.Store, skipTLS bool) *auth.Client {
	// Transport: reuse retry.Transport (which wraps http.DefaultTransport) so
	// we inherit the sensible retry/backoff defaults. When skipTLS is set we
	// build our own base transport with InsecureSkipVerify.
	var baseTransport http.RoundTripper = http.DefaultTransport
	if skipTLS {
		baseTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in by --skip-tls-verify
		}
	}

	httpClient := &http.Client{
		Transport: retry.NewTransport(baseTransport),
	}
	client := &auth.Client{
		Client:     httpClient,
		Credential: credentials.Credential(credStore),
	}
	client.SetUserAgent(userAgent)
	return client
}
