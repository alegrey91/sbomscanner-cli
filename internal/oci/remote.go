package oci

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	orasremote "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const userAgent = "sbomscannerdb"

// Config controls how a Remote contacts registries.
type Config struct {
	// SkipTLSVerify disables TLS certificate verification.
	SkipTLSVerify bool
	// PlainHTTP uses HTTP instead of HTTPS.
	PlainHTTP bool
}

// Remote performs push and pull operations against OCI registries.
type Remote struct {
	config Config
	logger *slog.Logger
}

// NewRemote returns a Remote using the given configuration.
func NewRemote(config Config, logger *slog.Logger) *Remote {
	return &Remote{config: config, logger: logger}
}

// Push publishes the artifact tagged as ref in the given store
// to the remote registry identified by the same reference.
func (remote *Remote) Push(ctx context.Context, store *Store, ref string) (Artifact, error) {
	dstRef, err := parseTagReference(ref)
	if err != nil {
		return Artifact{}, err
	}

	layout, err := store.open()
	if err != nil {
		return Artifact{}, err
	}
	if _, err := layout.Resolve(ctx, ref); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return Artifact{}, fmt.Errorf("%s not found in local store (run `build` first)", ref)
		}
		return Artifact{}, fmt.Errorf("resolve %s in local store: %w", ref, err)
	}

	repo, err := remote.newRepository(dstRef)
	if err != nil {
		return Artifact{}, err
	}

	// oras.Copy resolves the tag in the source, walks the graph,
	// and pushes missing blobs/manifests to the destination.
	// Progress hooks log each blob/manifest as it lands.
	copyOpts := oras.DefaultCopyOptions
	copyOpts.PreCopy = func(_ context.Context, desc ocispec.Descriptor) error {
		remote.logger.InfoContext(ctx, "pushing blob", "mediaType", desc.MediaType, "digest", desc.Digest, "bytes", desc.Size)
		return nil
	}
	copyOpts.OnCopySkipped = func(_ context.Context, desc ocispec.Descriptor) error {
		remote.logger.DebugContext(ctx, "skipped blob, already present", "mediaType", desc.MediaType, "digest", desc.Digest)
		return nil
	}

	pushedDesc, err := oras.Copy(ctx, layout, ref, repo, dstRef.Reference, copyOpts)
	if err != nil {
		return Artifact{}, fmt.Errorf("copy to remote: %w", err)
	}
	remote.logger.InfoContext(ctx, "pushed artifact", "ref", dstRef.String(), "digest", pushedDesc.Digest)

	return Artifact{
		Ref:    ref,
		Digest: pushedDesc.Digest.String(),
		Size:   pushedDesc.Size,
	}, nil
}

// Pull fetches the DB artifact at the given tag reference
// and writes its tar.gz layer to outDir/BundleFileName.
// It returns the written file path.
func (remote *Remote) Pull(ctx context.Context, ref, outDir string) (string, error) {
	srcRef, err := parseTagReference(ref)
	if err != nil {
		return "", err
	}

	repo, err := remote.newRepository(srcRef)
	if err != nil {
		return "", err
	}

	layerDesc, err := remote.resolveBundleLayer(ctx, repo, srcRef.Reference)
	if err != nil {
		return "", err
	}
	remote.logger.InfoContext(ctx, "pulling bundle layer", "ref", srcRef.String(), "digest", layerDesc.Digest, "bytes", layerDesc.Size)

	dst := filepath.Join(outDir, BundleFileName)
	if err := fetchBlobToFile(ctx, repo, layerDesc, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// resolveBundleLayer fetches the manifest at tag
// and returns the descriptor of the DB bundle layer, located by media type.
func (remote *Remote) resolveBundleLayer(ctx context.Context, repo *orasremote.Repository, tag string) (ocispec.Descriptor, error) {
	manifestDesc, manifestBytes, err := oras.FetchBytes(ctx, repo, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetch manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse manifest %s: %w", manifestDesc.Digest, err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType == LayerMediaType {
			return layer, nil
		}
	}
	return ocispec.Descriptor{}, fmt.Errorf("no layer with media type %s in manifest %s", LayerMediaType, manifestDesc.Digest)
}

// newRepository builds an authenticated remote repository client for ref.
func (remote *Remote) newRepository(ref registry.Reference) (*orasremote.Repository, error) {
	if err := requireDockerConfig(); err != nil {
		return nil, err
	}
	credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("load docker config: %w", err)
	}

	repo, err := orasremote.NewRepository(ref.String())
	if err != nil {
		return nil, fmt.Errorf("build remote client: %w", err)
	}
	repo.PlainHTTP = remote.config.PlainHTTP
	repo.Client = buildAuthClient(credStore, remote.config.SkipTLSVerify)
	return repo, nil
}

// fetchBlobToFile streams the blob described by desc into dst.
func fetchBlobToFile(ctx context.Context, repo *orasremote.Repository, desc ocispec.Descriptor, dst string) error {
	readCloser, err := repo.Blobs().Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetch blob %s: %w", desc.Digest, err)
	}
	defer readCloser.Close()

	outFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer outFile.Close()

	if _, err := io.CopyN(outFile, readCloser, desc.Size); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}

// parseTagReference parses ref and requires it to be a tag (not digest) reference.
func parseTagReference(ref string) (registry.Reference, error) {
	parsed, err := registry.ParseReference(ref)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	if err := parsed.ValidateReferenceAsTag(); err != nil {
		return registry.Reference{}, fmt.Errorf("reference must be a tag (not a digest): %w", err)
	}
	return parsed, nil
}

// requireDockerConfig checks that a docker config.json exists
// at either $DOCKER_CONFIG/config.json or ~/.docker/config.json.
// We don't want the operation to proceed anonymously if the file is absent.
func requireDockerConfig() error {
	// Mirror the resolution NewStoreFromDocker does internally.
	if dc := os.Getenv("DOCKER_CONFIG"); dc != "" {
		p := filepath.Clean(filepath.Join(dc, "config.json"))
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("docker config not found at %s: %w", p, err)
		}
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}
	p := filepath.Join(home, ".docker", "config.json")
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("docker config not found at %s: %w", p, err)
	}
	return nil
}

// buildAuthClient wires the credentials store
// into an auth.Client backed by a retry-capable transport.
// TLS verification is toggled by skipTLS.
func buildAuthClient(credStore credentials.Store, skipTLS bool) *auth.Client {
	// Transport: reuse retry.Transport (which wraps http.DefaultTransport)
	// so that we inherit the sensible retry/backoff defaults.
	// When skipTLS is set we build our own base transport with InsecureSkipVerify.
	baseTransport := http.DefaultTransport
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

	client := &auth.Client{
		Client:     &http.Client{Transport: retry.NewTransport(baseTransport)},
		Credential: credentials.Credential(credStore),
	}
	client.SetUserAgent(userAgent)
	return client
}
