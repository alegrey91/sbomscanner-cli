// Package pack implements the `sbomscanner-cli pack` command.
//
// Behavior:
//
//  1. Read ~/.sbomscanner/data/ and require both KEV and EPSS to be present.
//     Any other file in that directory is ignored.
//  2. Build two layers in fixed order (KEV first, EPSS second) using the
//     configured artifactType-per-layer.
//  3. Build an OCI 1.1 manifest with an empty config blob and the DB
//     artifactType.
//  4. Push blobs + manifest into the local OCI layout at ~/.sbomscanner/layout/
//     and tag it as both `sbomscanner-db_<12-hex content hash>` and `latest`.
//     The tag is derived from the KEV+EPSS content digests and the manifest's
//     created annotation is pinned to the Unix epoch, so identical input files
//     always repack to a byte-identical, same-named artifact (reproducible).
package pack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v3"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"

	"github.com/sbomscanner/sbomscanner-cli/internal/paths"
)

// Media types used by the DB artifact.
const (
	ArtifactType   = "application/vnd.sbomscanner.db.v1+json"
	KEVLayerMedia  = "application/vnd.sbomscanner.kev.v1+csv"
	EPSSLayerMedia = "application/vnd.sbomscanner.epss.v1+csv"
	LatestTag      = "latest"

	// epochCreated pins the manifest's created annotation to the Unix epoch so
	// identical input files yield a byte-identical manifest (SOURCE_DATE_EPOCH
	// convention). A wall-clock time here would change the manifest digest on
	// every run and defeat the content-addressed tag. Build provenance instead
	// comes from the registry's push metadata.
	epochCreated = "1970-01-01T00:00:00Z"
)

// Command builds the `pack` command.
func Command() *cli.Command {
	return &cli.Command{
		Name:  "pack",
		Usage: "Pack KEV+EPSS into an OCI artifact in the local layout",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				fmt.Fprintf(os.Stderr, "pack: unexpected arguments: %v\n", cmd.Args().Slice())
				return cli.Exit("", 2)
			}
			if err := run(ctx); err != nil {
				return cli.Exit("error: "+err.Error(), 1)
			}
			return nil
		},
	}
}

// run executes `pack`.
func run(ctx context.Context) error {
	dataDir, err := paths.DataDir()
	if err != nil {
		return err
	}
	// Preconditions: both files must be present *and* readable *and* non-empty.
	// Extra files in the directory are ignored per the spec.
	kevPath := filepath.Join(dataDir, paths.KEVFileName)
	epssPath := filepath.Join(dataDir, paths.EPSSFileName)
	if err := mustExistNonEmpty(kevPath); err != nil {
		return fmt.Errorf("pack: KEV precondition: %w", err)
	}
	if err := mustExistNonEmpty(epssPath); err != nil {
		return fmt.Errorf("pack: EPSS precondition: %w", err)
	}

	layoutDir, err := paths.EnsureLayoutDir()
	if err != nil {
		return err
	}

	store, err := oci.New(layoutDir)
	if err != nil {
		return fmt.Errorf("open OCI layout %s: %w", layoutDir, err)
	}
	// AutoSaveIndex defaults to true — Tag() persists index.json on its own.

	// Fixed layer order: KEV, then EPSS. Deterministic layer order gives us
	// stable digests across runs (given identical file contents).
	kevDesc, err := pushFileAsLayer(ctx, store, kevPath, KEVLayerMedia)
	if err != nil {
		return fmt.Errorf("push KEV layer: %w", err)
	}
	epssDesc, err := pushFileAsLayer(ctx, store, epssPath, EPSSLayerMedia)
	if err != nil {
		return fmt.Errorf("push EPSS layer: %w", err)
	}

	// Empty config blob — the DB artifactType lives on the manifest itself
	// (OCI 1.1 style), not on the config media type.
	emptyDesc, err := pushEmptyConfig(ctx, store)
	if err != nil {
		return fmt.Errorf("push empty config: %w", err)
	}

	manifestDesc, err := oras.PackManifest(
		ctx,
		store,
		oras.PackManifestVersion1_1,
		ArtifactType,
		oras.PackManifestOptions{
			Layers:           []ocispec.Descriptor{kevDesc, epssDesc},
			ConfigDescriptor: &emptyDesc,
			ManifestAnnotations: map[string]string{
				// Pinned (not time.Now) so the manifest is reproducible; oras
				// honors a caller-provided created annotation.
				ocispec.AnnotationCreated: epochCreated,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("pack manifest: %w", err)
	}

	// Tag from the layer content digests so unchanged files repack to the same
	// name. kevDesc/epssDesc.Digest are each sha256(file content).
	contentTagName := contentTag(kevDesc.Digest, epssDesc.Digest)

	if err := store.Tag(ctx, manifestDesc, contentTagName); err != nil {
		return fmt.Errorf("tag %s: %w", contentTagName, err)
	}
	if err := store.Tag(ctx, manifestDesc, LatestTag); err != nil {
		return fmt.Errorf("tag %s: %w", LatestTag, err)
	}

	fmt.Printf("packed %s (%s)\n", manifestDesc.Digest, manifestDesc.MediaType)
	fmt.Printf("  tag: %s\n", contentTagName)
	fmt.Printf("  tag: %s\n", LatestTag)
	return nil
}

// pushFileAsLayer streams file at path into the store as a blob with the given
// media type. Adds an image.title annotation so `oras manifest fetch` prints
// the original filename.
func pushFileAsLayer(ctx context.Context, store *oci.Store, path, mediaType string) (ocispec.Descriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Stat separately (not from f.Stat() alone) so we can build the descriptor
	// with size/digest up front. content-oras helpers wrap this pattern.
	desc, err := descriptorFromReader(f, mediaType)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc.Annotations = map[string]string{
		ocispec.AnnotationTitle: filepath.Base(path),
	}

	// Re-open a fresh reader for the actual push (descriptorFromReader consumed
	// the first one for hashing).
	f2, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reopen %s: %w", path, err)
	}
	defer f2.Close()

	if err := store.Push(ctx, desc, f2); err != nil {
		// Already-present blobs are fine — OCI store returns errdef.ErrAlreadyExists
		// for them. Treat as success (deterministic re-pack should be a no-op on
		// the layer bytes).
		if !isAlreadyExists(err) {
			return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", path, err)
		}
	}
	return desc, nil
}

// pushEmptyConfig pushes the standard empty JSON config blob referenced by
// OCI 1.1 image manifests when there is no real config payload.
func pushEmptyConfig(ctx context.Context, store *oci.Store) (ocispec.Descriptor, error) {
	desc := ocispec.DescriptorEmptyJSON
	if err := store.Push(ctx, desc, bytes.NewReader(ocispec.DescriptorEmptyJSON.Data)); err != nil {
		if !isAlreadyExists(err) {
			return ocispec.Descriptor{}, err
		}
	}
	return desc, nil
}

// descriptorFromReader computes size + digest of r and returns a descriptor.
// r is fully consumed.
func descriptorFromReader(r io.Reader, mediaType string) (ocispec.Descriptor, error) {
	// content.NewDescriptorFromReader would do the same; inlined to avoid
	// pulling more oras internals into the import surface.
	digester := newDigester()
	n, err := io.Copy(digester, r)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digester.Digest(),
		Size:      n,
	}, nil
}

// mustExistNonEmpty returns nil iff path is a regular non-empty file.
func mustExistNonEmpty(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if st.Size() == 0 {
		return fmt.Errorf("%s: empty file", path)
	}
	return nil
}
