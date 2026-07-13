package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
)

// Media types and file names used by the DB artifact.
const (
	// ArtifactType identifies the sbomscanner DB artifact on the manifest.
	ArtifactType = "application/vnd.sbomscanner.db.v1+json"
	// LayerMediaType is the media type of the single tar+gzip layer.
	LayerMediaType = "application/vnd.sbomscanner.db.layer.v1.tar+gzip"
	// BundleFileName is the file name of the tar.gz bundle,
	// used both as the layer title annotation and as the default output name on pull.
	BundleFileName = "sbomscanner-db.tar.gz"

	// epochCreated pins the manifest's created annotation to the Unix epoch
	// so that identical input files yield a byte-identical manifest (SOURCE_DATE_EPOCH convention).
	// A wall-clock time here would change the manifest digest on every run.
	epochCreated = "1970-01-01T00:00:00Z"
)

// Artifact describes one DB artifact by reference.
type Artifact struct {
	Ref    string
	Digest string
	Size   int64
}

// Builder assembles DB artifacts into a local store.
type Builder struct {
	store  *Store
	logger *slog.Logger
}

// NewBuilder returns a Builder writing into the given store.
func NewBuilder(store *Store, logger *slog.Logger) *Builder {
	return &Builder{store: store, logger: logger}
}

// Build packs the given data files from dataDir into the DB artifact
// and tags it as ref in the store.
func (builder *Builder) Build(ctx context.Context, ref, dataDir string, files []string) (Artifact, error) {
	layout, err := builder.store.open()
	if err != nil {
		return Artifact{}, err
	}

	builder.logger.InfoContext(ctx, "packing artifact", "ref", ref, "files", files)

	// Bundle the data files into a tar.gz layer, written to a temp dir.
	bundleDir, err := os.MkdirTemp("", "sbomscannerdb-bundle-*")
	if err != nil {
		return Artifact{}, fmt.Errorf("create temp bundle dir: %w", err)
	}
	defer os.RemoveAll(bundleDir)

	bundlePath := filepath.Join(bundleDir, BundleFileName)
	if err := writeBundle(bundlePath, dataDir, files); err != nil {
		return Artifact{}, fmt.Errorf("bundle data files: %w", err)
	}

	layerDesc, err := pushFileAsLayer(ctx, layout, bundlePath, LayerMediaType)
	if err != nil {
		return Artifact{}, fmt.Errorf("push layer: %w", err)
	}

	// Empty config blob — the DB artifactType lives on the manifest itself (OCI 1.1 style),
	// not on the config media type.
	emptyDesc, err := pushEmptyConfig(ctx, layout)
	if err != nil {
		return Artifact{}, fmt.Errorf("push empty config: %w", err)
	}

	manifestDesc, err := oras.PackManifest(
		ctx,
		layout,
		oras.PackManifestVersion1_1,
		ArtifactType,
		oras.PackManifestOptions{
			Layers:           []ocispec.Descriptor{layerDesc},
			ConfigDescriptor: &emptyDesc,
			ManifestAnnotations: map[string]string{
				// Pinned (not time.Now) so the manifest is reproducible;
				// oras honors a caller-provided created annotation.
				ocispec.AnnotationCreated: epochCreated,
			},
		},
	)
	if err != nil {
		return Artifact{}, fmt.Errorf("pack manifest: %w", err)
	}

	if err := layout.Tag(ctx, manifestDesc, ref); err != nil {
		return Artifact{}, fmt.Errorf("tag %s: %w", ref, err)
	}
	builder.logger.InfoContext(ctx, "tagged artifact", "ref", ref, "digest", manifestDesc.Digest)

	return Artifact{
		Ref:    ref,
		Digest: manifestDesc.Digest.String(),
		Size:   manifestDesc.Size,
	}, nil
}

// writeBundle creates a tar.gz at bundlePath containing the given files
// (read from dataDir, stored under their base names).
// Tar headers are normalized (zero mtime, fixed mode) for reproducibility.
func writeBundle(bundlePath, dataDir string, files []string) error {
	outFile, err := os.Create(bundlePath)
	if err != nil {
		return fmt.Errorf("create %s: %w", bundlePath, err)
	}
	defer outFile.Close()

	gzipWriter := gzip.NewWriter(outFile)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, name := range files {
		if err := addFileToTar(tarWriter, filepath.Join(dataDir, name), name); err != nil {
			return err
		}
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close %s: %w", bundlePath, err)
	}
	return nil
}

// addFileToTar appends the file at path to tarWriter under name with normalized metadata.
func addFileToTar(tarWriter *tar.Writer, path, name string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if fileInfo.Size() == 0 {
		return fmt.Errorf("%s: empty file", path)
	}

	// Normalized header: fixed mode, zero timestamps, no owner info,
	// so that identical file contents always produce identical bundle bytes.
	header := &tar.Header{
		Name: name,
		Mode: 0o644,
		Size: fileInfo.Size(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("write tar header %s: %w", name, err)
	}
	if _, err := io.Copy(tarWriter, file); err != nil {
		return fmt.Errorf("write tar entry %s: %w", name, err)
	}
	return nil
}

// pushFileAsLayer streams the file at path into the layout as a blob with the given media type.
// It adds an image.title annotation so that `oras manifest fetch` prints the original filename.
func pushFileAsLayer(ctx context.Context, layout *orasoci.Store, path, mediaType string) (ocispec.Descriptor, error) {
	desc, err := descriptorFromFile(path, mediaType)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc.Annotations = map[string]string{
		ocispec.AnnotationTitle: filepath.Base(path),
	}

	file, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	if err := layout.Push(ctx, desc, file); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, fmt.Errorf("push %s: %w", path, err)
	}
	return desc, nil
}

// pushEmptyConfig pushes the standard empty JSON config blob
// referenced by OCI 1.1 image manifests when there is no real config payload.
func pushEmptyConfig(ctx context.Context, layout *orasoci.Store) (ocispec.Descriptor, error) {
	desc := ocispec.DescriptorEmptyJSON
	if err := layout.Push(ctx, desc, bytes.NewReader(ocispec.DescriptorEmptyJSON.Data)); err != nil && !isAlreadyExists(err) {
		return ocispec.Descriptor{}, fmt.Errorf("push empty config blob: %w", err)
	}
	return desc, nil
}

// isAlreadyExists returns true when err (or any wrapped cause) is oras' "blob already exists" sentinel.
// Pushing a duplicate is not a real failure —
// content-addressed stores are idempotent on identical bytes.
func isAlreadyExists(err error) bool {
	return errors.Is(err, errdef.ErrAlreadyExists)
}
