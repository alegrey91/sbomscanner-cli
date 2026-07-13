package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRef = "registry.example.com/kubewarden/sbomscanner/sbomscannerdb:latest"

// writeTestData creates a data dir with two small CSV files and returns its
// path along with the file names.
func writeTestData(t *testing.T) (string, []string) {
	t.Helper()
	dataDir := t.TempDir()
	files := []string{"kev.csv", "epss.csv"}
	for _, name := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dataDir, name), []byte("data for "+name), 0o600))
	}
	return dataDir, files
}

func TestBuild_TagsArtifactInStore(t *testing.T) {
	dataDir, files := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")

	built, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, files)
	require.NoError(t, err)
	assert.Equal(t, testRef, built.Ref)

	artifacts, err := NewStore(storeDir, slog.New(slog.DiscardHandler)).List()
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, testRef, artifacts[0].Ref)
	assert.Equal(t, built.Digest, artifacts[0].Digest)
}

func TestBuild_IsReproducible(t *testing.T) {
	dataDir, files := writeTestData(t)

	first, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "a"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, files)
	require.NoError(t, err)
	second, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "b"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, files)
	require.NoError(t, err)

	assert.Equal(t, first.Digest, second.Digest)
}

func TestBuild_RetagsExistingContent(t *testing.T) {
	dataDir, files := writeTestData(t)
	storeDir := filepath.Join(t.TempDir(), "store")
	ctx := context.Background()

	store := NewStore(storeDir, slog.New(slog.DiscardHandler))
	builder := NewBuilder(store, slog.New(slog.DiscardHandler))
	_, err := builder.Build(ctx, testRef, dataDir, files)
	require.NoError(t, err)
	otherRef := "registry.example.com/kubewarden/sbomscanner/sbomscannerdb:v2"
	_, err = builder.Build(ctx, otherRef, dataDir, files)
	require.NoError(t, err)

	artifacts, err := store.List()
	require.NoError(t, err)
	refs := make([]string, 0, len(artifacts))
	for _, a := range artifacts {
		refs = append(refs, a.Ref)
	}
	assert.Contains(t, refs, testRef)
	assert.Contains(t, refs, otherRef)
}

func TestBuild_FailsOnMissingDataFile(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "store")
	_, err := NewBuilder(NewStore(storeDir, slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, t.TempDir(), []string{"missing.csv"})
	require.Error(t, err)
}

func TestBuild_FailsOnEmptyDataFile(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "empty.csv"), nil, 0o600))

	_, err := NewBuilder(NewStore(filepath.Join(t.TempDir(), "store"), slog.New(slog.DiscardHandler)), slog.New(slog.DiscardHandler)).Build(context.Background(), testRef, dataDir, []string{"empty.csv"})
	require.Error(t, err)
}

func TestList_EmptyOnMissingStore(t *testing.T) {
	artifacts, err := NewStore(filepath.Join(t.TempDir(), "does-not-exist"), slog.New(slog.DiscardHandler)).List()
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestWriteBundle_ContainsFiles(t *testing.T) {
	dataDir, files := writeTestData(t)
	bundlePath := filepath.Join(t.TempDir(), BundleFileName)

	require.NoError(t, writeBundle(bundlePath, dataDir, files))

	got := readTarGz(t, bundlePath)
	require.Len(t, got, len(files))
	for _, name := range files {
		assert.Equal(t, "data for "+name, got[name])
	}
}

// readTarGz returns the name -> content map of a tar.gz file.
func readTarGz(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gzr)

	entries := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		entries[hdr.Name] = string(data)
	}
	return entries
}
