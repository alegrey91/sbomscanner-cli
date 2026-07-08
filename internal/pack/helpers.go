package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/errdef"
)

// TagPrefix is prepended to the content-derived hash to form the artifact tag.
const TagPrefix = "sbomscanner-db_"

// contentTag derives the artifact tag from the content of both layers.
//
// Each layer descriptor's Digest is already sha256(file content), so hashing
// the two canonical digest strings (in fixed KEV, EPSS order) yields a stable
// identifier: identical input files always produce the same tag, making the
// pack reproducible. The digest is truncated to 12 hex chars (git-style short
// hash) — collision risk is negligible for this dataset.
func contentTag(kev, epss digest.Digest) string {
	sum := sha256.Sum256([]byte(kev.String() + "\n" + epss.String()))
	return TagPrefix + hex.EncodeToString(sum[:])[:12]
}

// digestWriter is a tiny wrapper that turns a digest.Digester into an
// io.Writer suitable for io.Copy. digest.Digester expects callers to write to
// the underlying hash directly, so we expose Write via that hash.
type digestWriter struct {
	h  hash.Hash
	dr digest.Digester
}

func newDigester() *digestWriter {
	dr := digest.Canonical.Digester()
	return &digestWriter{h: dr.Hash(), dr: dr}
}

func (d *digestWriter) Write(p []byte) (int, error) { return d.h.Write(p) }
func (d *digestWriter) Digest() digest.Digest       { return d.dr.Digest() }

// Ensure the interface bound for descriptorFromReader's second arg is met.
var _ io.Writer = (*digestWriter)(nil)

// isAlreadyExists returns true when err (or any wrapped cause) is oras'
// "blob already exists" sentinel. Pushing a duplicate is not a real failure —
// content-addressed stores are idempotent on identical bytes.
func isAlreadyExists(err error) bool {
	return errors.Is(err, errdef.ErrAlreadyExists)
}
