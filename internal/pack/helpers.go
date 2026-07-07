package pack

import (
	"errors"
	"hash"
	"io"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/errdef"
)

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
