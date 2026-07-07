// Package get implements the `sbomscanner-cli get` command.
//
// Subcommands:
//
//	get all   -- KEV then EPSS, sequentially. Partial success is preserved:
//	             if KEV succeeds and EPSS fails, the fresh KEV is kept on disk.
//	get kev   -- KEV only
//	get epss  -- EPSS only (gunzip'd before rename)
//
// All writes are atomic: bytes stream to a per-pid ".tmp.<pid>" sibling and
// rename into place on success. On any failure (HTTP error, gunzip error,
// Ctrl+C), the .tmp is unlinked.
//
// Verification runs at the end of each subcommand and checks only what that
// subcommand was responsible for (Stat + size > 0).
package get

import (
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/schollz/progressbar/v3"

	"github.com/sbomscanner/sbomscanner-cli/internal/paths"
)

const (
	kevURL  = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

	userAgent = "sbomscanner-cli"

	// 30s applies to dial + response-header wait. Body reads stream freely and
	// only unblock on ctx cancellation (Ctrl+C) or network error.
	dialTimeout           = 30 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// Usage returned for `get` with no subcommand or -h.
func Usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: sbomscanner-cli get <subcommand>

Subcommands:
  all    Download KEV then EPSS (sequential).
  kev    Download KEV only.
  epss   Download EPSS only (gunzip'd on the fly).

Files are stored under ~/.sbomscanner/data/ (dir 0700, files 0600):
  %s
  %s
`, paths.KEVFileName, paths.EPSSFileName)
}

// Run dispatches the get subcommand. args is os.Args[2:] (i.e. after "get").
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		Usage(os.Stderr)
		// The main binary translates ErrUsage to exit code 2.
		return ErrUsage
	}

	sub := args[0]
	rest := args[1:]

	// Per-subcommand flag set. We give each one -h/--help.
	fs := flag.NewFlagSet("get "+sub, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { Usage(os.Stderr) }

	if err := fs.Parse(rest); err != nil {
		// flag prints its own error; treat as usage.
		return ErrUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "get %s: unexpected arguments: %v\n", sub, fs.Args())
		return ErrUsage
	}

	dataDir, err := paths.EnsureDataDir()
	if err != nil {
		return err
	}

	switch sub {
	case "all":
		return runAll(ctx, dataDir)
	case "kev":
		return runKEV(ctx, dataDir)
	case "epss":
		return runEPSS(ctx, dataDir)
	case "-h", "--help", "help":
		Usage(os.Stdout)
		return nil
	default:
		fmt.Fprintf(os.Stderr, "get: unknown subcommand %q\n", sub)
		Usage(os.Stderr)
		return ErrUsage
	}
}

// ErrUsage signals a usage error; the top-level binary maps it to exit 2.
var ErrUsage = errors.New("usage error")

// runAll downloads KEV then EPSS. Partial success (KEV ok, EPSS fails) is
// preserved on disk per the spec; we only report the failure and exit non-zero.
func runAll(ctx context.Context, dataDir string) error {
	var kevErr, epssErr error

	if err := downloadKEV(ctx, dataDir); err != nil {
		kevErr = err
		fmt.Fprintf(os.Stderr, "get all: KEV failed: %v\n", err)
	}
	// EPSS runs even if KEV failed — the spec doesn't say "abort on first
	// failure", and getting one file is strictly better than getting zero.
	if err := downloadEPSS(ctx, dataDir); err != nil {
		epssErr = err
		fmt.Fprintf(os.Stderr, "get all: EPSS failed: %v\n", err)
	}

	// Verify both files exist and are non-empty. This is the source of truth
	// for the exit code — download-time errors are printed above.
	kevMissing := verifyFile(filepath.Join(dataDir, paths.KEVFileName)) != nil
	epssMissing := verifyFile(filepath.Join(dataDir, paths.EPSSFileName)) != nil

	if kevMissing {
		fmt.Fprintf(os.Stderr, "get all: %s is missing or empty\n", paths.KEVFileName)
	}
	if epssMissing {
		fmt.Fprintf(os.Stderr, "get all: %s is missing or empty\n", paths.EPSSFileName)
	}

	if kevErr != nil || epssErr != nil || kevMissing || epssMissing {
		return errors.New("one or more downloads failed")
	}
	return nil
}

func runKEV(ctx context.Context, dataDir string) error {
	if err := downloadKEV(ctx, dataDir); err != nil {
		return err
	}
	dst := filepath.Join(dataDir, paths.KEVFileName)
	if err := verifyFile(dst); err != nil {
		fmt.Fprintf(os.Stderr, "get kev: %s: %v\n", paths.KEVFileName, err)
		return err
	}
	return nil
}

func runEPSS(ctx context.Context, dataDir string) error {
	if err := downloadEPSS(ctx, dataDir); err != nil {
		return err
	}
	dst := filepath.Join(dataDir, paths.EPSSFileName)
	if err := verifyFile(dst); err != nil {
		fmt.Fprintf(os.Stderr, "get epss: %s: %v\n", paths.EPSSFileName, err)
		return err
	}
	return nil
}

// downloadKEV: plain CSV, write directly.
func downloadKEV(ctx context.Context, dataDir string) error {
	dst := filepath.Join(dataDir, paths.KEVFileName)
	size, err := downloadTo(ctx, kevURL, dst, false)
	if err != nil {
		return fmt.Errorf("download KEV: %w", err)
	}
	fmt.Printf("%s (%d bytes)\n", paths.KEVFileName, size)
	return nil
}

// downloadEPSS: gzipped CSV. Decompress on the fly into the .tmp before rename.
func downloadEPSS(ctx context.Context, dataDir string) error {
	dst := filepath.Join(dataDir, paths.EPSSFileName)
	size, err := downloadTo(ctx, epssURL, dst, true)
	if err != nil {
		return fmt.Errorf("download EPSS: %w", err)
	}
	fmt.Printf("%s (%d bytes)\n", paths.EPSSFileName, size)
	return nil
}

// downloadTo streams url into dst atomically. If gunzip is true, the response
// body is passed through gzip.Reader before hitting disk.
//
// The progress bar wraps the *network* stream (Content-Length is the compressed
// size for EPSS). We do NOT show a separate progress bar for decompression —
// gunzip is chained via io.Copy on the same read path, so the download bar
// naturally moves as gzipped bytes arrive.
//
// Returns the final on-disk size (post-decompression for EPSS).
func downloadTo(ctx context.Context, url, dst string, gunzip bool) (int64, error) {
	tmp := tmpPath(dst)

	// Best-effort cleanup: if we return without a successful rename, drop the
	// partial. Also fires on Ctrl+C via the ctx path below.
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmp)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Include a snippet of the body to make CDN/CISA errors debuggable.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("unexpected status %s: %s", resp.Status, string(snippet))
	}

	// Progress bar wraps the network read. Unknown-size mode kicks in when
	// Content-Length is -1 (server didn't send it).
	bar := progressbar.NewOptions64(
		resp.ContentLength,
		progressbar.OptionSetDescription(filepath.Base(dst)),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stderr) }),
		progressbar.OptionSetRenderBlankState(true),
	)
	src := io.Reader(io.TeeReader(resp.Body, bar))

	// Create tmp with 0600 up front. We still chmod after close in case umask
	// stripped bits from OpenFile's mode arg.
	tmpFile, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, paths.FileMode)
	if err != nil {
		return 0, fmt.Errorf("open temp %s: %w", tmp, err)
	}

	// Chain gunzip if requested. Note: the gzip.Reader sits *after* the tee,
	// so the progress bar shows compressed bytes arriving — which matches the
	// Content-Length reported by the server.
	var reader io.Reader = src
	var gzr *gzip.Reader
	if gunzip {
		gzr, err = gzip.NewReader(src)
		if err != nil {
			tmpFile.Close()
			return 0, fmt.Errorf("open gzip: %w", err)
		}
		reader = gzr
	}

	written, copyErr := io.Copy(tmpFile, reader)
	if gzr != nil {
		_ = gzr.Close()
	}
	if closeErr := tmpFile.Close(); closeErr != nil && copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return 0, fmt.Errorf("write %s: %w", tmp, copyErr)
	}

	// Ensure exact 0600 regardless of umask.
	if err := os.Chmod(tmp, paths.FileMode); err != nil {
		return 0, fmt.Errorf("chmod %s: %w", tmp, err)
	}

	// Atomic rename lands the file in its final place.
	if err := os.Rename(tmp, dst); err != nil {
		return 0, fmt.Errorf("rename %s -> %s: %w", tmp, dst, err)
	}
	renamed = true
	return written, nil
}

// httpClient returns a client with the timeouts specified in the plan:
// 30s dial, 30s response-header wait, unbounded body read (interruptible via
// request context). We build the Transport explicitly rather than reusing
// http.DefaultTransport to avoid leaking a mutated DefaultTransport.
func httpClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   dialTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	// No client-level Timeout: we don't want to cap total request duration,
	// only dial + response-header. Body reads are bounded by ctx.
	return &http.Client{Transport: transport}
}

// tmpPath returns the per-pid tmp sibling for dst. Per-pid suffix prevents
// two concurrent `get` runs from racing on the same partial file.
func tmpPath(dst string) string {
	return dst + ".tmp." + strconv.Itoa(os.Getpid())
}

// verifyFile returns nil iff path exists as a regular file with size > 0.
func verifyFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if st.Size() == 0 {
		return fmt.Errorf("empty file")
	}
	return nil
}
