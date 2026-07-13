package datafeed

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
)

// EPSSFileName is the file name of the EPSS scores in the destination directory.
const EPSSFileName = "epss_scores.csv"

// defaultEPSSURL is the daily EPSS bulk feed (gzipped CSV).
const defaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// EPSSDownloader downloads the EPSS scores feed.
type EPSSDownloader struct {
	http   *HTTPDownloader
	logger *slog.Logger
	url    string
}

// NewEPSSDownloader returns an EPSSDownloader fetching from the official EPSS bulk feed.
func NewEPSSDownloader(httpDownloader *HTTPDownloader, logger *slog.Logger) *EPSSDownloader {
	return &EPSSDownloader{
		http:   httpDownloader,
		logger: logger,
		url:    defaultEPSSURL,
	}
}

// Download fetches the EPSS scores (gzipped CSV, decompressed on the fly) into dir/EPSSFileName.
func (downloader *EPSSDownloader) Download(ctx context.Context, dir string) error {
	dst := filepath.Join(dir, EPSSFileName)
	downloader.logger.InfoContext(ctx, "downloading EPSS scores", "url", downloader.url)
	size, err := downloader.http.Download(ctx, downloader.url, dst)
	if err != nil {
		return fmt.Errorf("download EPSS: %w", err)
	}
	downloader.logger.InfoContext(ctx, "downloaded EPSS scores", "file", EPSSFileName, "bytes", size)
	return nil
}
