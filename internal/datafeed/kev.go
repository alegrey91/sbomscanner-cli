package datafeed

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
)

// KEVFileName is the file name of the KEV catalog in the destination directory.
const KEVFileName = "known_exploited_vulnerabilities.json"

// defaultKEVURL is the CISA KEV catalog feed.
const defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVDownloader downloads the CISA Known Exploited Vulnerabilities catalog.
type KEVDownloader struct {
	http   *HTTPDownloader
	logger *slog.Logger
	url    string
}

// NewKEVDownloader returns a KEVDownloader fetching from the official CISA feed.
func NewKEVDownloader(httpDownloader *HTTPDownloader, logger *slog.Logger) *KEVDownloader {
	return &KEVDownloader{
		http:   httpDownloader,
		logger: logger,
		url:    defaultKEVURL,
	}
}

// Download fetches the KEV catalog (JSON) into dir/KEVFileName.
func (downloader *KEVDownloader) Download(ctx context.Context, dir string) error {
	dst := filepath.Join(dir, KEVFileName)
	downloader.logger.InfoContext(ctx, "downloading KEV catalog", "url", downloader.url)
	size, err := downloader.http.Download(ctx, downloader.url, dst)
	if err != nil {
		return fmt.Errorf("download KEV: %w", err)
	}
	downloader.logger.InfoContext(ctx, "downloaded KEV catalog", "file", KEVFileName, "bytes", size)
	return nil
}
