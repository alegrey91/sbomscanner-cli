package datafeed

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureServer serves the files under test/fixtures.
func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.FileServer(http.Dir("../../test/fixtures")))
	t.Cleanup(srv.Close)
	return srv
}

// garbageServer serves an HTML error page on every path,
// mimicking a CDN/WAF response that is not a data feed.
func garbageServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Service temporarily unavailable</body></html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestKEVDownloader_Download(t *testing.T) {
	srv := fixtureServer(t)
	dir := t.TempDir()

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/known_exploited_vulnerabilities.json"
	require.NoError(t, d.Download(context.Background(), dir))

	file, err := os.Open(filepath.Join(dir, KEVFileName))
	require.NoError(t, err)
	defer file.Close()

	catalog, err := ParseKEVCatalog(file)
	require.NoError(t, err)
	assert.Equal(t, 1, catalog.Count)
	require.Len(t, catalog.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2021-44228", catalog.Vulnerabilities[0].CVEID)
}

func TestEPSSDownloader_Download(t *testing.T) {
	srv := fixtureServer(t)
	dir := t.TempDir()

	d := NewEPSSDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/epss_scores.csv.gz"
	require.NoError(t, d.Download(context.Background(), dir))

	// The gzipped fixture must land decompressed under the plain CSV name.
	file, err := os.Open(filepath.Join(dir, EPSSFileName))
	require.NoError(t, err)
	defer file.Close()

	scores, err := ParseEPSSScores(file)
	require.NoError(t, err)
	assert.Equal(t, "v2026.06.15", scores.ModelVersion)
	assert.Equal(t, "2026-07-12T12:00:00Z", scores.ScoreDate)
	require.Len(t, scores.Scores, 1)
	assert.Equal(t, EPSSScore{CVE: "CVE-2021-44228", EPSS: 0.97565, Percentile: 0.99992}, scores.Scores[0])
}

func TestKEVDownloader_DownloadFailsOnHTTPError(t *testing.T) {
	srv := fixtureServer(t)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/does-not-exist.json"
	require.Error(t, d.Download(context.Background(), t.TempDir()))
}

func TestKEVDownloader_DownloadFailsOnInvalidPayload(t *testing.T) {
	srv := garbageServer(t)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/known_exploited_vulnerabilities.json"
	err := d.Download(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate KEV")
}

func TestEPSSDownloader_DownloadFailsOnInvalidPayload(t *testing.T) {
	srv := garbageServer(t)

	d := NewEPSSDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/epss_scores-current.csv.gz"
	err := d.Download(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate EPSS")
}

func TestParseKEVCatalog_Failures(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"not JSON", "<html>error</html>"},
		{"empty vulnerabilities", `{"title":"KEV","count":0,"vulnerabilities":[]}`},
		{"missing cveID", `{"count":1,"vulnerabilities":[{"vendorProject":"Apache"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseKEVCatalog(strings.NewReader(tt.input))
			require.Error(t, err)
		})
	}
}

func TestParseEPSSScores_Failures(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"not CSV", "<html>error</html>"},
		{"wrong header", "id,score,rank\nCVE-2021-44228,0.9,0.9\n"},
		{"no rows", "#model_version:v1\ncve,epss,percentile\n"},
		{"non-numeric epss", "cve,epss,percentile\nCVE-2021-44228,high,0.9\n"},
		{"non-numeric percentile", "cve,epss,percentile\nCVE-2021-44228,0.9,top\n"},
		{"empty cve", "cve,epss,percentile\n,0.9,0.9\n"},
		{"wrong field count", "cve,epss,percentile\nCVE-2021-44228,0.9\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseEPSSScores(strings.NewReader(tt.input))
			require.Error(t, err)
		})
	}
}

func TestParseEPSSScores_MetadataIsOptional(t *testing.T) {
	scores, err := ParseEPSSScores(strings.NewReader("cve,epss,percentile\nCVE-2021-44228,0.97565,0.99992\n"))
	require.NoError(t, err)
	assert.Empty(t, scores.ModelVersion)
	assert.Empty(t, scores.ScoreDate)
	require.Len(t, scores.Scores, 1)
}
