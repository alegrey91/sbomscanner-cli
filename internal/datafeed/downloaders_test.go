package datafeed

import (
	"context"
	"encoding/json"
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

func TestKEVDownloader_Download(t *testing.T) {
	srv := fixtureServer(t)
	dir := t.TempDir()

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/known_exploited_vulnerabilities.json"
	require.NoError(t, d.Download(context.Background(), dir))

	data, err := os.ReadFile(filepath.Join(dir, KEVFileName))
	require.NoError(t, err)

	var catalog struct {
		Count           int `json:"count"`
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(data, &catalog))
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
	data, err := os.ReadFile(filepath.Join(dir, EPSSFileName))
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "#model_version:"), "first line should be the model header: %q", lines[0])
	assert.Equal(t, "cve,epss,percentile", lines[1])
	assert.True(t, strings.HasPrefix(lines[2], "CVE-"), "data row expected: %q", lines[2])
}

func TestKEVDownloader_DownloadFailsOnHTTPError(t *testing.T) {
	srv := fixtureServer(t)

	d := NewKEVDownloader(NewHTTPDownloader(), slog.New(slog.DiscardHandler))
	d.url = srv.URL + "/does-not-exist.json"
	require.Error(t, d.Download(context.Background(), t.TempDir()))
}
