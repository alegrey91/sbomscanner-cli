# sbomscannerdb

## Introduction

`sbomscannerdb` builds and distributes the vulnerability-prioritization data
used by [sbomscanner](https://github.com/kubewarden/sbomscanner) as an **OCI artifact**.
It packages the **KEV** and **EPSS** datasets into a single artifact
(`sbomscanner-db`) and pushes it to an OCI registry of your choice. sbomscanner
then consumes this data by pulling the database from that registry whenever it
needs it.

Distributing the data as an OCI artifact means it can be versioned, stored, and
retrieved through the same registry infrastructure already used for container
images.

### What are KEV and EPSS?

- **KEV (Known Exploited Vulnerabilities catalog)**: Maintained by CISA, it
  lists CVEs that are known to be **actively exploited in the wild**. A CVE
  appearing in KEV is a strong signal that it should be remediated with
  urgency, regardless of its CVSS score.
- **EPSS (Exploit Prediction Scoring System)**: Maintained by FIRST, it assigns
  each CVE a **probability that it will be exploited** in the next 30
  days. Where KEV tells you what *is* being exploited, EPSS estimates what is
  *likely* to be.

### Why they matter

A typical SBOM scan surfaces far more vulnerabilities than any team can fix at
once. CVSS severity alone is a poor guide to *what to fix first*, because it
does not reflect real-world exploitation. KEV and EPSS add exactly that missing
context:

- **KEV** flags the vulnerabilities that attackers are already using.
- **EPSS** ranks the rest by how likely they are to be exploited soon.

Together they let sbomscanner move from "here are 500 CVEs" to a **prioritized**
list that focuses remediation effort where it reduces the most risk.

## Commands

The CLI follows a docker-like workflow: artifacts are built into a local
store (an OCI image layout under the user cache directory, e.g.
`$XDG_CACHE_HOME/sbomscannerdb` on Linux or `~/Library/Caches/sbomscannerdb`
on macOS), tagged by reference, and pushed from there.

| Command | Description |
| ------- | ----------- |
| `build` | Downloads the KEV and EPSS data files and builds them into an OCI artifact in the local store, tagged with the given reference. |
| `list`  | Lists the artifacts in the local store. |
| `push`  | Pushes a previously built artifact from the local store to its registry. |
| `pull`  | Pulls the artifact from a registry and writes the `sbomscanner-db.tar.gz` bundle to the current directory. |

`build`, `push`, and `pull` take a single `<registry>/<repo>:<tag>` reference
(e.g. `ghcr.io/kubewarden/sbomscanner/sbomscannerdb:latest`). `push` and
`pull` share these flags:

- `--skip-tls-verify`: skip TLS certificate verification (e.g. for a registry
  with a self-signed certificate).
- `--plain-http`: use HTTP instead of HTTPS (useful for local registries).

### `build`

Downloads the latest KEV catalog and EPSS scores (the EPSS source is gzipped
and decompressed on the fly), bundles both data files into a single
`sbomscanner-db.tar.gz`, packs it as an OCI artifact, and tags it with the
given reference in the local store. Rebuilding the same reference re-tags it;
unchanged data is a no-op thanks to content addressing.

The artifact uses these media / artifact types:

- Artifact: `application/vnd.sbomscanner.db.v1+json`
- Layer: `application/vnd.sbomscanner.db.layer.v1.tar+gzip`

### `list`

Prints the tagged artifacts in the local store with their digest and
manifest size.

### `push`

Publishes a previously built artifact from the local store to the registry
identified by its reference. Authentication uses your existing Docker
credentials at `~/.docker/config.json` (or `$DOCKER_CONFIG/config.json`); if
no config file exists the command exits with an error.

### `pull`

Fetches the artifact manifest from the registry, locates the database layer by
media type, and writes it as `sbomscanner-db.tar.gz` to the current directory.
The bundle contains:

- `known_exploited_vulnerabilities.json` (KEV)
- `epss_scores.csv` (EPSS)

## Flow

```
  build:  KEV/EPSS feeds ──▶ sbomscanner-db.tar.gz ──▶ local store (tagged)
  push:   local store ──▶ registry
  pull:   registry ──▶ ./sbomscanner-db.tar.gz
```

Once the artifact is in a registry, configure sbomscanner to point at that
`<registry>/<repo>:<tag>`. sbomscanner will then pull the `sbomscanner-db`
artifact when it needs the KEV/EPSS data for CVE prioritization.

## Bundle contract

The artifact is an OCI 1.1 image manifest with:

- artifactType: `application/vnd.sbomscanner.db.v1+json`
- a single layer of media type `application/vnd.sbomscanner.db.layer.v1.tar+gzip`

The layer is a tar.gz (`sbomscanner-db.tar.gz`) containing exactly two files,
each kept verbatim in its upstream native format — no re-encoding is applied,
so the schemas below are owned by CISA and FIRST respectively:

### `known_exploited_vulnerabilities.json` (KEV)

The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
JSON feed. Top-level object with catalog metadata and a `vulnerabilities`
array:

```json
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.07.12",
  "dateReleased": "2026-07-12T00:00:00.0000Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "...",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": "",
      "cwes": ["CWE-20", "CWE-400", "CWE-502"]
    }
  ]
}
```

Typical consumption: build a set keyed by `cveID` for O(1) "is this CVE
actively exploited?" lookups.

### `epss_scores.csv` (EPSS)

The [FIRST EPSS](https://www.first.org/epss/) daily bulk feed, decompressed.
One row per published CVE (~300k rows, ~10 MB) with the score as of the day
the artifact was built:

```csv
#model_version:v2026.06.15,score_date:2026-07-12T12:00:00Z
cve,epss,percentile
CVE-2021-44228,0.97565,0.99992
```

- Lines starting with `#` are metadata (model version and score date) and
  should be skipped when parsing rows.
- `epss` is the probability (0–1) of exploitation in the next 30 days;
  `percentile` is the CVE's rank relative to all scored CVEs.

Typical consumption: stream the CSV into a map keyed by `cve` for O(1) score
lookups. The whole dataset fits comfortably in memory (~50 MB for both files
parsed).

### Example


```sh
# Build the database artifact into the local store
sbomscannerdb build ghcr.io/kubewarden/sbomscanner/sbomscannerdb:latest

# Inspect the local store
sbomscannerdb list

# Publish it
sbomscannerdb push ghcr.io/kubewarden/sbomscanner/sbomscannerdb:latest

# Retrieve it later
sbomscannerdb pull ghcr.io/kubewarden/sbomscanner/sbomscannerdb:latest
```

## Development

```sh
make build        # build ./bin/sbomscannerdb
make lint         # run golangci-lint
make test         # run tests
```
