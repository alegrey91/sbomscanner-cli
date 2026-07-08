# sbomscanner-cli

## Introduction

`sbomscanner-cli` builds and distributes the vulnerability-prioritization data
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

The CLI exposes three commands, backed only by Go's standard `flag` package
(no cobra):

| Command | Description |
| ------- | ----------- |
| `get`   | Downloads the KEV and/or EPSS data files into `~/.sbomscanner/data/`. |
| `pack`  | Bundles both data files into a local OCI artifact under `~/.sbomscanner/layout/`. |
| `push`  | Publishes a packed artifact from the local layout to a remote OCI registry. |

### `get`

Downloads the raw datasets and stores them under `~/.sbomscanner/data/`. The
files are not versioned upstream, so every run re-downloads and overwrites the
previous copies (force download is implicit). A progress bar is shown while
downloading.

- `get all`: download **both** files sequentially (KEV first, then EPSS).
- `get kev`: download only the KEV catalog.
- `get epss`: download only the EPSS scores (the source is gzipped and is
  decompressed before being stored).

Running `get` with no subcommand prints usage and exits `2`.

### `pack`

Loads both files from `~/.sbomscanner/data/` and assembles them into a single
OCI artifact in the local OCI layout at `~/.sbomscanner/layout/`. Both files
must be present or the command fails. The artifact is named
`sbomscanner-db_<hash>`, where `<hash>` is a 12-character SHA-256 derived from
the **content** of the KEV and EPSS files, and a `latest` tag is written
alongside it.

Because the tag comes from the file content, re-packing unchanged
files is **reproducible**: the same input always produces a byte-identical,
same-named artifact. If the data hasn't changed since the last run, the pack is
effectively a no-op.

The artifact uses these media / artifact types:

- Artifact: `application/vnd.sbomscanner.db.v1+json`
- KEV layer: `application/vnd.sbomscanner.kev.v1+csv`
- EPSS layer: `application/vnd.sbomscanner.epss.v1+csv`

### `push`

Publishes a packed artifact from the local layout to a registry, given a
`<registry>/<repo>:<tag>` reference. Authentication uses your existing Docker
credentials at `~/.docker/config.json` (or `$DOCKER_CONFIG/config.json`); if no
config file exists the command exits with an error. The artifact must already
exist in the local layout for the given tag.

- `--skip-tls-verify`: skip TLS certificate verification (e.g. for a registry
  with a self-signed certificate).

## Flow

The three commands form a simple pipeline. Run them in order to publish a fresh
database:

```
  get                pack                     push
  ────▶  data files  ────▶  OCI artifact      ────▶  registry
         on disk            in local layout
```

1. **Pull**: `get all` downloads the latest KEV and EPSS files into
   `~/.sbomscanner/data/`.
2. **Pack**: `pack` bundles those files into an OCI artifact in the local OCI
   layout at `~/.sbomscanner/layout/`.
3. **Push**: `push <registry>/<repo>:<tag>` uploads the artifact to the OCI
   registry of your choice.

Once the artifact is in a registry, configure sbomscanner to point at that
`<registry>/<repo>:<tag>`. sbomscanner will then pull the `sbomscanner-db`
artifact when it needs the KEV/EPSS data for CVE prioritization.

### Example

```sh
# 1. Pull the latest KEV + EPSS data
sbomscanner-cli get all

# 2. Pack them into a local OCI artifact
sbomscanner-cli pack

# 3. Push to your registry
sbomscanner-cli push registry.example.com/sbomscanner-db:latest
```
