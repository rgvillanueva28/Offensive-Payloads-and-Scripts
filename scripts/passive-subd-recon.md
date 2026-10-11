# Passive Subdomain Recon

An interactive Python utility that performs **passive** subdomain reconnaissance using multiple techniques, consolidates the results into a single source-tagged dataset, and optionally screenshots every discovered host with **gowitness**.

No packets are sent to the target itself: every technique relies on third-party data sources (certificate transparency, public URL archives, and threat-intel APIs).

## Features

- **Multiple Passive Techniques**: Correlation and merge from `subfinder`, `gau`, VirusTotal and `crt.sh`.
- **Parallel Execution**: All enabled techniques run concurrently; a failure in one does not abort the rest.
- **Source Attribution**: Every subdomain is tagged with the technique(s) that discovered it.
- **Consolidated Reports**: One dataset exported to **CSV**, **JSON** and **Markdown**.
- **Screenshotting**: `gowitness` captures every discovered subdomain (auto-detects gowitness v2/v3 CLI).
- **Interactive by Default**: Asks for options with sensible defaults; no arguments required.
- **Batch Mode**: Fully non-interactive for automation and pipelines.
- **Self-Contained Setup**: `setup` downloads the Go binaries; `check` validates the environment.
- **Graceful Degradation**: Works without `questionary`/`python-dotenv`/`aiohttp` installed (built-in fallbacks).

## Techniques

| Technique | Source | API Key |
|---|---|---|
| subfinder | ProjectDiscovery passive sources | No |
| gau | Wayback, CommonCrawl, OTX, URLScan | No |
| VirusTotal | `/api/v3/domains/<domain>/subdomains` | **Yes** |
| crt.sh | Certificate Transparency logs | No |

## Prerequisites

- **Python 3.8+**
- **Linux / macOS** (binaries are downloaded for `linux/amd64`)
- Optional Python packages (installed by `setup`, fallbacks exist if absent):

  ```bash
  pip install questionary python-dotenv aiohttp
  ```

- Optional: a free **VirusTotal API key** — https://www.virustotal.com/gui/my-apikey

## Installation

### 1. Make the script executable

```bash
chmod +x passive-subd-recon.py
```

### 2. Install the reconnaissance tools

```bash
./passive-subd-recon.py setup
```

This downloads the latest `subfinder`, `gau` and `gowitness` releases (linux/amd64) into `~/.local/bin` and best-effort installs the Python dependencies.

Options:

| Flag | Description |
|---|---|
| `--install-dir DIR` | Install binaries into `DIR` (default: `~/.local/bin`). |
| `--force` | Reinstall tools that are already present. |
| `--no-python-deps` | Skip installing `questionary`/`python-dotenv`/`aiohttp`. |

> If `~/.local/bin` is not on your `PATH`, `setup` prints the export line to add.

### 3. Provide the VirusTotal API key

The key is resolved in this order: **CLI flag → environment variable → `.env` file**.

Copy the template and edit it:

```bash
cp .env.example .env
```

```text
VT_API_KEY=your_virustotal_api_key_here
```

Or export it in your shell:

```bash
export VT_API_KEY=your_virustotal_api_key_here
```

Either variable name works: `VT_API_KEY` or `VIRUSTOTAL_API_KEY`.

### 4. Verify the environment

```bash
./passive-subd-recon.py check
```

Prints a table of installed tools with versions and validates the API keys:

```text
== Tool check ==

Tool        Status          Version       Location
----------------------------------------------------------------------
subfinder   found           2.13.0        /usr/bin/subfinder
gau         found           2.2.4         /usr/bin/gau
gowitness   found           3.1.1         /usr/bin/gowitness

== API key check ==

[+] VirusTotal   set and well-formed (environment (VT_API_KEY))
[+] crt.sh       no API key required
```

## Usage

### Interactive (default)

```bash
./passive-subd-recon.py
```

You are prompted for:

1. **Target domain(s)** — comma-separated, or a path to a file with one domain per line.
2. **Techniques** — checkbox, all pre-selected.
3. **VirusTotal API key** — only if not already configured.
4. **Output directory** — default `./results`.
5. **Screenshots** — `Yes` by default; asks for the gowitness thread count.

Press `Enter` at any prompt to accept the default.

### Batch / non-interactive

```bash
./passive-subd-recon.py --batch [options]
```

In batch mode **all boolean options default to `false`**: you must explicitly enable each technique and the screenshots.

```bash
# All techniques, screenshots enabled
./passive-subd-recon.py --batch -d example.com \
    --subfinder --gau --virustotal --crtsh --screenshots

# Single technique, no screenshots
./passive-subd-recon.py --batch -d example.com --crtsh --no-screenshots

# Multiple targets from a file
./passive-subd-recon.py --batch -f domains.txt --subfinder --crtsh --no-screenshots

# Multiple domains on the command line (repeatable flag)
./passive-subd-recon.py --batch -d a.com -d b.com --subfinder --crtsh

# Equivalent technique selection via --tools
./passive-subd-recon.py --batch -d example.com --tools subfinder,crtsh --no-screenshots
```

### Options

| Flag | Description |
|---|---|
| `-d, --domain DOMAIN` | Target domain (repeatable) or path to a domain file. |
| `-f, --file FILE` | File with one domain per line (`#` comments allowed). |
| `--batch` | Non-interactive; all options must be supplied as flags. |
| `--subfinder` | Enable the subfinder technique. |
| `--gau` | Enable the gau technique. |
| `--virustotal` | Enable the VirusTotal technique. |
| `--crtsh` | Enable the crt.sh technique. |
| `--tools LIST` | Comma-separated technique list: `subfinder,gau,virustotal,crtsh`. |
| `--output DIR` | Base output directory (default: `./results`). |
| `--screenshots` / `--no-screenshots` | Enable/disable gowitness screenshots. |
| `--threads N` | gowitness thread count (default: `5`). |
| `--vt-api-key KEY` | VirusTotal API key (overrides env/`.env`). |

## Output

Results are written per domain to `<output>/<domain>/`:

```text
results/
└── example.com/
    ├── subdomains.csv            # subdomain, sources
    ├── subdomains.json           # [ { "subdomain": ..., "sources": [ ... ] } ]
    ├── subdomains.md             # summary + full table
    ├── gowitness-targets.txt     # input fed to gowitness
    ├── gowitness.csv             # gowitness response metadata
    └── screenshots/              # screenshot images
```

### `subdomains.csv`

```csv
subdomain,sources
api.example.com,crtsh|subfinder
www.example.com,subfinder
```

### `subdomains.json`

```json
[
  {
    "subdomain": "api.example.com",
    "sources": ["crtsh", "subfinder"]
  }
]
```

### `subdomains.md`

Contains a summary header (domain, date, total count), a per-source breakdown, the full subdomain table, and an errors section if a technique failed.

## How It Works

```text
        example.com
             │
   asyncio.gather()  (parallel)
      ┌──────┼───────┬──────────┐
 subfinder  gau  VirusTotal  crt.sh
      └──────┼───────┴──────────┘
             ▼
   merge + source-tag + dedupe
             ▼
     CSV / JSON / Markdown
             ▼
      gowitness screenshots
```

- CLI tools (`subfinder`, `gau`) are executed as async subprocesses.
- HTTP APIs (VirusTotal, crt.sh) are queried asynchronously (`aiohttp`, or `urllib` fallback).
- Results are lowercased, validated as hostnames, and filtered to in-scope subdomains (the apex domain itself is excluded).
- VirusTotal pagination is followed via `links.next`; `429` responses honor `Retry-After`.
- crt.sh retries transient `502`s with a short backoff.

## Notes

- **Passive only**: no DNS resolution or direct target scanning is performed, so results may include stale or dead hosts.
- `gau` can be slow depending on Wayback Machine latency; it is given a generous timeout.
- If VirusTotal is selected without an API key, it is skipped with a warning and the run continues.
- Screenshots are taken for **all** discovered subdomains; gowitness tries both `http://` and `https://` for each host.
