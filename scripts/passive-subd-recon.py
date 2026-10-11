#!/usr/bin/env python3
"""
passive-subd-recon.py - Passive subdomain reconnaissance using multiple techniques.

Techniques:
    * subfinder  - ProjectDiscovery passive subdomain enumerator
    * gau        - GetAllUrls (Wayback/CommonCrawl/OTX/URLScan) subdomain harvesting
    * VirusTotal - /api/v3/domains/<domain>/subdomains (API key required)
    * crt.sh     - Certificate transparency logs (no API key required)

Discovered subdomains are consolidated into CSV, JSON and Markdown reports and
optionally screenshotted with gowitness.

Commands:
    passive-subd-recon.py setup          Install subfinder, gau and gowitness (Go binaries)
    passive-subd-recon.py check          Verify tools are installed and API keys are set
    passive-subd-recon.py                Interactive mode (asks for options, sensible defaults)
    passive-subd-recon.py --batch ...    Non-interactive mode (all options via flags)

Examples:
    # Interactive (recommended)
    ./passive-subd-recon.py

    # Non-interactive: all tools, screenshots on
    ./passive-subd-recon.py --batch -d example.com --subfinder --gau --virustotal --crtsh --screenshots

    # Multiple targets from a file, no screenshots
    ./passive-subd-recon.py --batch -f domains.txt --subfinder --crtsh --no-screenshots
"""

import argparse
import asyncio
import csv
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Optional dependencies (script degrades gracefully if they are missing)
# --------------------------------------------------------------------------- #
try:
    import questionary  # type: ignore
except ImportError:
    questionary = None

try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:
    load_dotenv = None

try:
    import aiohttp  # type: ignore
except ImportError:
    aiohttp = None


# --------------------------------------------------------------------------- #
# Terminal colors
# --------------------------------------------------------------------------- #
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_DIM = "\033[2m"
CLR_RED = "\033[1;31m"
CLR_GREEN = "\033[1;32m"
CLR_YELLOW = "\033[1;33m"
CLR_CYAN = "\033[1;36m"
CLR_MAGENTA = "\033[1;35m"

# Only colorize when attached to a TTY
if not sys.stdout.isatty():
    CLR_RESET = CLR_BOLD = CLR_DIM = CLR_RED = CLR_GREEN = ""
    CLR_YELLOW = CLR_CYAN = CLR_MAGENTA = ""


def visible_len(text):
    """Length of a string ignoring ANSI escape sequences."""
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def pad(text, width):
    """Left-justify accounting for invisible ANSI escape sequences."""
    return str(text) + " " * max(0, width - visible_len(text))


def info(msg):
    print(f"{CLR_CYAN}[*]{CLR_RESET} {msg}")


def ok(msg):
    print(f"{CLR_GREEN}[+]{CLR_RESET} {msg}")


def warn(msg):
    print(f"{CLR_YELLOW}[!]{CLR_RESET} {msg}")


def error(msg):
    print(f"{CLR_RED}[-]{CLR_RESET} {msg}")


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
TOOL_KEYS = ["subfinder", "gau", "virustotal", "crtsh"]
TOOL_LABELS = {
    "subfinder": "subfinder",
    "gau": "gau",
    "virustotal": "VirusTotal (needs API key)",
    "crtsh": "crt.sh",
}

# Go tool release metadata used by the `setup` command.
SETUP_TOOLS = [
    {"name": "subfinder", "repo": "projectdiscovery/subfinder"},
    {"name": "gau", "repo": "lc/gau"},
    {"name": "gowitness", "repo": "sensepost/gowitness"},
]

DEFAULT_OUTPUT_BASE = "./results"
DEFAULT_THREADS = 5

# `<label>.<label>...` hostname matcher (allows a-z 0-9 _ -)
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")
SEMVER_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
VMAJOR_RE = re.compile(r"\bv(\d+)\b")


# --------------------------------------------------------------------------- #
# .env / API key handling
# --------------------------------------------------------------------------- #
def _parse_env_file(path):
    """Minimal .env parser used when python-dotenv is unavailable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except OSError:
        pass


def load_env_files():
    """Load `.env` from the CWD and the script directory (never overrides real env)."""
    candidates = [Path.cwd() / ".env", Path(__file__).resolve().parent / ".env"]
    for path in candidates:
        if not path.is_file():
            continue
        if load_dotenv is not None:
            try:
                load_dotenv(path, override=False)
            except Exception:
                _parse_env_file(path)
        else:
            _parse_env_file(path)


def resolve_vt_key(cli_key=None):
    """Resolve the VirusTotal key: CLI arg > env var > .env. Returns (key, source)."""
    if cli_key:
        return cli_key.strip(), "CLI argument"
    for var in ("VT_API_KEY", "VIRUSTOTAL_API_KEY"):
        value = os.environ.get(var)
        if value:
            return value.strip(), f"environment ({var})"
    return None, None


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def extract_hostnames(values, domain):
    """Normalize raw lines (hostnames or URLs) into in-scope subdomains of `domain`."""
    domain = domain.lower()
    found = set()
    for raw in values:
        if raw is None:
            continue
        for token in re.split(r"[\s,]+", str(raw)):
            token = token.strip()
            if not token:
                continue
            if "://" in token:
                netloc = urllib.parse.urlsplit(token).netloc
            else:
                netloc = token.split("/")[0]
            netloc = netloc.split("@")[-1].split(":")[0]
            netloc = netloc.strip().strip(".").lower()
            if netloc.startswith("*."):
                netloc = netloc[2:]
            if not netloc or not HOST_RE.match(netloc):
                continue
            # Strictly subdomains: exclude the bare apex domain.
            if netloc != domain and netloc.endswith("." + domain):
                found.add(netloc)
    return found


def clean_domain(value):
    """Reduce a user supplied domain/URL to a bare hostname."""
    value = value.strip().lower()
    if "://" in value:
        value = urllib.parse.urlsplit(value).netloc
    value = value.split("/")[0].split(":")[0].split("@")[-1]
    value = value.strip().strip(".").lstrip("*.")
    return value


def read_domains_file(path):
    """Read one domain per line, ignoring blanks and comments."""
    domains = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                dom = clean_domain(line)
                if dom:
                    domains.append(dom)
    except OSError as exc:
        error(f"Cannot read domain file '{path}': {exc}")
    return domains


def parse_domain_input(value):
    """Accept a comma/space separated domain list OR a path to a domain file."""
    value = (value or "").strip()
    if not value:
        return []
    if os.path.isfile(value):
        return read_domains_file(value)
    return [clean_domain(p) for p in re.split(r"[,\s]+", value) if clean_domain(p)]


def dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------- #
# HTTP helpers (aiohttp when available, urllib fallback otherwise)
# --------------------------------------------------------------------------- #
def _urllib_get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, dict(exc.headers)
    except Exception as exc:  # noqa: BLE001 - network errors surface as status 0
        return 0, str(exc), {}


async def http_get(url, headers=None, timeout=30):
    """Async GET returning (status, text, headers)."""
    if aiohttp is not None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    text = await resp.text()
                    return resp.status, text, dict(resp.headers)
        except Exception as exc:  # noqa: BLE001
            return 0, str(exc), {}
    return await asyncio.to_thread(_urllib_get, url, headers, timeout)


async def run_process(cmd, timeout):
    """Run a subprocess and return (stdout, stderr). stdout is None on timeout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return None, f"{cmd[0]} not found"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return None, f"{cmd[0]} timed out after {timeout}s"
    return stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Recon techniques
# --------------------------------------------------------------------------- #
async def recon_subfinder(domain):
    if not shutil.which("subfinder"):
        raise RuntimeError("subfinder not found in PATH")
    stdout, stderr = await run_process(
        ["subfinder", "-d", domain, "-silent"], timeout=300
    )
    if stdout is None:
        raise RuntimeError(stderr.strip() or "subfinder failed")
    return [line for line in stdout.splitlines() if line.strip()]


async def recon_gau(domain):
    if not shutil.which("gau"):
        raise RuntimeError("gau not found in PATH")
    stdout, stderr = await run_process(
        ["gau", "--subs", "--threads", "5", domain], timeout=300
    )
    if stdout is None:
        raise RuntimeError(stderr.strip() or "gau failed")
    return [line for line in stdout.splitlines() if line.strip()]


async def recon_virustotal(domain, api_key):
    if not api_key:
        raise RuntimeError("VirusTotal API key not set")
    headers = {"accept": "application/json", "x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    results = []
    retries = 0
    while url:
        status, text, hdrs = await http_get(url, headers, timeout=45)
        if status == 429:
            retries += 1
            if retries > 3:
                raise RuntimeError("VirusTotal rate limit exceeded")
            try:
                wait = int(hdrs.get("Retry-After", "15") or 15)
            except (TypeError, ValueError):
                wait = 15
            warn(f"VirusTotal rate limited, waiting {wait}s...")
            await asyncio.sleep(wait)
            continue
        if status != 200:
            raise RuntimeError(f"VirusTotal returned HTTP {status}")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError("VirusTotal returned malformed JSON")
        for item in payload.get("data", []) or []:
            identifier = item.get("id")
            if identifier:
                results.append(identifier)
        url = (payload.get("links") or {}).get("next")
        await asyncio.sleep(0.4)
    return results


async def recon_crtsh(domain):
    # crt.sh is notoriously flaky and frequently returns transient 502s, so we
    # retry with a short backoff before giving up.
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last_error = "crt.sh failed"
    for attempt in range(6):
        status, text, _ = await http_get(url, {"accept": "application/json"}, timeout=60)
        if status == 200:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                last_error = "crt.sh returned non-JSON response"
                await asyncio.sleep(4)
                continue
            results = []
            for entry in payload:
                for field in ("name_value", "common_name"):
                    value = entry.get(field)
                    if value:
                        results.extend(str(value).splitlines())
            return results
        last_error = f"crt.sh returned HTTP {status}"
        if attempt < 5:
            await asyncio.sleep(4)
    raise RuntimeError(last_error)


async def gather_subdomains(domain, tools, vt_key):
    """Run every enabled technique concurrently and merge the results."""
    tasks = {}
    if "subfinder" in tools:
        tasks["subfinder"] = asyncio.create_task(recon_subfinder(domain))
    if "gau" in tools:
        tasks["gau"] = asyncio.create_task(recon_gau(domain))
    if "virustotal" in tools:
        tasks["virustotal"] = asyncio.create_task(recon_virustotal(domain, vt_key))
    if "crtsh" in tools:
        tasks["crtsh"] = asyncio.create_task(recon_crtsh(domain))

    merged = defaultdict(set)  # subdomain -> {sources}
    per_source = {}            # source -> distinct count
    errors = {}

    for name, task in tasks.items():
        try:
            raw = await task
        except Exception as exc:  # noqa: BLE001 - one tool must not abort the run
            errors[name] = str(exc)
            per_source[name] = 0
            warn(f"{name}: {exc}")
            continue
        hosts = extract_hostnames(raw, domain)
        for host in hosts:
            merged[host].add(name)
        per_source[name] = len(hosts)
        if hosts:
            ok(f"{name}: {len(hosts)} subdomain(s)")

    return merged, per_source, errors


# --------------------------------------------------------------------------- #
# Output writers
# --------------------------------------------------------------------------- #
def write_outputs(domain, merged, per_source, errors, out_dir, tools):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ordered = sorted(merged.keys())
    csv_path = out_dir / "subdomains.csv"
    json_path = out_dir / "subdomains.json"
    md_path = out_dir / "subdomains.md"

    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["subdomain", "sources"])
        for host in ordered:
            writer.writerow([host, "|".join(sorted(merged[host]))])

    # JSON (array of objects)
    payload = [
        {"subdomain": host, "sources": sorted(merged[host])} for host in ordered
    ]
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    # Markdown
    lines = [
        f"# Passive Subdomain Recon: {domain}",
        "",
        f"- **Domain:** {domain}",
        f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Total unique subdomains:** {len(ordered)}",
        f"- **Techniques:** {', '.join(tools)}",
        "",
        "## Source Breakdown",
        "",
        "| Source | Subdomains |",
        "|---|---|",
    ]
    for name in TOOL_KEYS:
        if name in tools:
            count = per_source.get(name, 0)
            suffix = ""
            if name in errors:
                suffix = " _(failed)_"
            lines.append(f"| {name} | {count}{suffix} |")
    lines += ["", "## Subdomains", ""]
    if ordered:
        lines.append("| # | Subdomain | Sources |")
        lines.append("|---|---|---|")
        for idx, host in enumerate(ordered, 1):
            lines.append(f"| {idx} | `{host}` | {', '.join(sorted(merged[host]))} |")
    else:
        lines.append("_No subdomains were discovered._")

    if errors:
        lines += ["", "## Errors", ""]
        for name, msg in errors.items():
            lines.append(f"- **{name}:** {msg}")

    lines.append("")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return {"csv": csv_path, "json": json_path, "md": md_path}


# --------------------------------------------------------------------------- #
# gowitness screenshots
# --------------------------------------------------------------------------- #
def gowitness_major_version():
    """Return the gowitness major version as an int, or None if undetectable."""
    if not shutil.which("gowitness"):
        return None
    try:
        result = subprocess.run(
            ["gowitness", "version"], capture_output=True, text=True, timeout=20
        )
    except Exception:  # noqa: BLE001
        return None
    blob = (result.stdout or "") + (result.stderr or "")
    match = SEMVER_RE.search(blob) or VMAJOR_RE.search(blob)
    if not match:
        return None
    token = match.group(0).lstrip("v")
    try:
        return int(token.split(".")[0])
    except ValueError:
        return None


def run_gowitness(subdomains, out_dir, threads):
    """Screenshot every subdomain. Returns a short status string."""
    if not shutil.which("gowitness"):
        return "skipped (gowitness not found)"

    out_dir = Path(out_dir)
    shots_dir = out_dir / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "gowitness-targets.txt"
    csv_file = out_dir / "gowitness.csv"

    with open(targets_file, "w", encoding="utf-8") as fh:
        for host in subdomains:
            fh.write(host + "\n")

    major = gowitness_major_version()
    if major == 2:
        cmd = [
            "gowitness", "file",
            "-f", str(targets_file),
            "-P", str(shots_dir),
            "-t", str(threads),
        ]
    else:  # v3 and newer
        cmd = [
            "gowitness", "scan", "file",
            "-f", str(targets_file),
            "-s", str(shots_dir),
            "-t", str(threads),
            "--write-csv",
            "--write-csv-file", str(csv_file),
        ]

    info(f"Running gowitness ({len(subdomains)} target(s), {threads} threads)...")
    print(f"{CLR_DIM}$ {' '.join(cmd)}{CLR_RESET}")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        warn("gowitness interrupted by user")
    except Exception as exc:  # noqa: BLE001
        return f"failed ({exc})"
    return f"done -> {shots_dir}"


# --------------------------------------------------------------------------- #
# check command
# --------------------------------------------------------------------------- #
def detect_tool_version(name):
    """Return (path, version) for a tool, or (None, None) if not installed."""
    path = shutil.which(name)
    if not path:
        return None, None
    invocations = {
        "subfinder": [[name, "-version"]],
        "gau": [[name, "--version"], [name, "-version"]],
        "gowitness": [[name, "version"]],
    }.get(name, [[name, "--version"], [name, "-version"]])
    for cmd in invocations:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except Exception:  # noqa: BLE001
            continue
        blob = (result.stdout or "") + (result.stderr or "")
        match = SEMVER_RE.search(blob) or VMAJOR_RE.search(blob)
        if match:
            return path, match.group(0)
    return path, "unknown"


def cmd_check(argv):
    parser = argparse.ArgumentParser(
        prog="passive-subd-recon.py check",
        description="Check that recon tools are installed and API keys are set.",
    )
    parser.add_argument("--vt-api-key", help="VirusTotal API key to validate")
    args = parser.parse_args(argv)

    print(f"\n{CLR_BOLD}== Tool check =={CLR_RESET}\n")
    print(f"{CLR_BOLD}{pad('Tool', 12)}{pad('Status', 16)}{pad('Version', 14)}Location{CLR_RESET}")
    print("-" * 70)
    all_ok = True
    for name in ("subfinder", "gau", "gowitness"):
        path, version = detect_tool_version(name)
        if path:
            status = f"{CLR_GREEN}found{CLR_RESET}"
            location = path
        else:
            status = f"{CLR_RED}missing{CLR_RESET}"
            version = "-"
            location = "run 'passive-subd-recon.py setup'"
            all_ok = False
        print(f"{pad(name, 12)}{pad(status, 16)}{pad(version, 14)}{location}")

    print(f"\n{CLR_BOLD}== API key check =={CLR_RESET}\n")
    key, source = resolve_vt_key(args.vt_api_key)
    if not key:
        warn(f"{pad('VirusTotal', 12)} "
             f"{CLR_RED}not set{CLR_RESET} (set VT_API_KEY or add to .env)")
        all_ok = False
    elif re.fullmatch(r"[0-9a-fA-F]{64}", key):
        ok(f"{pad('VirusTotal', 12)} set and well-formed ({source})")
    else:
        warn(f"{pad('VirusTotal', 12)} set ({source}) "
             "but not the expected 64-char hex format")
    ok(f"{pad('crt.sh', 12)} no API key required")

    print()
    if all_ok:
        ok("All checks passed.")
    else:
        warn("Some checks failed. Review the output above.")
    return 0 if all_ok else 1


# --------------------------------------------------------------------------- #
# setup command (download Go binaries from GitHub releases)
# --------------------------------------------------------------------------- #
def github_latest_release(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "passive-subd-recon-setup"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def pick_release_asset(assets, tool):
    """Pick the linux/amd64 asset for a tool. Returns (name, url) or (None, None)."""
    candidates = []
    for asset in assets:
        name = asset.get("name", "")
        lower = name.lower()
        if not lower:
            continue
        if "checksums" in lower or lower.endswith((".sig", ".sha256", ".txt")):
            continue
        if "linux" not in lower:
            continue
        if not any(tag in lower for tag in ("amd64", "x86_64")):
            continue
        if "arm" in lower:
            continue
        url = asset.get("browser_download_url")
        if url:
            candidates.append((name, url))
    if not candidates:
        return None, None
    for name, url in candidates:
        if tool in name.lower():
            return name, url
    return candidates[0]


def download_file(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "passive-subd-recon-setup"})
    with urllib.request.urlopen(req, timeout=180) as resp, open(dest, "wb") as fh:
        shutil.copyfileobj(resp, fh)


def _pick_member(names, tool):
    for name in names:
        if os.path.basename(name) == tool:
            return name
    for name in names:
        if os.path.basename(name).startswith(tool):
            return name
    return None


def extract_asset(url, archive_name, tool, workdir):
    """Download an asset and return the path to the extracted binary."""
    workdir = Path(workdir)
    archive_path = workdir / archive_name
    download_file(url, archive_path)
    lower = archive_name.lower()

    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            member = _pick_member(zf.namelist(), tool)
            if member is None:
                raise RuntimeError(f"no '{tool}' binary inside {archive_name}")
            zf.extract(member, workdir)
            return workdir / member

    if lower.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path) as tf:
            member = _pick_member(tf.getnames(), tool)
            if member is None:
                raise RuntimeError(f"no '{tool}' binary inside {archive_name}")
            try:
                tf.extract(member, workdir, filter="data")
            except TypeError:  # Python < 3.12 has no `filter` argument
                tf.extract(member, workdir)
            return workdir / member

    # Raw binary (e.g. gowitness releases)
    return archive_path


def install_tool(spec, install_dir, force):
    tool = spec["name"]
    dest = install_dir / tool

    if dest.exists() and not force:
        warn(f"{tool}: already present at {dest} (use --force to reinstall)")
        return True

    info(f"{tool}: fetching latest release from {spec['repo']}...")
    try:
        release = github_latest_release(spec["repo"])
    except Exception as exc:  # noqa: BLE001
        error(f"{tool}: could not query GitHub releases ({exc})")
        return False

    tag = release.get("tag_name", "?")
    asset_name, asset_url = pick_release_asset(release.get("assets", []), tool)
    if not asset_url:
        error(f"{tool}: no linux/amd64 asset found in release {tag}")
        return False

    with tempfile.TemporaryDirectory() as tmp:
        try:
            binary = extract_asset(asset_url, asset_name, tool, tmp)
        except Exception as exc:  # noqa: BLE001
            error(f"{tool}: failed to extract {asset_name} ({exc})")
            return False
        try:
            os.chmod(binary, 0o755)
            install_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(binary), str(dest))
        except OSError as exc:
            error(f"{tool}: could not install to {dest} ({exc})")
            return False

    ok(f"{tool}: installed {tag} -> {dest}")
    return True


def install_python_deps():
    """Best-effort install of the optional Python dependencies."""
    deps = ["questionary", "python-dotenv", "aiohttp"]
    info(f"Installing Python dependencies: {', '.join(deps)}")
    attempts = [
        [sys.executable, "-m", "pip", "install", "--user", *deps],
        # Kali/Debian mark the system Python as externally managed (PEP 668).
        [sys.executable, "-m", "pip", "install", "--user",
         "--break-system-packages", *deps],
    ]
    for cmd in attempts:
        try:
            result = subprocess.run(cmd, check=False)
        except Exception as exc:  # noqa: BLE001
            warn(f"Could not run pip ({exc}).")
            continue
        if result.returncode == 0:
            ok("Python dependencies installed.")
            return
    warn("pip install failed. Try a virtualenv or install manually.")


def cmd_setup(argv):
    parser = argparse.ArgumentParser(
        prog="passive-subd-recon.py setup",
        description="Download and install subfinder, gau and gowitness.",
    )
    parser.add_argument(
        "--install-dir",
        default=str(Path.home() / ".local" / "bin"),
        help="Directory to install binaries into (default: ~/.local/bin)",
    )
    parser.add_argument("--force", action="store_true", help="Reinstall existing tools")
    parser.add_argument(
        "--no-python-deps",
        action="store_true",
        help="Skip installing questionary/python-dotenv/aiohttp",
    )
    args = parser.parse_args(argv)

    install_dir = Path(os.path.expanduser(args.install_dir))
    print(f"\n{CLR_BOLD}== Installing recon tools into {install_dir} =={CLR_RESET}\n")

    results = []
    for spec in SETUP_TOOLS:
        results.append((spec["name"], install_tool(spec, install_dir, args.force)))

    if not args.no_python_deps:
        print()
        install_python_deps()

    print()
    if str(install_dir) not in os.environ.get("PATH", "").split(os.pathsep):
        warn(f"{install_dir} is not in your PATH.")
        warn(f'Add it with: export PATH="{install_dir}:$PATH"')
    else:
        ok(f"{install_dir} is already in PATH.")

    failed = [name for name, okd in results if not okd]
    if failed:
        error(f"Failed to install: {', '.join(failed)}")
        return 1
    ok("Setup complete.")
    return 0


# --------------------------------------------------------------------------- #
# Interactive prompts (questionary when available, input() fallback otherwise)
# --------------------------------------------------------------------------- #
def prompt_text(message, default=""):
    if questionary is not None:
        answer = questionary.text(message, default=default).ask()
        if answer is None:
            raise KeyboardInterrupt
        return answer.strip()
    raw = input(f"{message} [{default}]: ").strip()
    return raw or default


def prompt_password(message):
    if questionary is not None:
        answer = questionary.password(message).ask()
        if answer is None:
            raise KeyboardInterrupt
        return answer.strip()
    return getpass.getpass(f"{message}: ").strip()


def prompt_confirm(message, default=True):
    if questionary is not None:
        answer = questionary.confirm(message, default=default).ask()
        if answer is None:
            raise KeyboardInterrupt
        return answer
    hint = "Y/n" if default else "y/N"
    raw = input(f"{message} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def prompt_int(message, default):
    while True:
        raw = prompt_text(message, str(default))
        try:
            value = int(raw)
            if value < 1:
                raise ValueError
            return value
        except ValueError:
            warn("Please enter a positive integer.")


def prompt_checkbox(message, choices, default_keys):
    """choices: list of (key, label). Returns selected keys."""
    if questionary is not None:
        opts = [
            questionary.Choice(title=label, value=key, checked=(key in default_keys))
            for key, label in choices
        ]
        answer = questionary.checkbox(message, choices=opts).ask()
        if answer is None:
            raise KeyboardInterrupt
        return answer
    print(message)
    for idx, (key, label) in enumerate(choices, 1):
        mark = "x" if key in default_keys else " "
        print(f"  [{mark}] {idx}. {label}")
    raw = input("Select by number (comma separated) [Enter = defaults]: ").strip()
    if not raw:
        return list(default_keys)
    selected = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= len(choices):
            selected.append(choices[int(part) - 1][0])
    return selected


def interactive_config(args, vt_key):
    print(f"\n{CLR_BOLD}{CLR_MAGENTA}Passive Subdomain Recon{CLR_RESET}")
    print(f"{CLR_DIM}Interactive setup - press Enter to accept the default.{CLR_RESET}\n")

    # 1. Domain(s)
    preset = args.domain[0] if args.domain else ""
    domains = []
    while not domains:
        raw = prompt_text("Target domain(s), comma-separated, or path to a file", preset)
        domains = parse_domain_input(raw)
        if not domains:
            warn("No valid domain provided. Try again.")
    ok(f"Targets: {', '.join(domains)}")

    # 2. Techniques
    choices = [(key, TOOL_LABELS[key]) for key in TOOL_KEYS]
    tools = prompt_checkbox("\nSelect passive recon techniques:", choices, list(TOOL_KEYS))
    if not tools:
        warn("No techniques selected; enabling all by default.")
        tools = list(TOOL_KEYS)
    ok(f"Techniques: {', '.join(tools)}")

    # 3. VirusTotal key
    if "virustotal" in tools and not vt_key:
        vt_key = prompt_password("\nVirusTotal API key (leave blank to skip VirusTotal)")
        if not vt_key:
            warn("No API key provided; disabling VirusTotal for this run.")
            tools = [t for t in tools if t != "virustotal"]

    # 4. Output directory
    outdir = prompt_text(
        "\nBase output directory (a per-domain subfolder is created)",
        args.output,
    )

    # 5. Screenshots
    if args.screenshots is None:
        screenshots = prompt_confirm("\nTake screenshots with gowitness?", True)
    else:
        screenshots = args.screenshots

    threads = args.threads
    if screenshots:
        threads = prompt_int("Gowitness thread count", args.threads or DEFAULT_THREADS)

    return domains, tools, vt_key, outdir, screenshots, threads


# --------------------------------------------------------------------------- #
# Run command
# --------------------------------------------------------------------------- #
def cmd_run(argv):
    parser = argparse.ArgumentParser(
        prog="passive-subd-recon.py",
        description="Passive subdomain reconnaissance (subfinder, gau, VirusTotal, crt.sh).",
    )
    parser.add_argument("-d", "--domain", action="append", default=[],
                        help="Target domain (repeatable) or path to a domain file")
    parser.add_argument("-f", "--file", help="File with one domain per line")
    parser.add_argument("--batch", action="store_true",
                        help="Non-interactive; all options must be supplied as flags")
    parser.add_argument("--subfinder", action="store_true", help="Enable subfinder")
    parser.add_argument("--gau", action="store_true", help="Enable gau")
    parser.add_argument("--virustotal", action="store_true", help="Enable VirusTotal")
    parser.add_argument("--crtsh", action="store_true", help="Enable crt.sh")
    parser.add_argument("--tools", help="Comma-separated techniques: subfinder,gau,virustotal,crtsh")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_BASE,
                        help=f"Base output directory (default: {DEFAULT_OUTPUT_BASE})")
    shot_group = parser.add_mutually_exclusive_group()
    shot_group.add_argument("--screenshots", dest="screenshots", action="store_true",
                            help="Screenshot subdomains with gowitness")
    shot_group.add_argument("--no-screenshots", dest="screenshots", action="store_false",
                            help="Skip gowitness screenshots")
    parser.set_defaults(screenshots=None)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Gowitness thread count (default: {DEFAULT_THREADS})")
    parser.add_argument("--vt-api-key", help="VirusTotal API key (overrides env/.env)")
    args = parser.parse_args(argv)

    vt_key, _ = resolve_vt_key(args.vt_api_key)

    if args.batch:
        domains = dedupe(
            [d for item in args.domain for d in parse_domain_input(item)]
            + (read_domains_file(args.file) if args.file else [])
        )
        tools = set()
        for key in TOOL_KEYS:
            if getattr(args, key):
                tools.add(key)
        if args.tools:
            for token in args.tools.split(","):
                token = token.strip().lower()
                if token in TOOL_KEYS:
                    tools.add(token)
                elif token:
                    warn(f"Unknown technique ignored: {token}")
        tools = [key for key in TOOL_KEYS if key in tools]
        screenshots = bool(args.screenshots)  # default False in batch mode
        threads = args.threads
        outdir = args.output

        if not domains:
            error("Batch mode requires at least one target (-d/--domain or -f/--file).")
            return 2
        if not tools:
            error("Batch mode requires at least one technique "
                  "(--subfinder/--gau/--virustotal/--crtsh or --tools).")
            return 2
    else:
        if not sys.stdin.isatty():
            error("Not a TTY. Use --batch with explicit flags for non-interactive runs.")
            return 2
        try:
            (domains, tools, vt_key, outdir, screenshots, threads) = interactive_config(
                args, vt_key
            )
        except KeyboardInterrupt:
            print()
            warn("Cancelled by user.")
            return 130

    if "virustotal" in tools and not vt_key:
        warn("VirusTotal selected but no API key found; it will be skipped.")
        tools = [t for t in tools if t != "virustotal"]

    print(f"\n{CLR_BOLD}== Recon plan =={CLR_RESET}")
    print(f"  Targets     : {', '.join(domains)}")
    print(f"  Techniques  : {', '.join(tools) if tools else '(none)'}")
    print(f"  Output base : {outdir}")
    print(f"  Screenshots : {'yes' if screenshots else 'no'}"
          + (f" (threads: {threads})" if screenshots else ""))
    print()

    if not tools:
        error("No techniques to run. Nothing to do.")
        return 2

    for domain in domains:
        run_single_domain(domain, tools, vt_key, outdir, screenshots, threads)
    return 0


def run_single_domain(domain, tools, vt_key, outdir, screenshots, threads):
    print(f"{CLR_BOLD}{CLR_CYAN}=== {domain} ==={CLR_RESET}")
    info(f"Running {len(tools)} technique(s) in parallel...")

    merged, per_source, errors = asyncio.run(gather_subdomains(domain, tools, vt_key))

    domain_dir = Path(outdir) / domain
    paths = write_outputs(domain, merged, per_source, errors, domain_dir, tools)

    ok(f"{len(merged)} unique subdomain(s) discovered")
    print(f"  CSV      : {paths['csv']}")
    print(f"  JSON     : {paths['json']}")
    print(f"  Markdown : {paths['md']}")

    if screenshots and merged:
        status = run_gowitness(sorted(merged.keys()), domain_dir, threads)
        ok(f"Screenshots: {status}")
    elif screenshots:
        warn("No subdomains to screenshot.")
    print()


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    load_env_files()
    argv = sys.argv[1:]
    try:
        if argv and argv[0] == "setup":
            return cmd_setup(argv[1:])
        if argv and argv[0] == "check":
            return cmd_check(argv[1:])
        return cmd_run(argv)
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
