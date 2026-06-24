#!/usr/bin/env python3
"""
Threat intel feed scraper for Elencho.

Scrapes npm advisory DB, PyPI advisory DB, and GitHub Advisory Database
for newly reported malicious packages and generates an updated
known-malicious.yaml blocklist.

Usage:
  python3 hack/threat-intel/scrape.py
  python3 hack/threat-intel/scrape.py --output internal/scan/rules/known-malicious.yaml

Requires: pip install requests pyyaml
"""

import argparse
import hashlib
import json
import os
import sys
import time
import yaml

# ── npm advisory OSV feed ──────────────────────────────────────────────
NPM_OSV_FEED = "https://storage.googleapis.com/osv-vulnerabilities/npm/all.json"
PYPI_OSV_FEED = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.json"
GO_OSV_FEED = "https://storage.googleapis.com/osv-vulnerabilities/Go/all.json"

# Current known-malicious YAML path
DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(__file__), "..", "..", "internal", "scan", "rules", "known-malicious.yaml"
)


def fetch_json(url: str) -> list:
    """Fetch a JSON array from URL. Returns empty list on failure."""
    import urllib.request

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "elencho-threat-intel/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
        return []


def parse_npm_advisories(entries: list) -> list:
    """Extract malicious npm packages from OSV feed."""
    results = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Filter for malicious intent packages
        summary = (entry.get("summary") or "").lower()
        aliases = " ".join(entry.get("aliases", []) or []).lower()
        keywords = ["malicious", "typosquat", "dependency confusion", "protestware",
                     "backdoor", "trojan", "credential theft", "data exfiltration",
                     "supply chain", "compromised"]
        if not any(k in summary or k in aliases for k in keywords):
            continue

        affected = entry.get("affected", [])
        if not affected:
            continue
        pkg_info = affected[0]
        pkg_name = (pkg_info.get("package", {}) or {}).get("name", "")

        if not pkg_name:
            continue

        versions = []
        ranges = pkg_info.get("ranges", []) or []
        for r in ranges:
            for event in r.get("events", []) or []:
                if "introduced" in event:
                    versions.append(event["introduced"])
                if "fixed" in event:
                    versions.append(event["fixed"])

        results.append({
            "name": pkg_name,
            "ecosystem": "npm",
            "versions": list(set(v for v in versions if v and v != "0")),
            "notes": entry.get("summary", "Malicious package"),
            "discovered": (entry.get("published") or "")[:10],
        })
    return results


def parse_pypi_advisories(entries: list) -> list:
    """Extract malicious PyPI packages from OSV feed."""
    results = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        summary = (entry.get("summary") or "").lower()
        keywords = ["malicious", "typosquat", "dependency confusion",
                     "backdoor", "trojan", "credential theft"]
        if not any(k in summary for k in keywords):
            continue

        affected = entry.get("affected", [])
        if not affected:
            continue
        pkg_info = affected[0]
        pkg_name = (pkg_info.get("package", {}) or {}).get("name", "")
        if not pkg_name:
            continue

        results.append({
            "name": pkg_name.lower(),
            "ecosystem": "pypi",
            "versions": [],
            "notes": entry.get("summary", "Malicious package"),
            "discovered": (entry.get("published") or "")[:10],
        })
    return results


def parse_go_advisories(entries: list) -> list:
    """Extract malicious Go modules from OSV feed."""
    results = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        summary = (entry.get("summary") or "").lower()
        keywords = ["malicious", "backdoor", "trojan", "compromised",
                     "credential theft", "supply chain"]
        if not any(k in summary for k in keywords):
            continue

        affected = entry.get("affected", [])
        if not affected:
            continue
        pkg_info = affected[0]
        module = (pkg_info.get("package", {}) or {}).get("name", "")
        if not module or not module.startswith("github.com/"):
            continue

        results.append({
            "name": module,
            "ecosystem": "go",
            "versions": [],
            "notes": entry.get("summary", "Malicious module"),
            "discovered": (entry.get("published") or "")[:10],
        })
    return results


def load_existing(path: str) -> dict:
    """Load the existing known-malicious.yaml, return {ecosystem: {name: entry}}."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        data = yaml.safe_load(f)
    existing = {}
    for pkg in (data.get("packages") or []):
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if ecosystem and name:
            key = f"{ecosystem}:{name}"
            existing[key] = pkg
    return existing


def merge_and_write(existing: dict, new_entries: list, output_path: str):
    """Merge new entries into existing blocklist and write YAML."""
    for entry in new_entries:
        key = f"{entry['ecosystem']}:{entry['name']}"
        if key not in existing:
            existing[key] = entry
            print(f"  [+] New: [{entry['ecosystem']}] {entry['name']} — {entry['notes'][:60]}")

    # Sort: ecosystem then name
    sorted_pkgs = sorted(existing.values(), key=lambda p: (p["ecosystem"], p["name"]))

    output = {
        "version": 1,
        "packages": sorted_pkgs,
    }

    with open(output_path, "w") as f:
        yaml.dump(output, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"\n  ✓ Wrote {len(sorted_pkgs)} packages to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Elencho threat intel feed scraper")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output YAML path")
    parser.add_argument("--npm", action="store_true", help="Scrape npm advisories")
    parser.add_argument("--pypi", action="store_true", help="Scrape PyPI advisories")
    parser.add_argument("--go", action="store_true", help="Scrape Go advisories")
    parser.add_argument("--all", action="store_true", default=True, help="Scrape all feeds (default)")
    args = parser.parse_args()

    existing = load_existing(args.output)
    print(f"Loaded {len(existing)} existing entries")

    if args.all or args.npm:
        print("\nScraping npm advisories...")
        entries = fetch_json(NPM_OSV_FEED)
        new = parse_npm_advisories(entries)
        merge_and_write(existing, new, args.output)

    if args.all or args.pypi:
        print("\nScraping PyPI advisories...")
        entries = fetch_json(PYPI_OSV_FEED)
        new = parse_pypi_advisories(entries)
        merge_and_write(existing, new, args.output)

    if args.all or args.go:
        print("\nScraping Go advisories...")
        entries = fetch_json(GO_OSV_FEED)
        new = parse_go_advisories(entries)
        merge_and_write(existing, new, args.output)

    print("\nDone. Run 'make sign' to sign the updated blocklist.")


if __name__ == "__main__":
    main()
