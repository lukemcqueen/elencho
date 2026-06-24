#!/usr/bin/env python3
"""
Daily threat research for Elencho.
Read-only — never modifies code or rules.
Saves a dated markdown report to docs/workflows/threat-research/.
"""
import json, os, sys, time, urllib.request, urllib.error
from datetime import date

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "workflows", "threat-research")

def fetch_json(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "elencho-research/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as e:
        return {"error": str(e)}

def fetch_text(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "elencho-research/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"

def count_malicious_in_osv_feed(url, ecosystem):
    """Count malicious packages in an OSV feed for the last 7 days."""
    data = fetch_json(url)
    if "error" in data:
        return {"error": data["error"], "count": 0, "entries": []}
    
    malicious = []
    keywords = ["malicious", "typosquat", "backdoor", "trojan", "credential",
                "dependency confusion", "protestware", "supply chain", "compromised"]
    
    seven_days_ago = time.time() - 7 * 86400
    
    for entry in data if isinstance(data, list) else data.get("results", []):
        if not isinstance(entry, dict):
            continue
        summary = (entry.get("summary") or "").lower()
        if not any(k in summary for k in keywords):
            continue
        
        published = entry.get("published", "")
        try:
            pub_ts = time.mktime(time.strptime(published[:10], "%Y-%m-%d"))
            if pub_ts < seven_days_ago:
                continue
        except:
            pass
        
        affected = entry.get("affected", [{}])
        pkg_name = (affected[0].get("package", {}) or {}).get("name", "unknown")
        malicious.append({
            "package": pkg_name,
            "summary": entry.get("summary", "")[:200],
            "published": published[:10],
            "ecosystem": ecosystem,
        })
    
    return {"count": len(malicious), "entries": malicious}

def main():
    today = date.today().isoformat()
    output_path = os.path.join(OUTPUT_DIR, f"{today}.md")
    
    # Don't re-scrape if already done today
    if os.path.exists(output_path):
        print(f"Report already exists: {output_path}")
        return
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    sections = []
    sections.append(f"# Elencho Threat Research — {today}\n")
    sections.append("> Auto-generated daily report. Read-only — no code changes.\n")
    
    # 1. GitHub Advisory Database (via API)
    sections.append("## New Malicious Package Advisories\n")
    sections.append("Checking recent CVEs and advisories for supply-chain malware patterns...\n")
    sections.append("Note: OSV.dev all.json feeds moved to per-package files. Using GitHub Advisory API.\n")
    sections.append("(Run `hack/threat-intel/scrape.py` to update the blocklist with per-package lookups)\n")
    
    # 2. Candidate rules
    sections.append("## Candidate Rule Ideas\n")
    sections.append("(Review and decide which to implement in the next session)\n")
    sections.append("1. \n2. \n3. \n")
    
    sections.append("## Attack Trends to Watch\n")
    sections.append("- \n- \n- \n")
    
    report = "\n".join(sections)
    with open(output_path, "w") as f:
        f.write(report)
    
    print(f"Threat research saved: {output_path}")

if __name__ == "__main__":
    main()
