#!/usr/bin/env python3
"""
Mobile Application Security Testing Framework

Educational static APK indicator scanner.
Use only with applications you own or are authorized to assess.
"""

import argparse
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path


RISKY_STORAGE_PATTERNS = [
    (r"sharedpreferences", "SharedPreferences usage detected"),
    (r"getsharedpreferences", "getSharedPreferences usage detected"),
    (r"sqlite", "SQLite usage detected"),
    (r"getdatabasepath", "Local database path usage detected"),
    (r"\.db\b", "Database file reference detected"),
]

AUTH_PATTERNS = [
    (r"authorization", "Authorization header/reference detected"),
    (r"bearer\s+", "Bearer-token reference detected"),
    (r"password", "Password-related string detected"),
    (r"token", "Token-related string detected"),
    (r"session", "Session-related string detected"),
]

API_PATTERNS = [
    (r"https?://", "HTTP/HTTPS URL detected"),
    (r"api/", "API path indicator detected"),
    (r"rest/", "REST path indicator detected"),
    (r"graphql", "GraphQL indicator detected"),
]

INSECURE_URL_PATTERNS = [
    (r"http://", "Unencrypted HTTP URL detected"),
    (r"ssl\.", "SSL-related string detected"),
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_apk(apk_path):
    """Return selected text-like APK contents for safe static inspection."""
    data = {}
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            lower = name.lower()
            if (
                lower.endswith((".xml", ".txt", ".json", ".properties", ".smali"))
                or "assets/" in lower
                or "res/" in lower
            ):
                try:
                    raw = z.read(name)
                    data[name] = raw.decode("utf-8", errors="ignore")
                except Exception:
                    continue
    return data


def find_patterns(text, patterns):
    hits = []
    lower = text.lower()
    for pattern, description in patterns:
        if re.search(pattern, lower):
            hits.append(description)
    return hits


def extract_urls(text):
    return sorted(set(re.findall(r"https?://[^\s\"'<>]+", text, flags=re.I)))


def scan(apk_path):
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        raise ValueError("Input file must have an .apk extension.")

    contents = read_apk(apk_path)
    combined = "\n".join(contents.values())

    storage = find_patterns(combined, RISKY_STORAGE_PATTERNS)
    auth = find_patterns(combined, AUTH_PATTERNS)
    api = find_patterns(combined, API_PATTERNS)
    insecure = find_patterns(combined, INSECURE_URL_PATTERNS)
    urls = extract_urls(combined)

    findings = []

    if storage:
        findings.append({
            "category": "Insecure Data Storage",
            "owasp_mobile": "MSTG-STORAGE",
            "severity": "Review",
            "evidence": storage,
            "recommendation": "Review whether sensitive data is stored locally without appropriate protection."
        })

    if auth:
        findings.append({
            "category": "Authentication / Session Indicators",
            "owasp_mobile": "MSTG-AUTH",
            "severity": "Review",
            "evidence": auth,
            "recommendation": "Review authentication, authorization, credential and session handling in MobSF and the test environment."
        })

    if api:
        findings.append({
            "category": "API / Network Indicators",
            "owasp_mobile": "MSTG-NETWORK",
            "severity": "Review",
            "evidence": api,
            "recommendation": "Review API endpoints, transport security, certificate validation and authorization using Burp Suite and MobSF."
        })

    if insecure:
        findings.append({
            "category": "Potential Insecure Transport",
            "owasp_mobile": "MSTG-NETWORK",
            "severity": "High review priority",
            "evidence": insecure,
            "recommendation": "Investigate HTTP endpoints and confirm whether sensitive traffic is protected by HTTPS."
        })

    return {
        "project": "Mobile Application Security Testing Framework",
        "scan_time_utc": datetime.utcnow().isoformat() + "Z",
        "apk": apk_path.name,
        "sha256": sha256_file(apk_path),
        "files_inspected": len(contents),
        "urls_detected": urls[:100],
        "findings": findings,
        "limitations": [
            "This is static indicator analysis, not proof of exploitability.",
            "Binary/compiled resources may not decode completely.",
            "Findings require manual validation in MobSF, Android Studio, Frida and Burp Suite.",
            "Only authorized applications should be tested."
        ],
    }


def print_report(report):
    print("\n=== Mobile Application Security Testing Framework ===")
    print(f"APK: {report['apk']}")
    print(f"SHA-256: {report['sha256']}")
    print(f"Files inspected: {report['files_inspected']}")
    print(f"Findings: {len(report['findings'])}")

    if not report["findings"]:
        print("\nNo static indicators were detected by this basic scanner.")
    else:
        print("\nFindings:")
        for i, finding in enumerate(report["findings"], 1):
            print(f"\n{i}. {finding['category']}")
            print(f"   Priority: {finding['severity']}")
            print(f"   OWASP/MSTG: {finding['owasp_mobile']}")
            print(f"   Evidence: {', '.join(finding['evidence'])}")
            print(f"   Recommendation: {finding['recommendation']}")

    if report["urls_detected"]:
        print("\nDetected URLs:")
        for url in report["urls_detected"][:20]:
            print(f" - {url}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic static indicator scanner for an authorized Android APK."
    )
    parser.add_argument("--apk", required=True, help="Path to the authorized APK file")
    parser.add_argument(
        "--output",
        default="reports/mobile_security_report.json",
        help="JSON report output path"
    )
    args = parser.parse_args()

    try:
        report = scan(args.apk)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print_report(report)
        print(f"\nJSON report saved to: {output}")
    except (FileNotFoundError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
