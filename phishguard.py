#!/usr/bin/env python3
"""PhishGuard - a simple phishing URL detector (defensive, offline).

Scans URLs for common phishing indicators and gives a risk score (0-100).

Usage:
    python phishguard.py check "http://paypal-secure-login.xyz/verify"
    python phishguard.py scan samples/urls.txt
    python phishguard.py scan samples/urls.txt --csv report.csv
"""
import argparse
import csv
import ipaddress
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip", "country"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
KEYWORDS = ["login", "verify", "secure", "account", "update", "bank", "confirm",
            "password", "signin", "wallet", "paypal", "free", "bonus", "gift"]
BRANDS = ["paypal", "google", "facebook", "amazon", "microsoft", "apple", "netflix", "instagram"]


def analyze_url(url: str) -> dict:
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings = []  # (points, message)

    # 1. IP address instead of domain
    try:
        ipaddress.ip_address(host)
        findings.append((25, "Uses an IP address instead of a domain name"))
    except ValueError:
        pass

    # 2. No HTTPS
    if parsed.scheme != "https":
        findings.append((10, "Does not use HTTPS"))

    # 3. '@' trick
    if "@" in parsed.netloc:
        findings.append((20, "Contains '@' in the address (hides real destination)"))

    # 4. Long URL
    if len(url) > 75:
        findings.append((10, f"Very long URL ({len(url)} characters)"))

    # 5. Too many subdomains
    parts = host.split(".")
    if len(parts) > 4:
        findings.append((15, "Too many subdomains"))

    # 6. Suspicious TLD
    if parts and parts[-1] in SUSPICIOUS_TLDS:
        findings.append((15, f"Suspicious top-level domain (.{parts[-1]})"))

    # 7. Punycode / lookalike
    if "xn--" in host:
        findings.append((20, "Punycode domain (possible lookalike characters)"))

    # 8. Many hyphens
    if host.count("-") >= 3:
        findings.append((10, "Domain contains many hyphens"))

    # 9. Phishing keywords
    hits = [k for k in KEYWORDS if k in url.lower()]
    if hits:
        findings.append((min(5 * len(hits), 20), "Suspicious keywords: " + ", ".join(hits)))

    # 10. Brand name inside a non-brand domain
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for b in BRANDS:
        if b in host and not registered.startswith(b + "."):
            findings.append((25, f"Brand name '{b}' used in an unrelated domain"))
            break

    # 11. URL shortener
    if host in SHORTENERS:
        findings.append((10, "URL shortener hides the real destination"))

    # 12. Digits replacing letters (paypa1, g00gle)
    if re.search(r"[a-z][01][a-z]|[a-z]{2,}[01]{1,2}\.", host):
        findings.append((10, "Digits used inside the domain name (possible lookalike)"))

    score = min(sum(p for p, _ in findings), 100)
    verdict = "SAFE" if score < 25 else "SUSPICIOUS" if score < 50 else "DANGEROUS"
    return {"url": url, "host": host, "score": score, "verdict": verdict,
            "reasons": [m for _, m in findings]}


def print_result(r: dict):
    icon = {"SAFE": "[ OK ]", "SUSPICIOUS": "[WARN]", "DANGEROUS": "[DANGER]"}[r["verdict"]]
    print(f"{icon} {r['verdict']} (score {r['score']}/100) - {r['url']}")
    for reason in r["reasons"]:
        print(f"        - {reason}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="phishguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="check a single URL")
    c.add_argument("url")
    s = sub.add_parser("scan", help="scan a file with one URL per line")
    s.add_argument("file")
    s.add_argument("--csv", help="save results to a CSV file")
    a = p.parse_args(argv)

    if a.cmd == "check":
        print_result(analyze_url(a.url))
    else:
        with open(a.file, encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        results = [analyze_url(u) for u in urls]
        for r in results:
            print_result(r)
        bad = sum(r["verdict"] != "SAFE" for r in results)
        print(f"\nScanned {len(results)} URLs | flagged {bad}")
        if a.csv:
            with open(a.csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["url", "score", "verdict", "reasons"])
                for r in results:
                    w.writerow([r["url"], r["score"], r["verdict"], "; ".join(r["reasons"])])
            print(f"Report saved to {a.csv}")


if __name__ == "__main__":
    main()
