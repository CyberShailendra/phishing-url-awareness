# EWB Phishing URL Awareness Checker (Advanced Edition)
# Author: Shailendra Mourya (CyberShailendra) | cybershailendra1@gmail.com
# Safe & Offline: No network requests, zero internet probing.

import re
from urllib.parse import urlparse

# ANSI terminal colors for enhanced cyber-terminal UI
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
GRAY = "\033[90m"

INFO_MESSAGES = (
    "No URL entered",
    "Could not identify",
    "No listed warning",
    "This text is not a valid",
)

# Core & Advanced warning explanations
REASONS = {
    "Contains an @ symbol": "The browser ignores text before @.",
    "Unusually long URL": "Long links can hide the real destination far to the right.",
    "Uses an IP address": "Honest services normally use readable names, not numbers.",
    "Contains many hostname": "Stacking names like a.b.c.d.e makes a link look official.",
    "Contains a punycode": "xn-- can hide look-alike foreign letters.",
    "Uses HTTP": "HTTP is not encrypted, so data can be seen on the way.",
    "Uses a known URL shortener": "URL shorteners hide the real destination domain.",
    "Uses a high-risk TLD": "Free/abused TLDs are frequently preferred in mass phishing campaigns.",
    "Suspicious keywords detected": "Keywords like 'login', 'verify' or 'secure' in the path/subdomain can be bait.",
    "Excessive hyphens in domain": "Multiple hyphens are often used in brand-impersonating fake domains.",
}

# Weighted scoring for heuristic assessment
WEIGHTS = {
    "Contains an @ symbol": 25,
    "Unusually long URL": 15,
    "Uses an IP address": 30,
    "Contains many hostname segments": 20,
    "Contains a punycode": 25,
    "Uses HTTP": 15,
    "Uses a known URL shortener": 20,
    "Uses a high-risk TLD": 20,
    "Suspicious keywords detected": 20,
    "Excessive hyphens in domain": 15,
}

# High-risk / frequently abused TLDs (offline heuristics)
HIGH_RISK_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work", ".click"}

# Common URL shorteners (hiding destination)
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl", "ow.ly"}

# Common keywords abused in phishing lures
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "banking", "update", "wallet", "signin", "kyc", "password"]


def inspect_url(raw_url):
    """
    Check visible URL text for selected warning signs.
    Fully maintains the 6 base requirements from the workbook,
    plus safe offline advanced heuristics.
    """
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    candidate = url if "://" in url else "http://" + url

    # Improvement C: stop crashes on malformed input
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return ["This text is not a valid URL format."]

    if not host:
        return ["Could not identify a hostname."]

    # === BASE WORKBOOK CHECKS (Preserved exactly for test compliance) ===

    # Check 1: @ symbol
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # Check 2: Length > 100
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # Check 3: IP address hostname
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        findings.append("Uses an IP address instead of a familiar domain.")

    # Check 4: Hostname segments (>= 5)
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # Check 5: Punycode
    if "xn--" in host:
        findings.append("Contains a punycode-style hostname.")

    # Check 6: HTTP scheme
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    # === ADVANCED OFFLINE HEURISTICS ===

    # Check 7: Known URL shortener
    if host in URL_SHORTENERS:
        findings.append("Uses a known URL shortener service (destination is masked).")

    # Check 8: High-risk TLD check
    for tld in HIGH_RISK_TLDS:
        if host.endswith(tld):
            findings.append(f"Uses a high-risk TLD ({tld}) often associated with low-cost spam/phishing.")
            break

    # Check 9: Excessive hyphens in domain (e.g. paypal-security-update-center.com)
    if host.count("-") >= 3:
        findings.append("Excessive hyphens in domain name (common in fake brand impersonation).")

    # Check 10: Suspicious keyword presence in path, query, or subdomains
    full_path_query = (parsed.path + parsed.query).lower()
    matched_words = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path_query or (kw in host and not host.endswith(kw))]
    if matched_words and not host.endswith(("example.com", "example.invalid")):
        findings.append(f"Suspicious keywords detected in URL: {', '.join(set(matched_words))}.")

    # Clean check
    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings


def calculate_risk_score(findings):
    """Calculates a risk score from 0 to 100 based on weighted heuristics."""
    if not has_warnings(findings):
        return 0, "LOW", GREEN

    total_score = 0
    for finding in findings:
        for key, weight in WEIGHTS.items():
            if finding.startswith(key):
                total_score += weight
                break

    score = min(total_score, 100)
    if score >= 60:
        level, color = "HIGH / CRITICAL", RED
    elif score >= 30:
        level, color = "MEDIUM / SUSPICIOUS", YELLOW
    else:
        level, color = "LOW", GREEN

    return score, level, color


def has_warnings(findings):
    """Improvement B: Are these real warnings or just information messages?"""
    return not findings[0].startswith(INFO_MESSAGES)


def main():
    print(f"\n{BOLD}{CYAN}===================================================={RESET}")
    print(f"{BOLD}   EWB Phishing URL Awareness Checker (Advanced)    {RESET}")
    print(f"{GRAY}   Text checks only - no internet or remote probing {RESET}")
    print(f"{BOLD}                   @CyberShailendra     {RESET}")
    print(f"{BOLD}{CYAN}===================================================={RESET}")

    while True:
        raw_url = input(f"\n{BOLD}Enter a sample URL (or type 'q' to quit):{RESET} ")
        if raw_url.strip().lower() in ("q", "quit", "exit"):
            print(f"\n{GREEN}Goodbye! Stay alert online.{RESET}")
            break

        findings = inspect_url(raw_url)

        print(f"\n{BOLD}Result:{RESET}")
        for item in findings:
            if not has_warnings(findings):
                print(f"  {GREEN}✔ {item}{RESET}")
            else:
                print(f"  {YELLOW}⚠ {item}{RESET}")
                for key, reason in REASONS.items():
                    if item.startswith(key):
                        print(f"    {GRAY}Why: {reason}{RESET}")

        if has_warnings(findings):
            score, level, color = calculate_risk_score(findings)
            print(f"\n{BOLD}{color}[REVIEW CAREFULLY: {len(findings)} warning sign(s) found | Risk Score: {score}/100 ({level})]{RESET}")
        
        print(f"{GRAY}Never enter passwords or personal data from unexpected links.{RESET}")


if __name__ == "__main__":
    main()
