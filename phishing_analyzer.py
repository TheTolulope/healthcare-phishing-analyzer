#!/usr/bin/env python3
"""
Healthcare Phishing Email Analyzer
----------------------------------
Scans a plain-text email for common phishing red flags, with extra
focus on lures that target hospitals, clinics, and patients.

Usage:
    python phishing_analyzer.py sample_emails/phish_patient_portal.txt
    python phishing_analyzer.py sample_emails/          (scan a whole folder)
"""

import argparse
import re
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Red-flag word lists. Add your own as you learn more!
# ---------------------------------------------------------------------------
URGENCY_PHRASES = [
    "urgent", "immediately", "within 24 hours", "within 48 hours",
    "final notice", "action required", "account will be suspended",
    "account will be locked", "failure to respond", "act now",
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your password", "enter your password",
    "login credentials", "social security", "ssn", "date of birth",
    "insurance id", "member id", "medicare number", "credit card",
    "bank account", "update your payment",
]

HEALTHCARE_LURES = [
    "lab results", "test results", "patient portal", "hipaa", "prescription",
    "refund", "billing statement", "explanation of benefits",
    "insurance claim", "medicare", "covid",
]

GENERIC_GREETINGS = [
    "dear patient", "dear customer", "dear user", "dear member",
    "dear valued", "dear sir/madam",
]

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "protonmail.com", "icloud.com",
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}

SUSPICIOUS_DOMAIN_WORDS = ["secure", "login", "verify", "update", "account", "portal", "support"]

RISKY_ATTACHMENTS = (".exe", ".zip", ".html", ".htm", ".js", ".docm", ".xlsm", ".iso", ".scr")

# Points for each red flag. Tweak these to change how strict the tool is.
WEIGHTS = {
    "urgency": 10,
    "credential_request": 15,
    "healthcare_lure": 5,
    "generic_greeting": 10,
    "free_email_sender": 15,
    "reply_to_mismatch": 15,
    "ip_address_link": 25,
    "url_shortener": 20,
    "insecure_link": 10,
    "link_domain_mismatch": 15,
    "suspicious_domain": 10,
    "risky_attachment": 25,
}

# Max points a single category can add, so one category can't dominate.
CAPS = {"urgency": 20, "credential_request": 30, "healthcare_lure": 10}

URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def parse_email(text):
    """Split raw email text into a headers dict and a body string."""
    headers = {}
    lines = text.splitlines()
    body_start = 0
    for i, line in enumerate(lines):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    body = "\n".join(lines[body_start:])
    return headers, body


def get_email_domain(header_value):
    """Pull the domain out of a header like 'Name <user@example.com>'."""
    match = EMAIL_PATTERN.search(header_value or "")
    return match.group(1).lower() if match else ""


def get_link_host(url):
    """Return the hostname of a URL (adds http:// if it's missing)."""
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def base_domain(host):
    """Simplified 'registered domain': the last two labels (mail.a.com -> a.com)."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def find_phrases(text, phrases):
    """Return every phrase from the list that appears in the text."""
    return [p for p in phrases if p in text]


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------
def analyze_email(raw_text):
    """Analyze one email and return a dict with findings, score, and verdict."""
    headers, body = parse_email(raw_text)
    subject = headers.get("subject", "")
    content = f"{subject}\n{body}".lower()
    findings = []

    def add(category, detail):
        findings.append({"category": category, "detail": detail, "points": WEIGHTS[category]})

    # 1. Suspicious wording
    for phrase in find_phrases(content, URGENCY_PHRASES):
        add("urgency", f'Pressure language: "{phrase}"')
    for phrase in find_phrases(content, CREDENTIAL_PHRASES):
        add("credential_request", f'Asks for sensitive info: "{phrase}"')
    for phrase in find_phrases(content, HEALTHCARE_LURES):
        add("healthcare_lure", f'Common healthcare lure: "{phrase}"')
    for phrase in find_phrases(content, GENERIC_GREETINGS):
        add("generic_greeting", f'Generic greeting: "{phrase}"')

    # 2. Sender checks
    sender_domain = get_email_domain(headers.get("from", ""))
    if sender_domain in FREE_EMAIL_PROVIDERS:
        add("free_email_sender", f"Sent from a free email provider ({sender_domain})")

    reply_domain = get_email_domain(headers.get("reply-to", ""))
    if reply_domain and sender_domain and base_domain(reply_domain) != base_domain(sender_domain):
        add("reply_to_mismatch", f"Reply-To ({reply_domain}) differs from sender ({sender_domain})")

    # 3. Link checks
    for url in URL_PATTERN.findall(body):
        url = url.rstrip(".,);")
        host = get_link_host(url)
        if not host:
            continue
        if IP_PATTERN.match(host):
            add("ip_address_link", f"Link points to a raw IP address: {url}")
        if host in URL_SHORTENERS:
            add("url_shortener", f"Link uses a URL shortener (hides destination): {url}")
        if url.lower().startswith("http://"):
            add("insecure_link", f"Link is not HTTPS: {url}")
        if sender_domain and not IP_PATTERN.match(host) and base_domain(host) != base_domain(sender_domain):
            add("link_domain_mismatch", f"Link domain ({host}) doesn't match sender ({sender_domain})")
        registered_name = base_domain(host).split(".")[0]
        if any(word in registered_name for word in SUSPICIOUS_DOMAIN_WORDS):
            add("suspicious_domain", f"Domain stuffed with trust words: {host}")

    # 4. Attachment checks (looks for file names mentioned in headers/body)
    for word in re.findall(r"[\w-]+\.\w{2,4}\b", raw_text):
        if word.lower().endswith(RISKY_ATTACHMENTS):
            add("risky_attachment", f"Risky attachment type: {word}")

    # 5. Score it, applying per-category caps
    totals = {}
    for f in findings:
        totals[f["category"]] = totals.get(f["category"], 0) + f["points"]
    score = sum(min(points, CAPS.get(cat, points)) for cat, points in totals.items())
    score = min(score, 100)

    if score >= 60:
        verdict = "HIGH RISK - likely phishing"
    elif score >= 30:
        verdict = "MEDIUM RISK - be cautious"
    else:
        verdict = "LOW RISK - no major red flags"

    return {"subject": subject, "sender": headers.get("from", ""),
            "findings": findings, "score": score, "verdict": verdict}


def print_report(path, result):
    """Pretty-print the analysis results."""
    print("=" * 70)
    print(f"File:    {path}")
    print(f"From:    {result['sender']}")
    print(f"Subject: {result['subject']}")
    print("-" * 70)
    if result["findings"]:
        for f in result["findings"]:
            print(f"  [+{f['points']:>2}] {f['detail']}")
    else:
        print("  No red flags found.")
    print("-" * 70)
    print(f"Risk score: {result['score']}/100  ->  {result['verdict']}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Scan emails for healthcare phishing red flags.")
    parser.add_argument("path", help="A .txt email file, or a folder of them")
    args = parser.parse_args()

    target = Path(args.path)
    files = sorted(target.glob("*.txt")) if target.is_dir() else [target]
    if not files:
        print("No .txt email files found.")
        return

    for file in files:
        result = analyze_email(file.read_text(encoding="utf-8"))
        print_report(file, result)


if __name__ == "__main__":
    main()
