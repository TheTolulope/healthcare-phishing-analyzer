# 🏥 Healthcare Phishing Email Analyzer

A beginner-friendly Python tool that scans emails for phishing red flags, with a focus on the tricks attackers use against **hospitals, clinics, and patients**: fake patient portals, HIPAA "violation" scares, Medicare refund scams, and requests for insurance or medical IDs.

Healthcare is one of the most targeted industries for phishing because patient data is valuable and staff work under time pressure. This project explores how those attacks can be spotted automatically.

## Features

- **Language analysis**: flags urgency/pressure phrases, requests for credentials or PHI (insurance ID, Medicare number, date of birth), generic greetings, and healthcare-themed lures
- **Sender analysis**: detects free email providers posing as organizations and mismatched `Reply-To` addresses
- **Link analysis**: detects raw IP address links, URL shorteners, non-HTTPS links, links that don't match the sender's domain, and lookalike domains stuffed with words like "secure" or "login"
- **Attachment analysis**: flags risky file types like `.zip`, `.exe`, `.html`, and macro-enabled Office files
- **Risk scoring**: combines findings into a 0–100 score with a Low / Medium / High verdict
- **Unit tests** using Python's built-in `unittest`

No external libraries needed. Just Python 3.8+.

## Quick Start

```bash
git clone https://github.com/TheTolulope/healthcare-phishing-analyzer.git
cd healthcare-phishing-analyzer

# Scan one email
python phishing_analyzer.py sample_emails/phish_patient_portal.txt

# Scan a whole folder
python phishing_analyzer.py sample_emails/

# Run the tests
python -m unittest discover tests
```

## Example Output

```
======================================================================
File:    sample_emails/phish_hipaa_notice.txt
From:    HIPAA Compliance Office <hipaa.compliance.dept@gmail.com>
Subject: Final Notice - HIPAA Violation Reported Against You
----------------------------------------------------------------------
  [+10] Pressure language: "within 48 hours"
  [+10] Pressure language: "final notice"
  [+10] Pressure language: "failure to respond"
  [+ 5] Common healthcare lure: "hipaa"
  [+10] Generic greeting: "dear user"
  [+15] Sent from a free email provider (gmail.com)
  [+15] Reply-To (records-audit.example) differs from sender (gmail.com)
  [+25] Link points to a raw IP address: http://203.0.113.45/hipaa/case
  [+10] Link is not HTTPS: http://203.0.113.45/hipaa/case
  [+25] Risky attachment type: Violation_Report.zip
----------------------------------------------------------------------
Risk score: 100/100  ->  HIGH RISK - likely phishing
```

## How It Works

1. The email is split into **headers** (From, Reply-To, Subject) and **body**.
2. The text is checked against lists of red-flag phrases.
3. Every link is extracted and inspected.
4. Each finding adds points (see `WEIGHTS` in the code). Some categories are capped so one type of flag can't dominate.
5. The total becomes a score: **0–29 Low**, **30–59 Medium**, **60–100 High**.

## Project Structure

```
healthcare-phishing-analyzer/
├── phishing_analyzer.py     # The analyzer
├── sample_emails/           # Fictional test emails (3 phishing, 1 legitimate)
├── tests/
│   └── test_analyzer.py     # Unit tests
├── .gitignore
└── README.md
```

## Limitations

This is a learning project, not a production security tool. Keyword matching can be fooled by attackers who avoid common phrases, the domain comparison is simplified (it doesn't handle domains like `.co.uk` correctly), and it doesn't check real email authentication results (SPF, DKIM, DMARC).

## Roadmap

- [ ] Read real `.eml` files using Python's `email` library
- [ ] Check SPF/DKIM/DMARC results from email headers
- [ ] Detect lookalike characters (e.g. `rn` posing as `m`, `0` posing as `o`)
- [ ] Export results to CSV or JSON
- [ ] Run tests automatically with GitHub Actions

## Security Context

Relates to **MITRE ATT&CK T1566 (Phishing)**, including Spearphishing Link (T1566.002) and Spearphishing Attachment (T1566.001).

## Disclaimer

All sample emails are fictional. Domains use the reserved `.example` TLD and IP addresses come from documentation-only ranges. Built for educational purposes.
   ## Related Projects

   - [Hospital GRC Risk Assessment](https://github.com/YOUR-USERNAME/hospital-grc-risk-assessment): phishing is risk R05 in this assessment
