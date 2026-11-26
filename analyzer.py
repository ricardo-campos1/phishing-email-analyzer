#!/usr/bin/env python3
"""
phishing-email-analyzer

Reads a saved email (.eml) and prints a triage report:

  - sender checks: From vs Reply-To and Return-Path, fake display names
  - the Received path the email took
  - SPF, DKIM and DMARC results from Authentication-Results
  - links: IP addresses, lookalike domains, shorteners, mismatched link text
  - attachments: risky types, double extensions, SHA-256 hashes
  - a risk score and verdict

It only reads text. It never opens links or runs attachments.
Uses only the Python standard library.

Example:
    python3 analyzer.py sample_emails/credential_phish.eml
    python3 analyzer.py sample_emails/credential_phish.eml --json report.json
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# Step 2: load the email
# ---------------------------------------------------------------------------

def load_email(path):
    """Read an .eml file and return an EmailMessage object."""
    with open(path, "rb") as eml_file:
        return BytesParser(policy=policy.default).parse(eml_file)


# Temporary: print a few headers so you can see it works. Replaced in step 8.
if __name__ == "__main__":
    msg = load_email(sys.argv[1])
    for name in ("Subject", "From", "Reply-To", "Return-Path"):
        print(f"{name}: {msg.get(name, '(none)')}")
