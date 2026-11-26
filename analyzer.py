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

# ---------------------------------------------------------------------------
# Step 3: helpers and sender checks
# ---------------------------------------------------------------------------

# Brands that phishers like to copy, and the one domain each really uses
BRANDS = {
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "docusign": "docusign.com",
}


def add_finding(findings, severity, category, detail):
    """Add one finding to the list."""
    findings.append({"severity": severity, "category": category, "detail": detail})


def domain_of(address):
    """Return the domain part of an email address, lowercased."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower().strip(">")


def registered_domain(host):
    """Rough guess at the domain someone registered: the last two labels.

    login.microsoft.com -> microsoft.com
    This gets country domains like example.co.uk wrong (see README).
    """
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:])


def check_lookalike(host):
    """Return a reason string if host imitates a brand, otherwise None."""
    host = host.lower()
    if host.startswith("xn--") or ".xn--" in host:
        return "uses punycode (xn--), which can hide lookalike letters"

    domain = registered_domain(host)
    if domain in BRANDS.values():
        return None  # it really is the brand's domain

    subdomain = host[: -len(domain)]
    words = re.split(r"[-.]", domain.split(".")[0])

    for brand in BRANDS:
        if brand in subdomain:
            return f"puts '{brand}' in the subdomain of {domain}"
        for word in words:
            if word == brand:
                return f"uses the name '{brand}' but isn't {BRANDS[brand]}"
            if SequenceMatcher(None, word, brand).ratio() >= 0.8:
                return f"'{word}' looks like '{brand}'"
    return None


def check_sender(msg, findings):
    """Compare From, Reply-To and Return-Path. Returns the parsed addresses."""
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))

    from_domain = domain_of(from_addr)
    reply_domain = domain_of(reply_addr)
    return_domain = domain_of(return_addr)

    if reply_domain and registered_domain(reply_domain) != registered_domain(from_domain):
        add_finding(findings, "MEDIUM", "Sender",
                    f"Reply-To goes to {reply_domain}, not {from_domain}")

    if return_domain and registered_domain(return_domain) != registered_domain(from_domain):
        add_finding(findings, "LOW", "Sender",
                    f"Return-Path is {return_domain}, not {from_domain}")

    # "support@paypal.com" <someone@random.example>
    shown = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_name)
    if shown and shown.group(0).lower() != from_addr.lower():
        add_finding(findings, "HIGH", "Sender",
                    f"Display name shows {shown.group(0)} but the real sender is {from_addr}")

    # "PayPal Support" <someone@random.example>
    squashed_name = from_name.lower().replace(" ", "")
    for brand, real_domain in BRANDS.items():
        if brand in squashed_name and registered_domain(from_domain) != real_domain:
            add_finding(findings, "MEDIUM", "Sender",
                        f"Display name says '{brand}' but the email came from {from_domain}")
            break

    reason = check_lookalike(from_domain) if from_domain else None
    if reason:
        add_finding(findings, "HIGH", "Sender", f"Sender domain {from_domain} {reason}")

    return {"from": str(msg.get("From", "")), "reply_to": reply_addr, "return_path": return_addr}
# ---------------------------------------------------------------------------
# Step 4: the Received path
# ---------------------------------------------------------------------------

def parse_received(msg):
    """Return the Received hops, oldest first.

    Each server adds its Received header to the top, so the list from the
    email is newest first. We reverse it to read the path in order.
    """
    hops = []
    for header in reversed(msg.get_all("Received", [])):
        text = " ".join(str(header).split())  # fold multi-line headers into one line
        from_match = re.search(r"\bfrom\s+(\S+)", text)
        by_match = re.search(r"\bby\s+(\S+)", text)
        ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]", text)
        hops.append({
            "from": from_match.group(1) if from_match else "?",
            "by": by_match.group(1) if by_match else "?",
            "ip": ip_match.group(1) if ip_match else "?",
            "date": text.rsplit(";", 1)[1].strip() if ";" in text else "?",
        })
    return hops
# ---------------------------------------------------------------------------
# Step 5: SPF, DKIM and DMARC
# ---------------------------------------------------------------------------

def check_authentication(msg, findings):
    """Read the topmost Authentication-Results header and flag failures."""
    headers = msg.get_all("Authentication-Results", [])
    if not headers:
        add_finding(findings, "LOW", "Authentication",
                    "No Authentication-Results header, so SPF/DKIM/DMARC can't be checked")
        return {}

    # Only trust the top one: your own mail server added it.
    text = " ".join(str(headers[0]).split()).lower()
    results = {}
    for mechanism, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", text):
        results.setdefault(mechanism, result)

    for mechanism, result in results.items():
        if result == "fail":
            add_finding(findings, "HIGH", "Authentication", f"{mechanism.upper()} failed")
        elif result in ("softfail", "none", "neutral", "temperror", "permerror"):
            add_finding(findings, "MEDIUM", "Authentication", f"{mechanism.upper()} result is {result}")

    header_from = re.search(r"header\.from=([\w.-]+)", text)
    mail_from = re.search(r"smtp\.mailfrom=(?:[^@\s;]+@)?([\w.-]+)", text)
    if header_from and mail_from:
        if registered_domain(header_from.group(1)) != registered_domain(mail_from.group(1)):
            add_finding(findings, "MEDIUM", "Authentication",
                        f"Envelope sender {mail_from.group(1)} doesn't match "
                        f"From domain {header_from.group(1)}")
    return results
# ---------------------------------------------------------------------------
# Step 6: links
# ---------------------------------------------------------------------------

URL_SHORTENERS = {"bit.ly" , "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly"}

URL_RE = re.compile(r"https?//[^\s<>\"']+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b")

class LinkParser(HTMLParser):
    """Collect (href, visible text) for every <a> tag in an HTML body."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._text).strip()))
            self._href = None


def extract_links(msg):
    """Return a list of (url, link_text) from the text and HTML bodies."""
    found = {}  # url -> text; a dict keeps order and removes duplicates
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type == "text/html":
            parser = LinkParser()
            parser.feed(part.get_content())
            for url, text in parser.links:
                if url.lower().startswith(("http://", "https://")):
                    found[url] = text or found.get(url, "")
        elif content_type == "text/plain":
            for url in URL_RE.findall(part.get_content()):
                url = url.rstrip(".,);")
                found.setdefault(url, "")
    return list(found.items())


def defang(url):
    """Make a URL unclickable: https://evil.example -> hxxps://evil[.]example"""
    parts = urlsplit(url)
    rest = url.split(parts.netloc, 1)[1] if parts.netloc else ""
    return parts.scheme.replace("http", "hxxp") + "://" + parts.netloc.replace(".", "[.]") + rest


def check_link(url, text, findings):
    """Run every link check on one URL."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    shown = defang(url)

    try:
        ipaddress.ip_address(host)
        add_finding(findings, "HIGH", "Link", f"Goes to a bare IP address: {shown}")
        is_ip = True
    except ValueError:
        is_ip = False

    # Link text that names a different site than the real destination
    text_domain = DOMAIN_RE.search(text.lower())
    if text_domain:
        shown_host = urlsplit(text).hostname if "://" in text else text_domain.group(0)
        if shown_host and registered_domain(shown_host) != registered_domain(host):
            add_finding(findings, "HIGH", "Link",
                        f"Text shows {shown_host} but the link goes to {shown}")

    if not is_ip:
        reason = check_lookalike(host)
        if reason:
            add_finding(findings, "HIGH", "Link", f"{shown} {reason}")
        if registered_domain(host) in URL_SHORTENERS:
            add_finding(findings, "MEDIUM", "Link", f"URL shortener hides the destination: {shown}")
        if host.count(".") >= 4:
            add_finding(findings, "LOW", "Link", f"Unusually many subdomains: {shown}")

    if "@" in parts.netloc:
        add_finding(findings, "LOW", "Link", f"Has an @ in the address, which can hide the real host: {shown}")
    if parts.scheme == "http" and re.search(r"login|signin|verify|account|password", url.lower()):
        add_finding(findings, "LOW", "Link", f"Login-style page over plain http: {shown}")
# ---------------------------------------------------------------------------
# Step 7: attachments
# ---------------------------------------------------------------------------

RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".img", ".lnk",
                    ".html", ".htm", ".docm", ".xlsm", ".bat", ".cmd", ".ps1"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}

# What a few common file types should be labeled as in the email
EXPECTED_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".txt": "text/plain",
}


def check_attachments(msg, findings):
    """List attachments with their SHA-256 and flag risky ones."""
    attachments = []
    for part in msg.iter_attachments():
        name = part.get_filename() or "(no name)"
        data = part.get_payload(decode=True) or b""
        content_type = part.get_content_type()
        sha256 = hashlib.sha256(data).hexdigest()
        attachments.append({"name": name, "type": content_type, "size": len(data), "sha256": sha256})

        lower = name.lower()
        ext = os.path.splitext(lower)[1]
        pieces = lower.split(".")

        if len(pieces) >= 3 and "." + pieces[-2] in DOCUMENT_EXTENSIONS and ext in RISKY_EXTENSIONS:
            add_finding(findings, "HIGH", "Attachment",
                        f"{name} has a double extension, so it looks like a document but isn't")
        elif ext in RISKY_EXTENSIONS:
            add_finding(findings, "HIGH", "Attachment", f"{name} is a risky file type ({ext})")
        elif ext in ARCHIVE_EXTENSIONS:
            add_finding(findings, "MEDIUM", "Attachment", f"{name} is an archive, which can hide other files")

        expected = EXPECTED_TYPES.get(ext)
        if expected and content_type != expected:
            add_finding(findings, "LOW", "Attachment",
                        f"{name} is labeled {content_type}, expected {expected}")
    return attachments
# Temporary: print a few headers so you can see it works. Replaced in step 8.
if __name__ == "__main__":
    msg = load_email(sys.argv[1])
    for name in ("Subject", "From", "Reply-To", "Return-Path"):
        print(f"{name}: {msg.get(name, '(none)')}")