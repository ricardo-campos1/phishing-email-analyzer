# phishing-email-analyzer

A Python script that reads a saved email (.eml file) and flags the signs of phishing a SOC analyst checks first: spoofed senders, failed SPF/DKIM/DMARC, suspicious links and risky attachments. It ends with a risk score and a verdict.

## What it does and why

Users report suspicious emails all the time, and most of the first look is the same checklist: who really sent it, did it pass authentication, where do the links go, and what's attached. I wrote this to do that first pass of triage from the raw email.

- **Sender checks:** From domain vs Reply-To and Return-Path, a fake email address hidden in the display name, and a brand name in the display name that doesn't match the sending domain
- **Lookalike domains:** punycode, a brand name in a subdomain (`login.microsoft.com.verify-user.example`), and near-misses like `micros0ft`
- **Received path:** the servers the email passed through, oldest first, with their IPs
- **Authentication:** SPF, DKIM and DMARC results from the receiving server's Authentication-Results header
- **Links:** links to bare IP addresses, link text that shows one domain but goes to another, URL shorteners, too many subdomains, an @ in the address, and login pages over plain http
- **Attachments:** SHA-256 hash of each file, risky file types, double extensions like `invoice.pdf.exe`, archives, and file types that don't match their content type
- **Score:** each finding is HIGH (3 points), MEDIUM (2) or LOW (1). 7 or more is LIKELY PHISHING, 3 to 6 is SUSPICIOUS, and below that is LOW RISK.
- Optionally saves the results to a JSON file

It only reads text. It never opens links or runs attachments, and URLs in the report are defanged (`hxxps://evil[.]example`) so they can't be clicked by accident. It uses only the Python standard library, so there is nothing to install.

## How to run

Requires Python 3.9 or newer.

```
python3 analyzer.py sample_emails/credential_phish.eml
python3 analyzer.py sample_emails/credential_phish.eml --json report.json
```

To check a real email, save it as .eml from your mail client (in Gmail: the three-dot menu, then Download message) and pass that file in.

Run the tests:

```
python3 -m unittest discover tests
```

## Sample emails

The three emails in sample_emails are synthetic. They use .example domains and documentation IP ranges, so nothing in them points anywhere real.

- **clean_newsletter.eml:** a normal newsletter that passes every check
- **credential_phish.eml:** a fake Microsoft password-reset email with a spoofed display name, a mismatched Reply-To, failed SPF and DMARC, and links to an IP address, a shortener and a lookalike domain
- **invoice_attachment.eml:** an overdue-invoice email with a harmless placeholder attachment named `invoice_20931.pdf.exe`

Real phishing samples go in real_samples, which is in .gitignore so they never get pushed. Open those only inside a VM.

## How it works

1. **Load:** Python's email module parses the .eml file and decodes encoded headers and body parts.
2. **Check:** separate functions check the sender, Received path, authentication results, links and attachments. Each one adds findings with a severity and a short explanation.
3. **Score and report:** findings are sorted by severity, totaled into a score and printed with the verdict. The same results can be written to JSON.

Only the topmost Authentication-Results header is read. That's the one added by your own mail server. Anything below it could have been written by the sender.

## What I learned

- How to read raw email headers, and which ones a sender can fake
- What SPF, DKIM and DMARC each check, and where the receiving server records the results
- Common tricks in phishing links and attachments, and how to spot them in code
- Parsing HTML with Python's html.parser to pull out each link and the text shown for it
- Keeping each check small and testable with unittest, and running the tests in GitHub Actions

## Possible next steps

- Look up attachment hashes and link domains on VirusTotal or another threat-intel source
- Use the Public Suffix List so domains like example.co.uk are handled correctly
- Check WHOIS for newly registered sender and link domains
- Read .msg files from Outlook as well as .eml
- Send results to a SIEM or ticketing system
