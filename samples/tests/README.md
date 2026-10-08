# 🎣 PhishGuard

A lightweight **phishing URL detector** written in pure Python (no dependencies).
It checks a link for common phishing tricks and gives a **risk score (0-100)**.

## What it detects
- IP address used instead of a domain
- Missing HTTPS
- `@` trick that hides the real destination
- Very long URLs and too many subdomains
- Suspicious TLDs (`.xyz`, `.top`, `.tk` ...)
- Punycode / lookalike domains (`xn--`)
- Phishing keywords (`login`, `verify`, `secure` ...)
- Brand names inside unrelated domains (`amazon.account-check.top`)
- URL shorteners (`bit.ly` ...)

## Requirements
Python 3.8+

## Usage
```bash
# check one URL
python phishguard.py check "http://paypal-secure-login-verify.xyz/account/update"

# scan a list of URLs
python phishguard.py scan samples/urls.txt

# scan and export a CSV report
python phishguard.py scan samples/urls.txt --csv report.csv
```

### Sample output
```
[ OK ] SAFE (score 0/100) - https://www.google.com
[DANGER] DANGEROUS (score 80/100) - http://paypal-secure-login-verify.xyz/account/update
        - Does not use HTTPS
        - Suspicious top-level domain (.xyz)
        - Domain contains many hyphens
        - Suspicious keywords: login, verify, secure, account, update, paypal
        - Brand name 'paypal' used in an unrelated domain
```

## Run tests
```bash
python -m unittest discover tests
```

## Disclaimer
For educational and defensive use only. This tool is heuristic-based and does not guarantee detection.

## License
MIT
