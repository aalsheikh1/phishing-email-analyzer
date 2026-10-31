"""Phishing Email Analyzer - inspects a .eml file for common phishing indicators."""

import os
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# Visible link text that looks like an address, e.g. "https://site.com/x" or "site.com"
URL_LIKE = re.compile(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?$", re.IGNORECASE)

# ANSI terminal colors; turned off when output is piped to a file or NO_COLOR is set
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
RED, GREEN, YELLOW, BLUE, BOLD = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[1m"
RESET = "\033[0m"

# Pressure words phishers use to make victims act before thinking
URGENCY_KEYWORDS = [
    "urgent", "verify", "suspend", "immediately", "action required",
    "account locked", "unusual activity", "final notice", "expire",
]

# File types that can run code or hide malware: macro Office docs, executables,
# scripts, disk images, and HTML files used for fake login pages
DANGEROUS_EXTENSIONS = {
    ".xlsm", ".docm", ".pptm", ".exe", ".scr", ".bat", ".cmd", ".com",
    ".js", ".vbs", ".ps1", ".jar", ".msi", ".iso", ".img", ".lnk",
    ".hta", ".html", ".htm",
}


class LinkExtractor(HTMLParser):
    """Collect (href, visible text) pairs from <a> tags in HTML."""

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
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def load_email(path):
    """Read a .eml file and return a parsed email message."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_attachments(msg):
    """Return a list of attachment file names."""
    return [part.get_filename() for part in msg.iter_attachments() if part.get_filename()]


def get_domain(header_value):
    """Return the lowercase domain of an address header, or '' if missing."""
    _, address = parseaddr(header_value or "")
    return address.rpartition("@")[2].lower()


def check_reply_to(msg):
    """Flag emails whose replies go to a different domain than the sender's.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    from_domain = get_domain(msg["From"])
    reply_domain = get_domain(msg["Reply-To"])

    if reply_domain and reply_domain != from_domain:
        return 1, (f"[!] From-domain '{from_domain}' != Reply-To-domain "
                   f"'{reply_domain}' - reply goes somewhere else (+1)")
    return 0, "[ok] From and Reply-To domains agree"


def get_host(url):
    """Return the lowercase host of a URL (without 'www.'), adding a scheme if missing."""
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower()
    return host.removeprefix("www.")


def check_links(msg):
    """Flag links whose visible text shows one address but point to another.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    body = msg.get_body(preferencelist=("html",))
    if body is None:
        return 0, "[ok] No HTML links to inspect"

    extractor = LinkExtractor()
    extractor.feed(body.get_content())

    for href, text in extractor.links:
        if URL_LIKE.match(text) and get_host(text) != get_host(href):
            return 1, (f"[!] Link shows '{text}' but goes to '{href}' "
                       f"- the visible link lies (+1)")
    return 0, "[ok] No deceptive display-text links"


def get_body_text(msg):
    """Return the email body as plain text (HTML tags stripped)."""
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is None:
        return ""
    text = body.get_content()
    if body.get_content_subtype() == "html":
        text = re.sub(r"<[^>]+>", " ", text)
    return text


def check_urgency(msg):
    """Flag pressure words in the subject or body.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    text = f"{msg['Subject'] or ''} {get_body_text(msg)}".lower()
    found = [kw for kw in URGENCY_KEYWORDS if re.search(rf"\b{re.escape(kw)}", text)]

    if found:
        return 1, (f"[!] Urgency keywords: {', '.join(found)} "
                   f"- pressure is a phishing tell (+1)")
    return 0, "[ok] No urgency keywords"


def check_attachments(msg):
    """Flag attachments with file types that can carry malware.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    dangerous = [name for name in get_attachments(msg)
                 if any(name.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)]

    if dangerous:
        return 1, f"[!] Dangerous attachment: {', '.join(dangerous)} (+1)"
    return 0, "[ok] No dangerous attachment types"


def check_authentication(msg):
    """Flag SPF, DKIM, or DMARC failures recorded by the receiving mail server.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    headers = msg.get_all("Authentication-Results")
    if not headers:
        return 0, "[?] No Authentication-Results header - not checked (+0)"

    # The first (topmost) result for each method was added by the receiving server
    results = {}
    for method, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", " ".join(headers), re.IGNORECASE):
        results.setdefault(method.lower(), result.lower())

    failed = [f"{method}={result}" for method, result in results.items()
              if result in ("fail", "softfail", "permerror")]

    if failed:
        return 1, (f"[!] Authentication failed: {', '.join(failed)} "
                   f"- the sender may be forged (+1)")
    if results.keys() >= {"spf", "dkim", "dmarc"} and all(r == "pass" for r in results.values()):
        return 0, "[ok] SPF, DKIM and DMARC passed"
    summary = ", ".join(f"{m}={r}" for m, r in results.items()) or "no results found"
    return 0, f"[?] Authentication not conclusive: {summary} (+0)"


def color(text, *codes):
    """Wrap text in ANSI color codes when color output is enabled."""
    if not USE_COLOR:
        return text
    return "".join(codes) + text + RESET


def get_verdict(score):
    """Turn a suspicion score into a colored verdict line."""
    if score >= 2:
        return color("HIGH - Likely phishing. Do not click, do not reply.", BOLD, RED)
    if score == 1:
        return color("MEDIUM - Suspicious. Verify the sender through another channel.", BOLD, YELLOW)
    return color("LOW - Looks benign. No action needed.", BOLD, GREEN)


def print_summary(path, msg):
    """Print the key headers of the email."""
    attachments = get_attachments(msg)
    print(color(f"PHISHING ANALYSIS: {path}", BOLD, BLUE))
    print(f"From:        {msg['From']}")
    print(f"Reply-To:    {msg['Reply-To'] or '(none)'}")
    print(f"Subject:     {msg['Subject']}")
    print(f"Attachments: {', '.join(attachments) if attachments else '(none)'}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python phishing_analyzer.py <email.eml>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        msg = load_email(path)
    except FileNotFoundError:
        print(f"Error: file not found: {path}")
        sys.exit(1)

    if USE_COLOR and os.name == "nt":
        os.system("")  # enables ANSI color support in older Windows consoles

    print_summary(path, msg)

    score = 0
    print("\n" + color("FINDINGS:", BOLD, BLUE))
    for check in (check_authentication, check_reply_to, check_links,
                  check_urgency, check_attachments):
        points, finding = check(msg)
        score += points
        if points:
            finding_color = RED
        elif finding.startswith("[?]"):
            finding_color = YELLOW
        else:
            finding_color = GREEN
        print(f"  {color(finding, finding_color)}")

    print("\n" + color(f"Suspicion score: {score}", BOLD, YELLOW))
    print(f"Verdict: {get_verdict(score)}")


if __name__ == "__main__":
    main()
