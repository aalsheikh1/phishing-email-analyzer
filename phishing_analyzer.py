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

# Brands phishers often impersonate, mapped to their real domain
KNOWN_BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "amazon": "amazon.com",
    "google": "google.com", "apple": "apple.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
    "outlook": "outlook.com", "office365": "office365.com", "dropbox": "dropbox.com",
    "docusign": "docusign.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com", "dhl": "dhl.com", "fedex": "fedex.com",
}

# Characters swapped in to fool the eye, e.g. "paypa1" or "arnazon"
LOOKALIKE_SWAPS = [
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
    ("4", "a"), ("5", "s"), ("7", "t"),
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


def get_links(msg):
    """Return (href, visible text) pairs from the HTML body, or None if there is no HTML."""
    body = msg.get_body(preferencelist=("html",))
    if body is None:
        return None
    extractor = LinkExtractor()
    extractor.feed(body.get_content())
    return extractor.links


def check_links(msg):
    """Flag links whose visible text shows one address but point to another.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    links = get_links(msg)
    if links is None:
        return 0, "[ok] No HTML links to inspect"

    for href, text in links:
        if URL_LIKE.match(text) and get_host(text) != get_host(href):
            return 1, (f"[!] Link shows '{text}' but goes to '{href}' "
                       f"- the visible link lies (+1)")
    return 0, "[ok] No deceptive display-text links"


def edit_distance(a, b):
    """Return how many single-letter edits turn a into b (Levenshtein distance)."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def get_registered_domain(host):
    """Return the main domain of a host, e.g. 'mail.paypal.com' -> 'paypal.com'.

    Handles two-part endings like 'co.uk' in a simple way.
    """
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in ("co", "com", "org", "net") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def find_imitated_brand(host):
    """Return the real brand domain a host is imitating, or None."""
    if host.startswith("xn--") or ".xn--" in host:
        return "a brand (punycode / foreign-character domain)"

    # The exact brand name under any ending (paypal.com, amazon.co.uk) counts as the real brand
    registered = get_registered_domain(host)
    if registered.split(".")[0] in KNOWN_BRANDS:
        return None

    for label in host.split(".")[:-1]:
        normalized = label
        for fake, real in LOOKALIKE_SWAPS:
            normalized = normalized.replace(fake, real)
        for brand, real_domain in KNOWN_BRANDS.items():
            if (normalized == brand
                    or brand in normalized.split("-")
                    or (len(brand) >= 6 and edit_distance(normalized, brand) == 1)):
                return real_domain
    return None


def check_lookalike_domains(msg):
    """Flag sender, Reply-To, or link domains that imitate a well-known brand.

    Returns (points, finding) where points is 1 if suspicious, else 0.
    """
    hosts = [get_domain(msg["From"]), get_domain(msg["Reply-To"])]
    hosts += [get_host(href) for href, _ in get_links(msg) or []]

    fakes = []
    for host in dict.fromkeys(h for h in hosts if h):
        imitated = find_imitated_brand(host)
        if imitated:
            fakes.append(f"'{host}' imitates {imitated}")

    if fakes:
        return 1, f"[!] Lookalike domain: {'; '.join(fakes)} (+1)"
    return 0, "[ok] No lookalike domains"


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
                  check_lookalike_domains, check_urgency, check_attachments):
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
