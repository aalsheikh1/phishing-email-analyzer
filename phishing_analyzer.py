"""Phishing Email Analyzer - inspects a .eml file for common phishing indicators."""

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# Visible link text that looks like an address, e.g. "https://site.com/x" or "site.com"
URL_LIKE = re.compile(r"^(https?://)?[\w.-]+\.[a-z]{2,}(/\S*)?$", re.IGNORECASE)


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


def print_summary(path, msg):
    """Print the key headers of the email."""
    attachments = get_attachments(msg)
    print(f"PHISHING ANALYSIS: {path}")
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

    print_summary(path, msg)

    print("\nFINDINGS:")
    for check in (check_reply_to, check_links):
        _, finding = check(msg)
        print(f"  {finding}")


if __name__ == "__main__":
    main()
