"""Phishing Email Analyzer - inspects a .eml file for common phishing indicators."""

import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


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

    _, finding = check_reply_to(msg)
    print("\nFINDINGS:")
    print(f"  {finding}")


if __name__ == "__main__":
    main()
