"""Phishing Email Analyzer - inspects a .eml file for common phishing indicators."""

import sys
from email import policy
from email.parser import BytesParser


def load_email(path):
    """Read a .eml file and return a parsed email message."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_attachments(msg):
    """Return a list of attachment file names."""
    return [part.get_filename() for part in msg.iter_attachments() if part.get_filename()]


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


if __name__ == "__main__":
    main()
