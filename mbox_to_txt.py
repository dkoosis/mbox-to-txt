import argparse
import mailbox
import os
import re
import sys
import chardet
from typing import Dict, List, Optional
from html.parser import HTMLParser


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []

    def handle_data(self, d):
        self.result.append(d)

    def get_text(self):
        return " ".join(self.result)


# --- Configuration ---
# Headers to remove (add more if needed)
HEADERS_TO_REMOVE = {
    "Message-ID",
    "Received",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
    "DKIM-Signature",
    "X-Mailer",
    "X-Spam-Status",
    "X-Spam-Checker-Version",
    "X-Spam-Level",
    'X-Originating-IP',
    'X-Rcpt-To',
    'Return-Path',
    'Delivered-To'
    # Add other X- headers that are consistently irrelevant
}

# Patterns for signature/disclaimer detection (customize these)
SIGNATURE_PATTERNS = [
    re.compile(r"^--\s*$"),  # Common signature delimiter
    re.compile(r"^-----Original Message-----", re.IGNORECASE),
    re.compile(r"^________________________________", re.IGNORECASE),
    re.compile(r"^\s*On.*wrote:\s*$", re.IGNORECASE),  # often used before quoted text
    re.compile(r"^\s*From:.*$", re.IGNORECASE),  # common in forwarded messages
    re.compile(r"^\s*Sent from my iPhone", re.IGNORECASE),
    re.compile(r"^\s*Sent from Mail for Windows", re.IGNORECASE),
    re.compile(r"This email may contain confidential information\.", re.IGNORECASE),
    # Add more patterns based on your email data
]
# Patterns of text to delete from messages.
DELETION_PATTERNS = [
    # Forwarded messages:
    r"(\n|^)---------- Forwarded message ----------(.|\n)*$",
    # PGP:
    r"(\n|^)-----BEGIN PGP MESSAGE-----\n(.|\n)*-----END PGP MESSAGE-----\n",
    # Embedded links:
    r"<[^ ]+>",
]

# Pre-compile regular expressions for efficiency
COMPILED_DELETION_PATTERNS = [re.compile(pattern) for pattern in DELETION_PATTERNS]
COMPILED_SIGNATURE_PATTERNS = [re.compile(pattern) for pattern in SIGNATURE_PATTERNS]


# --- Functions ---

def munge_message(text):
    """
    Munges an e-mail message (in text form).

    :param text: The e-mail message.
    :return: The munged e-mail message.
    """
    for pattern in COMPILED_DELETION_PATTERNS:
        text = pattern.sub("", text)
    return text


def remove_headers(message: mailbox.mboxMessage):
    """Removes unnecessary headers from an email message."""
    for header in HEADERS_TO_REMOVE:
        if header in message:
            del message[header]
    # Remove empty headers
    keys_to_delete = [k for k, v in message.items() if not v.strip()]
    for key in keys_to_delete:
        del message[key]


def remove_signature(text: str) -> str:
    """Attempts to remove signatures and disclaimers from email text."""
    lines = text.splitlines()

    # Heuristic: Assume signature is at the bottom.
    # Work backwards from the end of the email

    for i in range(len(lines) - 1, -1, -1):
        line = lines[i]
        if any(pattern.match(line) for pattern in COMPILED_SIGNATURE_PATTERNS):
            # Possible signature or disclaimer found.
            # Check if the line before the matched line was empty,
            # since people often put a blank line before their signature.
            if i > 0 and lines[i - 1].strip() == "":
                return "\n".join(lines[:i - 1])  # remove signature AND empty line before
            else:
                return "\n".join(lines[:i])  # signature begins on non-empty line

    return text  # No signature found


def unquoted_line(line):
    """
    Unquotes an e-mail message line according to RFC 3676.

    :param line: The (possibly quoted) message line.
    :return: (unquoted line, quote depth).
    """
    quote_depth = 0
    while line.startswith(">"):
        line = line[1:]
        quote_depth += 1
    return line, quote_depth


def unstuff_line(line):
    """
    Unstuffs an e-mail message line according to RFC 3637.

    :param line: The (possibly stuffed) message line.
    :return: The unstuffed message line.
    """
    if line.startswith(" "):
        return line[1:]
    return line


def unflow_line(line, delsp):
    """
    Unflows an e-mail message line according to RFC 3637.

    :param line: The (possibly soft-broken) message line.
    :param delsp: Whether or not soft-break spaces should be deleted.
    :return: (processed line, soft-broken)
    """
    if len(line) < 1:
        return line, False
    if line.endswith(" "):
        if delsp:
            line = line[:-1]
        return line, True
    return line, False


def unflow_text(text, delsp):
    """
    Unflows an e-mail message according to RFC 3637.

    :param text: The flowed message.
    :param delsp: Whether or not soft-break spaces should be deleted.
    :return: The processed message.
    """
    full_line = ""
    full_text = ""
    lines = text.splitlines()
    for line in lines:
        (line, quote_depth) = unquoted_line(line)
        line = unstuff_line(line)
        (line, soft_break) = unflow_line(line, delsp)
        full_line += line
        if not soft_break:
            full_text += ">" * quote_depth + full_line + "\n"
            full_line = ""
    return full_text


def detect_encoding(part):
    """
    Detects the encoding of an email part using chardet.

    :param part: The email part.
    :return: The detected encoding or 'utf-8' as a fallback.
    """
    payload = part.get_payload(decode=True)
    if payload is None:
        return "utf-8"  # Default to UTF-8 if no payload

    detected_encoding = chardet.detect(payload)["encoding"]
    return detected_encoding or "utf-8"  # Use utf-8 as fallback


def part_to_text(part):
    """
    Converts an e-mail message part into text, handling encoding with chardet.
    Handles both plain text and HTML parts.

    :param part: E-mail message part.
    :return: Message text.
    """
    content_type = part.get_content_type()

    if content_type == "text/plain":
        charset = part.get_content_charset()
        if not charset:
            charset = detect_encoding(part)

        try:
            payload = part.get_payload(decode=True)
            if not payload:
                return None

            text = payload.decode(charset, errors="replace")  # Decode using detected charset

            if part.get_param("format") == "flowed":
                text = unflow_text(text, part.get_param("delsp", False))
            return text

        except Exception as e:
            print(f"Error decoding part with charset {charset}: {e}", file=sys.stderr)
            return None

    elif content_type == "text/html":
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return None

            charset = part.get_content_charset()
            if not charset:
                charset = detect_encoding(part)

            text = payload.decode(charset, errors="replace")
            extractor = TextExtractor()
            extractor.feed(text)
            return extractor.get_text()

        except Exception as e:
            print(f"Error processing HTML content: {e}", file=sys.stderr)
            return None
    else:
        return None


def message_to_text(message):
    """
    Converts an e-mail message into text.

    :param message: E-mail message.
    :return: Message text.
    """
    text = ""
    for part in message.walk():
        part_text = part_to_text(part)
        if part_text:
            text += part_text
    return text


def matches_filter(
    message: mailbox.mboxMessage,
    to_filters: List[str],
    from_filters: List[str],
    subject_filters: List[str],
) -> bool:
    """
    Check if a message matches all the specified filters.
    All filters are case-insensitive substring matches.
    Multiple filters of the same type are combined with OR logic.
    Different types of filters are combined with AND logic.

    :param message: The email message to check
    :param to_filters: List of strings to match in To: field
    :param from_filters: List of strings to match in From: field
    :param subject_filters: List of strings to match in Subject: field
    :return: True if message matches all filters, False otherwise
    """

    def matches_any(header_value: Optional[str], filters: List[str]) -> bool:
        if not filters:  # If no filters of this type, consider it a match
            return True
        if not header_value:  # If no header value but we have filters, it's not a match
            return False
        header_value = header_value.lower()
        return any(f.lower() in header_value for f in filters)

    to_match = matches_any(message.get("To"), to_filters)
    from_match = matches_any(message.get("From"), from_filters)
    subject_match = matches_any(message.get("Subject"), subject_filters)

    return to_match and from_match and subject_match


def create_skip_mboxes(save_dir: str) -> Dict[str, mailbox.mbox]:
    """Create mbox files for different skip categories"""
    skip_mboxes = {}
    categories = [
        "no-content",
        "empty-after-munge",
    ]

    for category in categories:
        filename = os.path.join(save_dir, f"skipped-{category}.mbox")
        skip_mboxes[category] = mailbox.mbox(filename)

    return skip_mboxes


def mailbox_text(
    mb,
    to_filters=None,
    from_filters=None,
    subject_filters=None,
    save_skipped: Optional[str] = None,
):
    """
    Returns the contents of a mailbox as text.
    Filters messages based on To:, From:, and Subject: fields.
    Optionally saves skipped messages to separate mbox files.
    """
    to_filters = to_filters or []
    from_filters = from_filters or []
    subject_filters = subject_filters or []

    skip_mboxes = create_skip_mboxes(save_skipped) if save_skipped else {}

    total = 0
    skipped_filter = 0
    no_content = 0
    processed = 0
    empty_after_munge = 0
    total_incoming_word_count = 0
    total_outgoing_word_count = 0

    try:
        for message in mb:
            total += 1

            # Apply filters
            if not matches_filter(message, to_filters, from_filters, subject_filters):
                skipped_filter += 1
                continue

            # Check content types and extract text
            has_plain = False
            has_html = False
            text = ""

            remove_headers(message)  # Remove headers before processing parts

            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    has_plain = True
                    text += part_to_text(part) or ""
                elif part.get_content_type() == "text/html":
                    has_html = True
                    text += part_to_text(part) or ""

            if not has_plain and not has_html:
                no_content += 1
                if save_skipped:
                    skip_mboxes["no-content"].add(message)
                continue

            # Count incoming words
            incoming_word_count = len(text.split())
            total_incoming_word_count += incoming_word_count

            # Munge, remove signature, and clean up whitespace
            text = munge_message(text)
            text = remove_signature(text)
            lines = text.splitlines()
            processed_lines = []
            for line in lines:
                line = line.strip()
                line = re.sub(r"\s+", " ", line)  # Reduce multiple spaces to single spaces
                if line != "":
                    processed_lines.append(line)
            text = "\n".join(processed_lines)

            # Check for empty content after cleanup
            if not text or len(text.strip()) == 0:
                empty_after_munge += 1
                if save_skipped:
                    skip_mboxes["empty-after-munge"].add(message)
                continue

            processed += 1

            # Count outgoing words
            outgoing_word_count = len(text.split())
            total_outgoing_word_count += outgoing_word_count

            yield text

    finally:
        # Close all skip mboxes
        if save_skipped:
            for mbox in skip_mboxes.values():
                mbox.close()

    # Calculate percentage reduction
    if total_incoming_word_count > 0:
      percent_reduction = ((total_incoming_word_count - total_outgoing_word_count) / total_incoming_word_count) * 100
    else:
      percent_reduction = 0

    # Print statistics
    print(f"\nEmail Processing Statistics:", file=sys.stderr)
    print(f"Total emails examined: {total}", file=sys.stderr)
    print(f"Skipped (didn't match filters): {skipped_filter}", file=sys.stderr)
    print(f"Skipped (no text content): {no_content}", file=sys.stderr)
    print(f"Skipped (empty after cleaning): {empty_after_munge}", file=sys.stderr)
    print(f"Successfully processed: {processed}", file=sys.stderr)
    print(f"Total incoming words: {total_incoming_word_count}", file=sys.stderr)
    print(f"Total outgoing words: {total_outgoing_word_count}", file=sys.stderr)
    print(f"Word count reduction: {percent_reduction:.2f}%", file=sys.stderr)

    unprocessed = total - processed - skipped_filter
    print(f"\nSummary:", file=sys.stderr)
    print(f"Processed: {processed} ({processed/total*100:.1f}%)", file=sys.stderr)
    print(f"Unprocessed: {unprocessed} ({unprocessed/total*100:.1f}%)", file=sys.stderr)

    if save_skipped:
        print(f"\nSkipped emails saved to:", file=sys.stderr)
        for category, mbox in skip_mboxes.items():
            path = mbox._path
            size = os.path.getsize(path)
            if size > 0:
                print(f"  {path} ({size} bytes)", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Convert mbox to text file with flexible filtering.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("mbox_file", help=".mbox file to parse")
    parser.add_argument(
        "--to", action="append", help="Filter emails containing TEXT in To: field", metavar="TEXT"
    )
    parser.add_argument(
        "--from",
        dest="from_",
        action="append",
        help="Filter emails containing TEXT in From: field",
        metavar="TEXT",
    )
    parser.add_argument(
        "--subject",
        action="append",
        help="Filter emails containing TEXT in Subject: field",
        metavar="TEXT",
    )
    parser.add_argument(
        "--save-skipped",
        metavar="DIR",
        help="Save skipped emails to mbox files in specified directory",
    )

    args = parser.parse_args()

    if args.save_skipped:
        os.makedirs(args.save_skipped, exist_ok=True)

    mb = mailbox.mbox(args.mbox_file, create=False)
    for text in mailbox_text(mb, args.to, args.from_, args.subject, args.save_skipped):
        print(text)


if __name__ == "__main__":
    main()