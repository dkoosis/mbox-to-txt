import argparse
import mailbox
import os
import re
import sys
import chardet
from typing import Dict, List, Optional
from html.parser import HTMLParser
from email.utils import parsedate_to_datetime

class TextExtractor(HTMLParser):
    """Extracts text content from HTML."""
    def __init__(self):
        super().__init__()
        self.result = []

    def handle_data(self, data):  # Parameter name changed to 'data'
        self.result.append(data)

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
    re.compile(r"^________________________________________+", re.IGNORECASE), # Added + for flexibility
    re.compile(r"^\s*On.*wrote:\s*$", re.IGNORECASE),  # often used before quoted text
    re.compile(r"^\s*From:.*$", re.IGNORECASE),  # common in forwarded messages
    re.compile(r"^\s*Sent from my iPhone", re.IGNORECASE),
    re.compile(r"^\s*Sent from Mail for Windows", re.IGNORECASE),
    re.compile(r"This email may contain confidential information\.", re.IGNORECASE),  # Example disclaimer
    # Add more patterns based on your email data
]

DELETION_PATTERNS = [
    # Forwarded message headers
    r"(\n|^)---------- Forwarded message ----------(.|\n)*$",
    r"(\n|^)-------- Original Message --------(.|\n)*$",
    r"(\n|^)Begin forwarded message:(.|\n)*$",

    # Email security related
    r"(\n|^)-----BEGIN PGP MESSAGE-----\n(.|\n)*-----END PGP MESSAGE-----\n",
    r"(\n|^)-----BEGIN PGP SIGNATURE-----\n(.|\n)*-----END PGP SIGNATURE-----\n",

    # HTML and CSS cleanup
    r"<[^>]+>",  # HTML tags
    r"/\*[\s\S]*?\*/",  # CSS comments
    r"",  # HTML comments
    r"<style[^>]*>[\s\S]*?</style>",  # Style tags and contents

    # CSS rules and declarations
    r"@font-face\s*{[^}]*}",  # Font face declarations
    r"@page[^}]*}",  # Page rules
    r"\.[\w-]+\s*{[^}]*}",  # CSS class definitions
    r"@import url\([^)]*\);",  # CSS imports
    r"@media[^{]*{[^}]*}",  # Media queries
    r"body\s*{[^}]*}",  # Body style definitions
    r"table\s*{[^}]*}",  # Table style definitions
    r"#[\w-]+\s*{[^}]*}",  # ID-based style definitions

    # Email client specific
    r"_{10,}",  # Long underline separators
    r"\[cid:[^\]]+\]",  # Content-ID references
    r"Content-Type: \S+\n",  # Content type headers (Consider removing if needed)
    r"Content-Transfer-Encoding: \S+\n",  # Transfer encoding headers (Consider removing if needed)

    # Calendar invite cleanup
    r"This email has been scanned for.*$",
    r"Click here to report this email as spam.*$",
    r"You are receiving this.*calendar notifications.*$",
    r"Invitation from Google Calendar:.*$",

    # Reply markers
    r"On.*wrote:$",
    r"From:.*Sent:.*To:.*Subject:",

    # Disclaimer blocks
    r"CONFIDENTIALITY NOTICE:[\s\S]*?$",
    r"DISCLAIMER:[\s\S]*?$",
    r"This email and any files.*confidential.*$",

    # Signature separators
    r"^--\s*$",  # Simple signature delimiter
    r"_{30,}",  # Long signature separator
    r"-{30,}",  # Alternative signature separator

    # Email client formatting
    r"@-webkit-keyframes[^{]*{[^}]*}",
    r"@keyframes[^{]*{[^}]*}",
    r"@-ms-viewport[^{]*{[^}]*}",
    r"@viewport[^{]*{[^}]*}"
]

# Pre-compile regular expressions for efficiency
COMPILED_DELETION_PATTERNS = [re.compile(pattern) for pattern in DELETION_PATTERNS]
COMPILED_SIGNATURE_PATTERNS = [re.compile(pattern) for pattern in SIGNATURE_PATTERNS]


# --- Functions ---
# Add new function to detect auto-responses
def is_auto_response(message: mailbox.mboxMessage) -> bool:
    """Returns True if message appears to be an auto-response."""
    subject = message.get("Subject", "").lower()
    auto_subjects = {"automatic reply", "out of office", "auto-reply"}
    return any(auto in subject for auto in auto_subjects)


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
    Handles both plain text and HTML parts, and multipart messages.

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

            text = payload.decode(charset, errors="replace")

            if part.get_param("format") == "flowed":
                text = unflow_text(text, part.get_param("delsp", False))
            return text

        except UnicodeDecodeError:
            print(f"UnicodeDecodeError decoding part with charset {charset}. Trying latin-1.", file=sys.stderr)
            try:
                text = payload.decode('latin-1', errors="replace")
                return text
            except UnicodeDecodeError as e:  # Catch UnicodeDecodeError again
                print(f"Error decoding with latin-1: {e}", file=sys.stderr)
                return None

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

        except UnicodeDecodeError:
            print(f"UnicodeDecodeError processing HTML content. Trying latin-1.", file=sys.stderr)
            try:
                text = payload.decode('latin-1', errors="replace")
                extractor = TextExtractor()
                extractor.feed(text)
                return extractor.get_text()
            except Exception as e:
                print(f"Error processing HTML content with latin-1: {e}", file=sys.stderr)
                return None

        except Exception as e:  # Handle other potential exceptions
            print(f"Error processing HTML content: {e}", file=sys.stderr)
            return None

    elif content_type.startswith("multipart"):
        # Handle multipart messages by recursively calling part_to_text
        text = ""
        for sub_part in part.get_payload():
            part_text = part_to_text(sub_part)
            if part_text:
                text += part_text
        return text

    else:
        return None
   
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

def create_special_mboxes(save_dir: str) -> Dict[str, mailbox.mbox]:
    """Create mbox files for different special categories"""
    special_mboxes = {}
    categories = [
        "tickets",
    ]

    for category in categories:
        filename = os.path.join(save_dir, f"special-{category}.mbox")
        special_mboxes[category] = mailbox.mbox(filename)

    return special_mboxes

def save_to_skip_mbox(mbox, message):
    """
    Safely save a message to skip mbox, handling both string and list payloads.
    
    :param mbox: The mbox to save to
    :param message: The message to save
    """
    try:
        if message.is_multipart():
            # For multipart messages, we need to handle the full message structure
            new_message = mailbox.mboxMessage()
            # Copy all headers
            for key, value in message.items():
                new_message[key] = value
            # Set the payload with the full MIME structure
            new_message.set_payload(message.get_payload())
            mbox.add(new_message)
        else:
            # For simple messages, converting to string should work
            message_string = message.as_string()
            new_message = mailbox.mboxMessage(message_string)
            mbox.add(new_message)
        
        mbox.flush()  # Ensure changes are written to disk
        
    except Exception as e:
        print(f"Error saving message to mbox: {str(e)}", file=sys.stderr)

def get_header_string(message, header_name):
    """
    Safely retrieves a header value from an email message, handling lists.

    Args:
        message: The email message.
        header_name: The name of the header to retrieve.

    Returns:
        The header value as a string, or an empty string if not found or if a list is encountered.
    """
    header_value = message.get(header_name)
    if isinstance(header_value, list):
        # Option 1: Join with a separator (e.g., comma)
        return ", ".join(header_value)
        # Option 2: Take the first element (if it makes sense for the header)
        # return header_value[0] if header_value else "" 
    elif isinstance(header_value, str):
        return header_value
    else:
        return ""
def parse_date(date_str):
    """
    Parses a date string from an email header into a formatted date string.

    :param date_str: The date string from the email header.
    :return: A formatted date string or "Invalid Date Format" if parsing fails.
    """
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OverflowError):
        return "Invalid Date Format"

def remove_quoted_text(text: str) -> str:
    """
    Remove quoted text from email content using common markers.
    Preserves the original message while removing quoted replies/forwards.
    
    Args:
        text (str): Raw email message text
        
    Returns:
        str: Email text with quotes removed
    """
    # Split into lines for processing
    lines = text.splitlines()
    cleaned_lines = []
    skip_mode = False
    
    for line in lines:
        # Check for start of quoted text
        if re.match(r'^\s*On\s+.*wrote:$', line) or \
           re.match(r'^\s*-{3,}\s*Original Message\s*-{3,}', line) or \
           re.match(r'^\s*From:.*Sent:.*To:.*Subject:', line):
            skip_mode = True
            continue
            
        # Skip lines starting with '>' and any following indented content
        if line.startswith('>') or line.startswith('&gt;'):
            skip_mode = True
            continue
            
        # If we hit a non-quoted, non-indented line, turn off skip mode
        if skip_mode and line.strip() and not line.startswith(' '):
            skip_mode = False
            
        # Keep lines that aren't being skipped
        if not skip_mode:
            cleaned_lines.append(line)
    
    # Clean up any artifacts
    result = '\n'.join(cleaned_lines)
    result = re.sub(r'\n{3,}', '\n\n', result)  # Normalize multiple blank lines
    return result.strip()

def mailbox_text(
        mb,
        to_filters=None,
        from_filters=None,
        subject_filters=None,
        save_skipped: Optional[str] = "output",
        output_dir: Optional[str] = "output"
):
    """
    Returns the contents of a mailbox as text.
    Filters messages based on To:, From:, and Subject: fields.
    Optionally saves skipped messages to separate mbox files.
    """
    to_filters = to_filters or []
    from_filters = from_filters or []
    subject_filters = subject_filters or []

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, "tickets"), exist_ok=True)  # Create tickets sub-directory
    skip_mboxes = create_skip_mboxes(save_skipped) if save_skipped else {}
    special_mboxes = create_special_mboxes(save_skipped) if save_skipped else {}

    total = 0
    skipped_filter = 0
    no_content = 0
    processed = 0
    empty_after_munge = 0
    total_word_count = 0
    chunk_word_count = 0
    chunk_counter = 1
    current_chunk_name = os.path.join(output_dir, f"output_{chunk_counter}.txt")
    current_chunk_file = open(current_chunk_name, "w", encoding="utf-8")

    try:
        for message in mb:
            total += 1
            text = ""

            # Skip auto-responses
            if is_auto_response(message):
                skipped_filter += 1
                continue

            # Apply filters
            if not matches_filter(message, to_filters, from_filters, subject_filters):
                skipped_filter += 1
                continue

            # Check for ticket emails
            subject = message.get("Subject", "")
            if subject.startswith("Ticket#"):
                if save_skipped:
                    try:
                        save_to_skip_mbox(special_mboxes["tickets"], message)
                    except Exception as e:
                        print(f"Error adding ticket email to mbox: {e}")
                continue

            # Check content types and extract text
            has_plain = False
            has_html = False

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
                    try:
                        save_to_skip_mbox(skip_mboxes["no-content"], message)
                    except Exception as e:
                        print(f"Error adding message to 'no-content' mbox: {e}")
                continue

            # Munge, remove signature, and clean up whitespace
            text = munge_message(text)
            text = remove_quoted_text(text)  
            text = remove_signature(text)
            lines = text.splitlines()
            processed_lines = []

            # Process the lines
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
                    try:
                        save_to_skip_mbox(skip_mboxes["empty-after-munge"], message)
                    except Exception as e:
                        print(f"Error saving skipped message: {e}", file=sys.stderr)
                continue  # Skip further processing for empty messages

            # Word count for the current message, AFTER processing
            message_word_count = len(text.split())

            # Check if adding the current message would exceed the word limit
            if chunk_word_count + message_word_count > 500000:
                current_chunk_file.close()
                chunk_counter += 1
                current_chunk_name = os.path.join(output_dir, f"output_{chunk_counter}.txt")
                current_chunk_file = open(current_chunk_name, "w", encoding="utf-8")
                chunk_word_count = 0

            # Add the message to the current chunk
            current_chunk_file.write("=== EMAIL START ===\n")

            # Extract and format metadata
            from_header = get_header_string(message, "From")
            to_header = get_header_string(message, "To")
            subject_header = get_header_string(message, "Subject")
            date_header = parse_date(message.get("Date"))


            # Write metadata to file
            current_chunk_file.write(f"From: {from_header}\n")
            current_chunk_file.write(f"To: {to_header}\n")
            current_chunk_file.write(f"Date: {date_header}\n")
            current_chunk_file.write(f"Subject: {subject_header}\n\n")

            # Write the message content
            current_chunk_file.write(text)
            current_chunk_file.write("\n=== EMAIL END ===\n\n")

            # Update word counts
            chunk_word_count += message_word_count
            total_word_count += message_word_count

            processed += 1

    finally:
        current_chunk_file.close()  # Ensure the last chunk file is closed

        # Close all skip mboxes
        if save_skipped:
            for mbox in skip_mboxes.values():
                mbox.close()

            # Close all special mboxes
            for mbox in special_mboxes.values():
                mbox.close()

    # Print statistics
    print(f"\nEmail Processing Statistics:", file=sys.stderr)
    print(f"Total emails examined: {total}", file=sys.stderr)
    print(f"Skipped (didn't match filters): {skipped_filter}", file=sys.stderr)
    print(f"Skipped (no text content): {no_content}", file=sys.stderr)
    print(f"Skipped (empty after cleaning): {empty_after_munge}", file=sys.stderr)
    print(f"Successfully processed: {processed}", file=sys.stderr)
    print(f"Total words processed: {total_word_count}", file=sys.stderr)

    unprocessed = total - processed - skipped_filter
    print(f"\nSummary:", file=sys.stderr)
    print(f"Processed: {processed} ({processed/total*100:.1f}%)", file=sys.stderr)
    print(f"Unprocessed: {unprocessed} ({unprocessed/total*100:.1f}%)", file=sys.stderr)

    if save_skipped:
        print(f"\nSkipped emails saved to:", file=sys.stderr)
        for category, mbox in skip_mboxes.items():
            path = mbox._path  # Accessing protected member _path
            size = os.path.getsize(path)
            if size > 0:
                print(f"  {path} ({size} bytes)", file=sys.stderr)

        print(f"\nSpecial emails saved to:", file=sys.stderr)
        for category, mbox in special_mboxes.items():
            path = mbox._path  # Accessing protected member _path
            size = os.path.getsize(path)
            if size > 0:
                print(f"  {path} ({size} bytes)", file=sys.stderr)

def main():
    """
    entry
    """
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
        help="Save skipped emails to mbox files in specified directory (default: output)",
        default="output"
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="Directory to save output text files (default: output)",
        default="output"
    )

    args = parser.parse_args()

    if args.save_skipped:
        os.makedirs(args.save_skipped, exist_ok=True)

    mb = mailbox.mbox(args.mbox_file, create=False)
    mailbox_text(mb, args.to, args.from_, args.subject, args.save_skipped, args.output_dir)


if __name__ == "__main__":
    main()