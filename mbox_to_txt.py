# See README.md for information and usage.
#
# Copyright 2016 Christopher Allen Ogden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import mailbox
import os
import re
import sys
from typing import Dict, List, Optional

# Patterns of text to delete from messages.
DELETION_PATTERS = [
    # Reply text:
    r'(\n|^)On.*\n?.*wrote:\n+(.|\n)*$',
    r'(\n|^)From:(.|\n)*$',

    # Forwarded messages:
    r'(\n|^)---------- Forwarded message ----------(.|\n)*$',

    # PGP:
    r'(\n|^)-----BEGIN PGP MESSAGE-----\n(.|\n)*-----END PGP MESSAGE-----\n',

    # Embedded links:
    r'<[^ ]+>',
]


def munge_message(text):
    """
    Munges an e-mail message (in text form).

    :param text: The e-mail message.
    :return: The munged e-mail message.
    """
    for pattern in DELETION_PATTERS:
        text = re.sub(pattern, '', text)
    return text


def unquoted_line(line):
    """
    Unquotes an e-mail message line according to RFC 3676.

    :param line: The (possibly quoted) message line.
    :return: (unquoted line, quote depth).
    """
    quote_depth = 0
    while line.startswith('>'):
        line = line[1:]
        quote_depth += 1
    return line, quote_depth


def unstuff_line(line):
    """
    Unstuffs an e-mail message line according to RFC 3637.

    :param line: The (possibly stuffed) message line.
    :return: The unstuffed message line.
    """
    if line.startswith(' '):
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
    if line.endswith(' '):
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
    full_line = ''
    full_text = ''
    lines = text.splitlines()
    for line in lines:
        (line, quote_depth) = unquoted_line(line)
        line = unstuff_line(line)
        (line, soft_break) = unflow_line(line, delsp)
        full_line += line
        if not soft_break:
            full_text += '>' * quote_depth + full_line + '\n'
            full_line = ''
    return full_text


def part_to_text(part):
    """
    Converts an e-mail message part into text.

    Returns None if the message could not be decoded as ASCII.

    :param part: E-mail message part.
    :return: Message text.
    """
    if part.get_content_type() != 'text/plain':
        return None
    charset = part.get_content_charset()
    if not charset:
        return None
    text = str(part.get_payload(decode=True), encoding=charset, errors='ignore')
    try:
        text = str(text.encode('ascii'), 'ascii')
    except UnicodeEncodeError:
        return None
    except UnicodeDecodeError:
        return None
    if part.get_param('format') == 'flowed':
        text = unflow_text(text, part.get_param('delsp', False))
    return text


def message_to_text(message):
    """
    Converts an e-mail message into text.

    Returns an empty string if the e-mail message could not be decoded as ASCII.

    :param message: E-mail message.
    :return: Message text.
    """
    text = ''
    for part in message.walk():
        part = part_to_text(part)
        if part:
            text += part
    return text


def matches_filter(message: mailbox.mboxMessage, to_filters: List[str], from_filters: List[str], subject_filters: List[str]) -> bool:
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
    
    to_match = matches_any(message.get('To'), to_filters)
    from_match = matches_any(message.get('From'), from_filters)
    subject_match = matches_any(message.get('Subject'), subject_filters)
    
    return to_match and from_match and subject_match

#!/usr/bin/env python3

import argparse
import mailbox
import os
import re
import sys
from typing import Dict, Optional


# [Previous code unchanged until mailbox_text function]

def create_skip_mboxes(save_dir: str) -> Dict[str, mailbox.mbox]:
    """Create mbox files for different skip categories"""
    skip_mboxes = {}
    categories = [
        'html-only',
        'no-content',
        'encoding-failed',
        'no-charset',
        'empty-after-munge'
    ]
    
    for category in categories:
        filename = os.path.join(save_dir, f'skipped-{category}.mbox')
        skip_mboxes[category] = mailbox.mbox(filename)
        
    return skip_mboxes

def mailbox_text(mb, to_filters=None, from_filters=None, subject_filters=None, save_skipped: Optional[str] = None):
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
    skipped_html = 0
    skipped_filter = 0
    no_content = 0
    encoding_failed = 0
    no_charset = 0
    processed = 0
    empty_after_munge = 0
    
    try:
        for message in mb:
            total += 1
            
            # Apply filters
            if not matches_filter(message, to_filters, from_filters, subject_filters):
                skipped_filter += 1
                continue
            
            # Check content types
            has_plain = False
            has_html = False
            for part in message.walk():
                if part.get_content_type() == 'text/plain':
                    has_plain = True
                elif part.get_content_type() == 'text/html':
                    has_html = True
                    
            if not has_plain and has_html:
                skipped_html += 1
                if save_skipped:
                    skip_mboxes['html-only'].add(message)
                continue
            elif not has_plain and not has_html:
                no_content += 1
                if save_skipped:
                    skip_mboxes['no-content'].add(message)
                continue
                
            # Try to get text content
            text = ''
            encoding_failed_flag = False
            no_charset_flag = False
            
            for part in message.walk():
                if part.get_content_type() != 'text/plain':
                    continue
                    
                charset = part.get_content_charset()
                if not charset:
                    no_charset_flag = True
                    continue
                    
                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    text_part = str(payload, encoding=charset, errors='ignore')
                    try:
                        text_part = str(text_part.encode('ascii'), 'ascii')
                        text += text_part
                    except UnicodeEncodeError:
                        encoding_failed_flag = True
                        continue
                except Exception:
                    encoding_failed_flag = True
                    continue
                    
            if encoding_failed_flag:
                encoding_failed += 1
                if save_skipped:
                    skip_mboxes['encoding-failed'].add(message)
                continue
                
            if no_charset_flag and not text:
                no_charset += 1
                if save_skipped:
                    skip_mboxes['no-charset'].add(message)
                continue
                
            if not text:
                no_content += 1
                if save_skipped:
                    skip_mboxes['no-content'].add(message)
                continue
                
            text = munge_message(text)
            if not text or len(text.strip()) == 0:
                empty_after_munge += 1
                if save_skipped:
                    skip_mboxes['empty-after-munge'].add(message)
                continue
                
            processed += 1
            yield text
                
    finally:
        # Close all skip mboxes
        if save_skipped:
            for mbox in skip_mboxes.values():
                mbox.close()
            
    print(f"\nEmail Processing Statistics:", file=sys.stderr)
    print(f"Total emails examined: {total}", file=sys.stderr)
    print(f"Skipped (didn't match filters): {skipped_filter}", file=sys.stderr)
    print(f"Skipped (HTML-only): {skipped_html}", file=sys.stderr)
    print(f"Skipped (no text content): {no_content}", file=sys.stderr)
    print(f"Skipped (encoding failed): {encoding_failed}", file=sys.stderr)
    print(f"Skipped (no charset): {no_charset}", file=sys.stderr)
    print(f"Skipped (empty after cleaning): {empty_after_munge}", file=sys.stderr)
    print(f"Successfully processed: {processed}", file=sys.stderr)
    
    unprocessed = total - processed
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
        description='Convert mbox to text file with flexible filtering.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('mbox_file', help='.mbox file to parse')
    parser.add_argument('--to', action='append', help='Filter emails containing TEXT in To: field', metavar='TEXT')
    parser.add_argument('--from', dest='from_', action='append', help='Filter emails containing TEXT in From: field', metavar='TEXT')
    parser.add_argument('--subject', action='append', help='Filter emails containing TEXT in Subject: field', metavar='TEXT')
    parser.add_argument('--save-skipped', metavar='DIR', help='Save skipped emails to mbox files in specified directory')
    
    args = parser.parse_args()
    
    if args.save_skipped:
        os.makedirs(args.save_skipped, exist_ok=True)

    mb = mailbox.mbox(args.mbox_file, create=False)
    for text in mailbox_text(mb, args.to, args.from_, args.subject, args.save_skipped):
        print(text)


if __name__ == '__main__':
    main()