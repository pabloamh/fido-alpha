"""Character handling routines for Format Identification for Digital Objects (FIDO)."""

import string

ORDINARY = frozenset(string.ascii_letters + string.digits + ' \'"#%&,./:;=@_~')
SPECIAL = frozenset('$()*+.?![]^\\{|}')
HEX = '0123456789abcdef'


def escape_char(c):
    """Add appropriate escape sequence to passed character c."""
    escape_map = {'\n': '\\n', '\r': '\\r'}
    if c in escape_map:
        return escape_map[c]
    if c in SPECIAL:
        return '\\' + c
    return f'\\x{ord(c):02x}'


def escape(string):
    """Escape characters in pattern that are non-printable, non-ascii, or special for regexes."""
    return ''.join(c if c in ORDINARY else escape_char(c) for c in string)
