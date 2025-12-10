"""Character handling routines for Format Identification for Digital Objects (FIDO)."""

# \a\b\n\r\t\v
# MdR: took out '<' and '>' out of _ordinary because they were converted to entities &lt;&gt;
# MdR: moved '!' from _ordinary to _special because it means "NOT" in the regex world. At this time no regex in any sig has a negate set, did this to be on the safe side
ORDINARY = frozenset(' "#%&\',-/0123456789:;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~')
SPECIAL = '$()*+.?![]^\\{|}'  # Before: '$*+.?![]^\\{|}'
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
