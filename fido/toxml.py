"""
FIDO CSV output to XML.

Author: Maurice de Rooij <maurice.de.rooij@nationaalarchief.nl>, September 2011

Usage in combination with FIDO:
- Windows: python fido.py [ARGS] | python toxml.py > output.xml
- Linux: fido.py [ARGS] | toxml.py > output.xml

Usage afterwards:
- Windows: type output.csv | toxml.py > output.xml
- Linux: cat output.csv | toxml.py > output.xml

For difference in usage, see:
- http://bugs.python.org/issue9390
- http://support.microsoft.com/default.aspx?kbid=321788
"""

import csv
import sys

from . import __version__ 
from .versions import get_local_versions


def main():
    """Generate XML as read from CSV and send it to the standard output stream."""
    versions = get_local_versions()
    sys.stdout.write(f'''<?xml version="1.0" encoding="utf-8"?>
<fido_output>
    <versions>
        <fido_version>{__version__}</fido_version>
        <signature_version>{versions.pronom_version}</signature_version>
    </versions>''')

    reader = csv.reader(sys.stdin)

    for row in reader:
        sys.stdout.write(f'''
    <file>
        <filename>{row[6]}</filename>
        <status>{row[0]}</status>
        <matchtype>{row[8]}</matchtype>
        <time>{row[1]}</time>
        <puid>{row[2]}</puid>
        <mimetype>{row[7]}</mimetype>
        <formatname>{row[3]}</formatname>
        <signaturename>{row[4]}</signaturename>
        <filesize>{row[5]}</filesize>
    </file>''')

    sys.stdout.write("\n</fido_output>\n")


if __name__ == '__main__':
    main()
