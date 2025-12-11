"""
Format Identification for Digital Objects (FIDO).

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""

from pathlib import Path

__version__ = '1.6.1'


CONFIG_DIR = Path(__file__).parent.resolve() / 'conf'
