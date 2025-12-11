"""
Format Identification for Digital Objects (FIDO).

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""

from os.path import abspath, dirname, join


__version__ = '1.6.1'


CONFIG_DIR = join(abspath(dirname(__file__)), 'conf')
