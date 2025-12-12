"""
FIDO Configuration

This module holds the default configuration for the FIDO application.
"""

DEFAULTS = {
    'bufsize': 128 * 1024,  # (bytes)
    'regexcachesize': 2084,  # (bytes)
    'printmatch': "OK,{info.time},{info.puid},\"{info.formatname}\",\"{info.signaturename}\",{info.filesize},\"{info.filename}\",\"{info.mimetype}\",\"{info.matchtype}\"\n",
    'printnomatch': "KO,{info.time},,,,{info.filesize},\"{info.filename}\",,\"{info.matchtype}\"\n",
    'format_files': [
        'formats-v116.xml',
        'format_extensions.xml'
    ],
    'containersignature_file': 'container-signature-20231127.xml',
    'container_bufsize': 512 * 1024,  # (bytes)
    'description': """Format Identification for Digital Objects (fido).
FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.""",
    'epilog': """
Open Preservation Foundation (http://www.openpreservation.org)
See License.txt for license information.
Download from: https://github.com/openpreserve/fido/releases
Author: Adam Farquhar (BL), 2010
FIDO uses the UK National Archives (TNA) PRONOM File Format descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/""",
}

PRONOM_DEFAULTS = {
    'pronom_url': "http://www.nationalarchives.gov.uk/pronom/{puid}.xml",
    'droid_sig_url': "https://cdn.nationalarchives.gov.uk/documents/DROID_SignatureFile_V{version}.xml",
    'pronom_service_url': 'http://www.nationalarchives.gov.uk/pronom/service.asmx',
}