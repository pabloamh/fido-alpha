#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FIDO SIGNATURE UPDATER.

Open Planets Foundation (http://www.openplanetsfoundation.org)
See License.txt for license information.
Download from: https://github.com/openplanets/fido/releases
Author: Maurice de Rooij (NANETH), 2012

FIDO uses the UK National Archives (TNA) PRONOM File Format and Container descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/.
"""

from argparse import ArgumentParser
from shutil import rmtree
import logging
import sys
import time
from xml.etree import ElementTree as CET
import zipfile
from pathlib import Path

from . import __version__, CONFIG_DIR, query_yes_no 
from .prepare import run as prepare_pronom_to_fido
from .versions import get_local_versions
from .pronom.soap import get_pronom_sig_version, get_droid_signatures, NS
from .pronom.http import get_sig_xml_for_puid

ABORT_MSG = 'Aborting update...'

DEFAULTS = {
    'signatureFileName': 'DROID_SignatureFile-v{0}.xml',
    'pronomZipFileName': 'pronom-xml-v{0}.zip',
    'fidoSignatureVersion': 'format_extensions.xml',
    'containerVersion': 'container-signature-UPDATE-ME.xml',  # container version is frozen and needs human attention before updating,
}

OPTIONS = {
    'http_throttle': 0.5,  # in secs, to prevent DoS of PRONOM server
    'tmp_dir': Path(CONFIG_DIR) / 'tmp',
    'deleteTempDirectory': True,
    'version': 'latest',
}


def run(defaults=None):
    """
    Update PRONOM signatures.

    Interactive script, requires keyboard input.
    """
    print("FIDO signature updater v{}".format(__version__))
    options = {**OPTIONS, **(defaults or {})}
    try:
        logging.info("Contacting PRONOM...")
        latest, sig_file = sig_version_check(options.get('version'))
        download_sig_file(latest, sig_file)
        logging.info("Extracting PRONOM PUID's from signature file...")
        tree = CET.parse(sig_file)
        format_eles = tree.findall('.//sig:FileFormat', NS)
        logging.info("Found %s PRONOM FileFormat elements", len(format_eles))
        tmpdir, resume = init_sig_download(options)
        download_signatures(options, format_eles, resume, tmpdir)
        create_zip_file(options, format_eles, latest, tmpdir)
        if options['deleteTempDirectory']:
            logging.info("Deleting temporary folder and files...")
            rmtree(tmpdir, ignore_errors=True)
        update_versions_xml(latest)

        logging.info("Preparing to convert PRONOM formats to FIDO signatures...")
        prepare_pronom_to_fido()
        logging.info("FIDO signatures successfully updated")

    except KeyboardInterrupt:
        sys.exit(ABORT_MSG)


def sig_version_check(version='latest'):
    """Return a tuple consisting of current sig file version and the derived file name."""
    logging.info('Sig version check for version: %s', version)
    if version == 'latest':
        logging.info('Getting latest version number from PRONOM...')
        version = get_pronom_sig_version()
        if not version:
            sys.exit('Failed to obtain PRONOM signature file version number, please try again.')

    logging.info('Querying PRONOM for signaturefile version %s.', version)
    sig_file_name = _sig_file_name(version)
    if sig_file_name.is_file():
        logging.warning("You already have the PRONOM signature file, version %s", version)
        if not query_yes_no("Update anyway?"):
            sys.exit(ABORT_MSG)
    return version, sig_file_name


def _sig_file_name(version):
    return Path(CONFIG_DIR) / DEFAULTS['signatureFileName'].format(version)


def download_sig_file(version, sig_file):
    """Download the latest version of the PRONOM sigs to signatureFile."""
    logging.info("Downloading signature file version %s...", version)
    sig_xml, _ = get_droid_signatures(version)
    if not sig_xml:
        sys.exit('Failed to obtain PRONOM signature file, please try again.')
    logging.info("Writing %s...", sig_file.name)
    with open(sig_file, 'w') as file_:
        file_.write(sig_xml)


def init_sig_download(defaults):
    """
    Initialise the download of individual PRONOM signatures.

    Handles user input and resumption of interupted downloads.
    Return a tuple of the temp directory for writing and a boolean resume flag.
    """
    logging.info("Downloading signatures can take a while")
    if not query_yes_no("Continue and download signatures?"):
        sys.exit(ABORT_MSG)
    tmpdir = defaults['tmp_dir']
    resume = False
    if tmpdir.is_dir():
        logging.info("Found previously created temporary folder for download: %s", tmpdir)
        resume = query_yes_no('Do you want to resume download (yes) or start over (no)?')
        if resume:
            logging.info("Resuming download...")
    else:
        print("Creating temporary folder for download:", tmpdir)
        try:
            tmpdir.mkdir()
        except OSError:
            pass
    if not tmpdir.is_dir():
        sys.stderr.write("Failed to create temporary folder for PUID's, using: " + tmpdir)
    return tmpdir, resume


def download_signatures(defaults, format_eles, resume, tmpdir):
    """Download PRONOM signatures and write to individual files."""
    logging.info("Downloading signatures, one moment please...")
    puid_count = len(format_eles)
    one_percent = (float(puid_count) / 100)
    numfiles = 0
    for format_ele in format_eles:
        download_sig(format_ele, tmpdir, resume, defaults)
        numfiles += 1
        sys.stdout.write(r"Downloaded {}/{} files [{}%]".format(numfiles, puid_count, int(float(numfiles) / one_percent)) + "\r")
    sys.stdout.write("\n")


def download_sig(format_ele, tmpdir, resume, defaults):
    """
    Download an individual PRONOM signature.

    The signature to be downloaded is identified by the FileFormat element
    parameter format_ele. The downloaded signature is written to tmpdir.
    """
    puid, puid_filename = get_puid_file_name(format_ele)
    filename = tmpdir / puid_filename
    if filename.is_file() and resume:
        return
    try:
        xml = get_sig_xml_for_puid(puid)
    except Exception as e:
        logging.error("Failed to download signature file: %s", puid)
        logging.error("Error: %s", e)
        return
    with open(str(filename), 'wb') as file_:
        file_.write(xml)
    time.sleep(defaults['http_throttle'])


def create_zip_file(options, format_eles, version, tmpdir):
    """Create zip file of signatures."""
    logging.info("Creating PRONOM zip...")
    compression = zipfile.ZIP_DEFLATED if 'zlib' in sys.modules else zipfile.ZIP_STORED
    zip_path = Path(CONFIG_DIR) / options['pronomZipFileName'].format(version)
    with zipfile.ZipFile(str(zip_path), mode='w', compression=compression) as zf:
        print("Adding files with compression mode", zipfile.compression_names[compression])
        for format_ele in format_eles:
            _, puid_filename = get_puid_file_name(format_ele)
            filename = tmpdir / puid_filename
            if filename.is_file():
                zf.write(str(filename), arcname=puid_filename)
                if options['deleteTempDirectory']:
                    filename.unlink()


def get_puid_file_name(format_ele):
    """Return a tupe of PUID and PUID file name derived from format_ele."""
    puid = format_ele.get('PUID')
    type_part, num_part = puid.split("/")
    return puid, 'puid.{}.{}.xml'.format(type_part, num_part)


def update_versions_xml(version):
    """Create new versions identified sig XML file."""
    logging.info('Updating versions.xml...')
    versions = get_local_versions()
    versions.pronom_version = str(version)
    versions.pronom_signature = "formats-v" + str(version) + ".xml"
    versions.pronom_container_signature = DEFAULTS['containerVersion']
    versions.fido_extension_signature = DEFAULTS['fidoSignatureVersion']
    versions.update_script = __version__
    versions.write()


def main():
    """Main CLI entrypoint."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    parser = ArgumentParser(description='Download and convert the latest PRONOM signatures')
    parser.add_argument('-tmpdir', default=OPTIONS['tmp_dir'], help='Location to store temporary files', dest='tmp_dir')
    parser.add_argument('-keep_tmp', default=OPTIONS['deleteTempDirectory'], help='Do not delete temporary files after completion', dest='deleteTempDirectory', action='store_false')
    parser.add_argument('-http_throttle', default=OPTIONS['http_throttle'], help='Time (in seconds) to wait between downloads', type=float, dest='http_throttle')
    parser.add_argument('-version', default=OPTIONS['version'], help='Download and convert a specific signature file by version', dest='version')
    args = parser.parse_args()
    opts = DEFAULTS.copy()
    opts.update(vars(args))
    run(opts)


if __name__ == '__main__':
    main()
