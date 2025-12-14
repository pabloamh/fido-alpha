"""
FIDO SIGNATURE UPDATER.

Open Planets Foundation (http://www.openplanetsfoundation.org)
See License.txt for license information. 
Download from: https://github.com/openplanets/fido/releases
Author: Maurice de Rooij (NANETH), 2012

FIDO uses the UK National Archives (TNA) PRONOM File Format and Container descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/.
"""
import asyncio
import aiohttp
from argparse import ArgumentParser
import logging
import sys
import time
from xml.etree import ElementTree as CET
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

from . import __version__, CONFIG_DIR, FidoError
from .prepare import run as prepare_pronom_to_fido
from .pronom import PronomClient
from .versions import get_local_versions
from .cli import query_yes_no

ABORT_MSG = 'Aborting update...'
class UpdateSignaturesError(FidoError):
    """Update Signatures Error."""

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


async def run_async(defaults=None) -> None:
    """
    Asynchronously update PRONOM signatures.

    Interactive script, requires keyboard input.
    """
    print("FIDO signature updater v{}".format(__version__))
    options = {**OPTIONS, **(defaults or {})}
    pronom_client = PronomClient()
    try:
        logging.info("Contacting PRONOM...")
        latest, sig_file = await sig_version_check_async(pronom_client, options.get('version'))
        await download_sig_file_async(pronom_client, latest, sig_file)
        logging.info("Extracting PRONOM PUID's from signature file...")
        tree = CET.parse(str(sig_file))
        format_eles = tree.findall('.//sig:FileFormat', pronom_client.ns)
        logging.info("Found %s PRONOM FileFormat elements", len(format_eles))
        tmpdir, resume = init_sig_download(options) # type: ignore
        await download_signatures_async(pronom_client, options, format_eles, resume, tmpdir)
        create_zip_file(options, format_eles, latest, tmpdir)
        if options['deleteTempDirectory']:
            logging.info("Deleting temporary folder and files...")
            # shutil.rmtree is blocking, but acceptable for this cleanup task.
            from shutil import rmtree
            rmtree(tmpdir, ignore_errors=True)
        update_versions_xml(latest)

        logging.info("Preparing to convert PRONOM formats to FIDO signatures...")
        prepare_pronom_to_fido()
        logging.info("FIDO signatures successfully updated")

    except (KeyboardInterrupt, UpdateSignaturesError):
        sys.exit(ABORT_MSG)
    finally:
        await pronom_client.close_async_session()

async def sig_version_check_async(pronom_client: PronomClient, version: str = 'latest') -> Tuple[int, Path]:
    """Return a tuple consisting of current sig file version and the derived file name."""
    logging.info('Sig version check for version: %s', version)
    if version == 'latest':
        logging.info('Getting latest version number from PRONOM...')
        version = await pronom_client.get_pronom_sig_version_async()
        if not isinstance(version, int):
            raise RuntimeError('Failed to obtain PRONOM signature file version number, please try again.')

    logging.info('Querying PRONOM for signaturefile version %s.', version)
    sig_file_name = _sig_file_name(version)
    if sig_file_name.is_file():
        logging.warning("You already have the PRONOM signature file, version %s", version)
        if not query_yes_no("Update anyway?"):
            raise UpdateSignaturesError(ABORT_MSG)
    return version, sig_file_name


def _sig_file_name(version: int) -> Path:
    return Path(CONFIG_DIR) / DEFAULTS['signatureFileName'].format(version)


async def download_sig_file_async(pronom_client: PronomClient, version: int, sig_file: Path) -> None:
    """Download the latest version of the PRONOM sigs to signatureFile."""
    logging.info("Downloading signature file version %s...", version)
    sig_xml, _ = await pronom_client.get_droid_signatures_async(version)
    if not sig_xml:
        raise RuntimeError('Failed to obtain PRONOM signature file, please try again.')
    logging.info("Writing %s...", sig_file.name)
    with open(sig_file, 'w') as file_:
        file_.write(sig_xml)


def init_sig_download(defaults: Dict) -> Tuple[Path, bool]:
    """
    Initialise the download of individual PRONOM signatures.

    Handles user input and resumption of interupted downloads.
    Return a tuple of the temp directory for writing and a boolean resume flag.
    """
    logging.info("Downloading signatures can take a while")
    if not query_yes_no("Continue and download signatures?"):
        raise InterruptedError(ABORT_MSG)
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


async def download_sig(pronom_client: PronomClient, format_ele: CET.Element, tmpdir: Path, resume: bool, defaults: Dict) -> None:
    """
    Asynchronously download an individual PRONOM signature.
    """
    puid, puid_filename = get_puid_file_name(format_ele)
    filename = tmpdir / puid_filename
    if filename.is_file() and resume:
        return
    try:
        xml = await pronom_client.get_sig_xml_for_puid_async(puid)
        with open(str(filename), 'wb') as file_:
            file_.write(xml)
        time.sleep(defaults['http_throttle'])
    except Exception as e:
        logging.error("Failed to download signature file: %s. Error: %s", puid, e)

async def download_signatures_async(pronom_client: PronomClient, defaults: Dict, format_eles: List[CET.Element], resume: bool, tmpdir: Path) -> None:
    """Download PRONOM signatures and write to individual files."""
    logging.info("Downloading signatures, one moment please...")
    tasks = [download_sig(pronom_client, format_ele, tmpdir, resume, defaults) for format_ele in format_eles]
    puid_count = len(tasks)
    for i, f in enumerate(asyncio.as_completed(tasks)):
        await f
        progress = (i + 1) / puid_count
        sys.stdout.write(f"\rDownloaded {i+1}/{puid_count} files [{int(progress * 100)}%]")
        sys.stdout.flush()
    print("\nDownload complete.")


def create_zip_file(options: Dict, format_eles: List[CET.Element], version: int, tmpdir: Path) -> None:
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

def get_puid_file_name(format_ele: CET.Element) -> Tuple[str, str]:
    """Return a tupe of PUID and PUID file name derived from format_ele."""
    puid = format_ele.get('PUID')
    type_part, num_part = puid.split("/")
    return 'puid.{}.{}.xml'.format(type_part, num_part)


def update_versions_xml(version: int) -> None:
    """Create new versions identified sig XML file."""
    logging.info('Updating versions.xml...')
    versions = get_local_versions()
    versions.pronom_version = str(version)
    versions.pronom_signature = "formats-v" + str(version) + ".xml"
    versions.pronom_container_signature = DEFAULTS['containerVersion']
    versions.fido_extension_signature = DEFAULTS['fidoSignatureVersion']
    versions.update_script = __version__
    versions.write()


def run(defaults=None) -> None:
    """Synchronous wrapper for the async run function."""
    asyncio.run(run_async(defaults))


def main(args=None) -> None:
    """Main CLI entrypoint."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    parser = ArgumentParser(description='Download and convert the latest PRONOM signatures', fromfile_prefix_chars='@')
    parser.add_argument('-tmpdir', help='Location to store temporary files', dest='tmp_dir')
    parser.add_argument('-keep_tmp', help='Do not delete temporary files after completion', dest='deleteTempDirectory', action='store_false')
    parser.add_argument('-http_throttle', help='Time (in seconds) to wait between downloads', type=float, dest='http_throttle')
    parser.add_argument('-version', help='Download and convert a specific signature file by version', dest='version')
    args = parser.parse_args(args)
    run(vars(args))


if __name__ == '__main__':
    main()
