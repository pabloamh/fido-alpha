"""Support for containers."""

import logging
import re
import tempfile
import tarfile
import asyncio
import aiofiles
from pathlib import Path
import gzip
import zipfile 
import bz2
from contextlib import closing
import io

try:
    import olefile
    import pycdlib
except ImportError:
    olefile = None

from xml.etree import ElementTree as etree
from .models import FileFormat, Signature, Pattern
from .char_handler import escape


class Container:
    """Base class for container file processors."""
    def __init__(self, fido_instance):
        self.fido = fido_instance

    def walk(self, filename, fileobj, extension):
        raise NotImplementedError("Subclasses must implement this method")
    """Base class for container file processors."""
    def __init__(self, fido_instance):
        self.fido = fido_instance

    def walk(self, filename, fileobj, extension):
        raise NotImplementedError("Subclasses must implement this method")


class Package():
    """Base class for container support."""

    async def walk(self):
        """Async generator to yield (member_name, member_stream, member_size)."""
        raise NotImplementedError("Subclasses must implement this method.")

    def _process_puid_map(self, data, puid_map):
        results = set() 
        for puid, signatures in puid_map.items():
            results.update(self._process_matches(data, puid, signatures))

        return results

    def _process_matches(self, data, puid, signatures):
        results = []
        for signature in signatures:
            if re.search(signature["signature"], data):
                results.append(puid)

        return results

    async def _process_puid_map_async(self, data, puid_map):
        """Asynchronously process PUID map against data."""
        results = set()
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(None, self._process_matches, data, puid, signatures) for puid, signatures in puid_map.items()]
        for res in await asyncio.gather(*tasks):
            results.update(res)
        return results

    def _process_matches(self, data, puid, signatures):
        """Synchronously match signatures against data."""
        results = []
        for signature in signatures:
            if re.search(signature["signature"], data):
                results.append(puid)
        return results

class OlePackage(Package):
    """OlePackage supports OLE containers."""

    def __init__(self, ole, signatures):
        """Instantiate OlePackage object given the location of its file and signatures."""
        self.ole = ole
        self.signatures = signatures

    def detect_formats(self):
        """Detect available formats inside the OLE container."""
        try:
            with olefile.OleFileIO(self.ole) as ole: # type: ignore
                results = set()
                for path, puid_map in self.signatures.items():
                    # Each OLE container signature lists the path of the file inside the OLE
                    # on which it operates; if the file is missing, there can be no match.
                    # This is not a precise match because the name of the stream may slightly
                    # differ; for example, \x01CompObj instead of CompObj
                    filepath = None
                    for paths in ole.listdir():
                        p = '/'.join(paths)
                        if p == path or p[1:] == path:
                            filepath = p
                            break

                    # Path to match isn't in the container at all
                    if filepath is None:
                        continue

                    with ole.openstream(filepath) as stream:
                        contents = stream.read()
                        results.update(self._process_puid_map(contents, puid_map))

                return results
        except IOError:
            return []

    async def detect_formats_async(self):
        """Asynchronously detect available formats inside the OLE container."""
        try:
            async with aiofiles.open(self.ole, 'rb') as f:
                ole_content = await f.read()
            
            with olefile.OleFileIO(ole_content) as ole:
                results = set()
                for path, puid_map in self.signatures.items():
                    filepath = None
                    for paths in ole.listdir():
                        p = '/'.join(paths)
                        if p == path or p[1:] == path:
                            filepath = p
                            break

                    if filepath is None:
                        continue

                    with ole.openstream(filepath) as stream:
                        contents = stream.read()
                        results.update(await self._process_puid_map_async(contents, puid_map))
                return results
        except (IOError, asyncio.CancelledError):
            return []


class ZipPackage(Package):
    """ZipPackage supports Zip containers."""

    def __init__(self, zip_, signatures):
        """Instantiate ZipPackage object given the location of its file and signatures."""
        self.zip = zip_
        self.signatures = signatures

    def detect_formats(self):
        """Detect available formats inside the ZIP container."""
        try:
            with zipfile.ZipFile(self.zip) as zip_:
                results = set()
                for path, puid_map in self.signatures.items():
                    # Each ZIP container signature lists the path of the file inside the ZIP
                    # on which it operates; if the file is missing, there can be no match.
                    if path not in zip_.namelist():
                        continue

                    # Extract the requested file from the ZIP only once, and pass the same
                    # data to each signature that requires it.
                    with zip_.open(path) as id_file:
                        contents = id_file.read()
                        results.update(self._process_puid_map(contents, puid_map))

                return results
        except (zipfile.BadZipfile, RuntimeError, UnicodeDecodeError):
            return []
    
    async def detect_formats_async(self):
        """Asynchronously detect available formats inside the ZIP container."""
        try:
            async with aiofiles.open(self.zip, 'rb') as f:
                zip_content = await f.read()
            
            with zipfile.ZipFile(io.BytesIO(zip_content)) as zip_:
                results = set()
                for path, puid_map in self.signatures.items():
                    if path in zip_.namelist():
                        contents = zip_.read(path)
                        results.update(await self._process_puid_map_async(contents, puid_map))
                return results
        except (zipfile.BadZipfile, RuntimeError, UnicodeDecodeError, asyncio.CancelledError):
            return []


async def _parse_cue_sheet_async(filename: str) -> str | None:
    """
    A simple, modern async CUE sheet parser to extract the binary file name.
    This avoids the `cueparser` dependency which relies on `six`.
    """
    file_pattern = re.compile(r'^\s*FILE\s+"([^"]+)"', re.IGNORECASE)
    async with aiofiles.open(filename, mode='r', encoding='utf-8', errors='ignore') as f:
        async for line in f:
            match = file_pattern.match(line)
            if match:
                return match.group(1)
    return None

class TarPackage(Package):
    """TarPackage supports TAR archives."""

    def __init__(self, filename, signatures=None):
        self.filename = filename
        self.signatures = signatures

    async def walk(self):
        """Walk through TAR file members."""
        try:
            with tarfile.open(self.filename, 'r') as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        yield member.name, tar.extractfile(member), member.size
        except tarfile.TarError:
            return

class GzipPackage(Package):
    """GzipPackage supports Gzip compressed files."""

    def __init__(self, filename):
        self.filename = filename

    async def walk(self):
        """Decompress and yield the single member of a Gzip file."""
        try:
            path = Path(self.filename)
            # Gzip only contains one file, so we derive the name from the archive name.
            member_name = path.stem
            with gzip.open(self.filename, 'rb') as f:
                content = f.read()
                yield member_name, io.BytesIO(content), len(content)
        except (gzip.BadGzipFile, EOFError):
            return

class Bzip2Package(Package):
    """Bzip2Package supports Bzip2 compressed files."""

    def __init__(self, filename):
        self.filename = filename

    async def walk(self):
        """Decompress and yield the single member of a Bzip2 file."""
        try:
            path = Path(self.filename)
            member_name = path.stem
            with bz2.open(self.filename, 'rb') as f:
                content = f.read()
                yield member_name, io.BytesIO(content), len(content)
        except OSError: # bz2 raises OSError for invalid files
            return

class IsoPackage(Package):
    """IsoPackage supports ISO 9660 disk images."""

    def __init__(self, filename):
        self.filename = filename

    async def walk(self):
        """Walk through files in an ISO image."""
        if pycdlib is None:
            logging.warning("pycdlib is not installed. ISO support is disabled.")
            return

        try:
            iso = pycdlib.PyCdlib()
            iso.open(self.filename)
            for dirname, _, filelist in iso.walk(iso_path='/'):
                for filename in filelist:
                    iso_path = f"{dirname}/{filename}"
                    try:
                        member_stream = iso.get_file_from_iso(iso_path=iso_path)
                        # pycdlib doesn't easily give file size, so we read the stream
                        content = member_stream.read()
                        yield iso_path.lstrip('/'), io.BytesIO(content), len(content)
                    except pycdlib.pycdlibexception.PyCdlibInvalidInput:
                        continue # Skip unreadable files
            iso.close()
        except (pycdlib.pycdlibexception.PyCdlibInvalidInput, IOError):
            return

class CueBinPackage(Package):
    """CueBinPackage supports CUE/BIN disk images."""

    def __init__(self, filename):
        self.filename = filename

    async def walk(self):
        """Walk through files in a CUE/BIN image."""
        if pycdlib is None:
            logging.warning("pycdlib is not installed. CUE/BIN support is disabled.")
            return

        bin_filename = await _parse_cue_sheet_async(self.filename)
        if not bin_filename:
            logging.warning("Could not find a FILE directive in CUE sheet: %s", self.filename)
            return

        bin_file = Path(self.filename).parent / bin_filename
        if bin_file.exists():
            iso_package = IsoPackage(str(bin_file))
            async for member_info in iso_package.walk():
                yield member_info


class ZipContainer(Container):
    """Processes files within a Zip archive."""

    def walk(self, filename, fileobj=None, extension=True):
        try:
            with zipfile.ZipFile((fileobj if fileobj else filename), 'r') as zipstream:
                for item in zipstream.infolist():
                    if item.is_dir() or item.file_size == 0:
                        continue
                    
                    with zipstream.open(item) as f:
                        item_name = f"{filename}!{item.filename}"
                        self.fido.process_stream(f, item_name, item.file_size, extension)

                        # Recurse into nested containers
                        # Note: This part is simplified. A full implementation would need
                        # to handle the matches and container types more robustly.
                        # For now, we focus on the structural refactoring.

        except (IOError, zipfile.BadZipfile):
            raise RuntimeError(f"FIDO: ZipError {filename}\n")


class TarContainer(Container):
    """Processes files within a Tar archive."""

    def walk(self, filename, fileobj, extension=True):
        try:
            with tarfile.TarFile(filename, fileobj=fileobj, mode='r') as tarstream:
                for item in tarstream.getmembers():
                    if not item.isfile():
                        continue
                    
                    with closing(tarstream.extractfile(item)) as f:
                        item_name = f"{filename}!{item.name}"
                        self.fido.process_stream(f, item_name, item.size, extension)

                        # Recurse into nested containers
                        # As with ZipContainer, this is a simplified representation.

        except tarfile.TarError:
            raise RuntimeError(f"FIDO: Error: TarError {filename}\n")


def get_container_handler(fido_instance, container_type):
    """Factory function to get the appropriate container handler."""
    if container_type == 'zip':
        return ZipContainer(fido_instance)
    if container_type == 'tar':
        return TarContainer(fido_instance)
    return None


class SignatureLoader:
    """Loads and parses signature files into FileFormat objects."""

    def __init__(self, conf_dir, format_files, containersignature_file):
        self.conf_dir = conf_dir
        self.format_files = format_files
        self.containersignature_file = containersignature_file
        self.formats = []
        self.puid_format_map = {}

    def load_signatures(self):
        """Load all signature files and return a map of PUIDs to FileFormat objects."""
        for xml_file in self.format_files:
            self._load_fido_xml(Path(self.conf_dir).resolve().joinpath(xml_file))
        
        # The container signature logic could also be moved into this loader
        # for better encapsulation, but we'll leave it for a future refactoring.

        return self.puid_format_map

    def _load_fido_xml(self, file_path):
        """Load a FIDO format XML file and parse it."""
        try: # type: ignore
            tree = etree.parse(str(file_path))
            for element in tree.xpath('/formats/format'):
                self._process_format_element(element)
        except (etree.ParseError, IOError) as e:
            raise RuntimeError(f"Failed to parse signature file {file_path}: {e}")

    def _process_format_element(self, element):
        """Parse an XML element into a FileFormat object."""
        puid = element.findtext('puid')
        if not puid:
            return

        mime_element = element.find('mime')
        container_element = element.find('container')
        version_element = element.find('version')

        file_format = FileFormat(
            puid=puid,
            name=element.findtext('name', ''),
            version=version_element.text if version_element is not None else None,
            container=container_element.text if container_element is not None else None,
            mime=mime_element.text if mime_element is not None else None,
            extensions=[ext.text for ext in element.findall('extension') if ext.text],
            has_priority_over={
                p.text for p in element.findall('has_priority_over') if p.text
            },
        )

        for sig_element in element.findall('signature'):
            signature = Signature(
                name=sig_element.findtext('name', ''),
                note=sig_element.findtext('note'),
                patterns=[]
            )
            for pat_element in sig_element.findall('pattern'):
                regex_text = pat_element.findtext('regex')
                if regex_text:
                    try:
                        compiled_regex = re.compile(regex_text.encode('utf8'))
                        pattern = Pattern(
                            position=pat_element.findtext('position', 'BOF'),
                            regex=compiled_regex,
                            pronom_pattern=pat_element.findtext('pronom_pattern', '')
                        )
                        signature.patterns.append(pattern)
                    except re.error:
                        # Skip invalid regex patterns
                        continue
            if signature.patterns:
                file_format.signatures.append(signature)

        if puid in self.puid_format_map:
            self.formats[self.formats.index(self.puid_format_map[puid])] = file_format
        else:
            self.formats.append(file_format)
        self.puid_format_map[puid] = file_format
