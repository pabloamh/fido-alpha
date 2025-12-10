"""Support for containers."""

import re
import tempfile
import tarfile
from pathlib import Path
import zipfile
import olefile 
from contextlib import closing
from xml.etree import ElementTree as ET

from .models import FileFormat, Signature, Pattern
from .char_handler import escape


class Container:
    """Base class for container file processors."""
    def __init__(self, fido_instance):
        self.fido = fido_instance

    def walk(self, filename, fileobj, extension):
        raise NotImplementedError("Subclasses must implement this method")


class Package():
    """Base class for container support."""

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
        try:
            tree = ET.parse(file_path)
            for element in tree.getroot().findall('./format'):
                self._process_format_element(element)
        except (ET.ParseError, IOError) as e:
            raise RuntimeError(f"Failed to parse signature file {file_path}: {e}")

    def _process_format_element(self, element):
        """Parse an XML element into a FileFormat object."""
        puid = element.findtext('puid')
        if not puid:
            return

        mime_element = element.find('mime')
        version_element = element.find('version')

        file_format = FileFormat(
            puid=puid,
            name=element.findtext('name', ''),
            version=version_element.text if version_element is not None else None,
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
