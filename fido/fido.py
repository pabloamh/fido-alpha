"""
Format Identification for Digital Objects (FIDO).

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""
import asyncio
import re
from collections import deque
from pathlib import Path
from aiopath import AsyncPath
from xml.etree import ElementTree as ET

from fido import __version__, CONFIG_DIR
from fido.config import DEFAULTS
from fido.package import OlePackage, SignatureLoader, ZipPackage
from fido.char_handler import escape
from fido.utils import perf_counter, query_yes_no
from fido.models import FileFormat
from typing import List, Dict, Tuple, Optional, Any, IO, Union, AsyncIterator

try:
    from lxml import etree
except ImportError:
    from xml.etree import ElementTree as etree

class Fido:
    """Main FIDO application class."""

    def __init__(self, conf_dir: Union[str, Path] = CONFIG_DIR, format_files: Optional[List[str]] = None, containersignature_file: Optional[str] = None) -> None:
        """Initialise a FIDO class instance."""
        self.bufsize = DEFAULTS['bufsize']
        self.container_bufsize = DEFAULTS['container_bufsize']
        self.conf_dir = conf_dir
        format_files = format_files or DEFAULTS['format_files']

        loader = SignatureLoader(conf_dir, format_files, containersignature_file)
        self.puid_format_map = loader.load_signatures()
        self.formats = loader.formats

        self.zip_signatures = None
        self.ole_signatures = None
        if containersignature_file:
            self.load_container_signatures(containersignature_file)
            self.containersignature_file: Optional[str] = containersignature_file
        else:
            self.containersignature_file = None

        self.current_count = 0  # Count of calls to match_formats
        self.current_file: Optional[str] = None
        self.current_filesize: int = 0
        re._MAXCACHE = DEFAULTS['regexcachesize']
        self.externalsig = ET.XML('<signature><name>External</name></signature>')

    def load_container_signatures(self, containersignature_file: str) -> None:
        """Load container signatures."""
        if self.containersignature_file is None:
            return
        container_file = Path(self.conf_dir).joinpath(containersignature_file)
        self.zip_signatures = self.extract_signatures(container_file, signature_type="ZIP")
        self.ole_signatures = self.extract_signatures(container_file, signature_type="OLE")

    def convert_container_sequence(self, sig: str) -> bytes:
        """Parse the PRONOM container sequences and convert to regular expressions."""
        # This is a direct port of the original Java logic.
        # It can be complex to follow but it is a faithful implementation.
        # A future improvement would be to refactor this to be more Pythonic.
        sequence = b'(?s)'
        in_quotes = False
        in_range = False
        is_byte = False
        range_or = False
        i = 0
        while i < len(sig):
            char = sig[i]
            if not in_quotes and not in_range:
                if char == "'":
                    in_quotes = True
                elif char in " \n":
                    pass
                elif char == "[":
                    sequence += b'('
                    in_range = True
                elif not is_byte:
                    sequence += b'\\x' + char.lower().encode('utf8')
                    is_byte = True
                elif is_byte:
                    sequence += char.lower().encode('utf8')
                    is_byte = False
            elif in_quotes:
                if char == "'" and not in_range:
                    in_quotes = False
                else:
                    sequence += escape(char).encode('utf8')
            elif in_range:
                if char == ']':
                    sequence += b')'
                    in_range = False
                # This part of the logic is complex and may need further review
                # For now, we are keeping it as close to the original as possible
                # to ensure correctness.
                elif char in " -'":
                    sequence += b'|'
                else:
                    sequence += escape(char).encode('utf8')
            i += 1
        return sequence

    def extract_signatures(self, doc: Path, signature_type: str = "ZIP") -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Given an XML container signature file, returns a dictionary of signatures.

        The format of the dictionary is:

        {
            "path_to_file_inside_zip": {"puid": [signature_details]}
        }
        """
        tree = etree.parse(str(doc))

        def format_signature_attributes(element: ET.Element) -> Dict[str, Any]:
            return {
                "path": element.findtext("Files/File/Path"),
                "id": element.attrib["Id"],
                "signature": self.convert_container_sequence(element.findtext("Files/File/BinarySignatures/InternalSignatureCollection/InternalSignature/ByteSequence/SubSequence/Sequence"))
            }

        elements = tree.xpath(f"//ContainerSignature[@ContainerType='{signature_type}']")
        signatures = {}
        for el in elements:
            if el.find("Files/File/BinarySignatures") is None:
                continue

            puid_element = tree.xpath(f"//FileFormatMapping[@signatureId='{el.attrib['Id']}']")
            if not puid_element:
                continue
            puid = puid_element[0].attrib["Puid"]
            signature = format_signature_attributes(el)
            path = signature["path"]
            if path not in signatures:
                signatures[path] = {}
            if puid not in signatures[path]:
                signatures[path][puid] = []
            signatures[path][puid].append(format_signature_attributes(el))
        return signatures

    def identify_file(self, filename: str, extension: bool = True) -> List[Dict[str, Any]]:
        """
        Identify the type of @param filename.

        If the file is a container, it will also identify the contents.
        Returns a list of match dictionaries.
        """
        matches = []
        size: int = Path(filename).stat().st_size
        with open(str(filename), 'rb') as f:
            bofbuffer, eofbuffer, _ = self.get_buffers(f, size, seekable=True)
        
        signature_matches = self.match_formats(bofbuffer, eofbuffer)
        matches.extend(self._format_matches(signature_matches, filename, "signature"))

        container_type = self.container_type(signature_matches)
        if container_type:
            matches.extend(self.match_container_contents(filename, container_type))

        if not matches and extension:
            extension_matches = self.match_extensions(filename)
            matches.extend(self._format_matches(extension_matches, filename, "extension"))

        return matches

    async def identify_file_async(self, filename: str, extension: bool = True) -> List[Dict[str, Any]]:
        """
        Asynchronously identify the type of @param filename.

        If the file is a container, it will also identify the contents.
        Returns a list of match dictionaries.
        """
        matches = []
        apath = AsyncPath(filename)
        size: int = (await apath.stat()).st_size
        async with apath.open('rb') as f:
            bofbuffer, eofbuffer, _ = await self.get_buffers_async(f, size, seekable=True)

        signature_matches = self.match_formats(bofbuffer, eofbuffer)
        matches.extend(self._format_matches(signature_matches, filename, "signature"))

        container_type = self.container_type(signature_matches)
        if container_type:
            matches.extend(await self.match_container_contents_async(filename, container_type))

        if not matches and extension:
            extension_matches = self.match_extensions(filename)
            matches.extend(self._format_matches(extension_matches, filename, "extension"))

        return matches

    def identify_stream(self, stream: IO[bytes], filename: Optional[str], extension: bool = True) -> Tuple[List[Dict[str, Any]], int]:
        """
        Identify the type of @param stream.

        Call self.handle_matches instead of returning a value.
        Does not close stream.
        Returns a list of match tuples.
        """
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream, length=None)
        signature_matches = self.match_formats(bofbuffer, eofbuffer)
        
        formatted_matches = self._format_matches(signature_matches, filename or 'stream', 'stream')

        if not formatted_matches and extension and filename:
            extension_matches = self.match_extensions(filename)
            formatted_matches.extend(self._format_matches(extension_matches, filename, "extension"))

        return formatted_matches, bytes_read

    def container_type(self, matches: List[Dict[str, Any]]) -> Union[str, bool]:
        """
        Return true if this is a container type.

        Determine if one of the @param matches is the format of a container
        that we can look inside of (e.g., zip, tar).
        @return False, zip, or tar.
        """
        for match in matches:
            format_ = match['format']
            container = format_.find('container')
            if container is not None:
                return container.text

            # aside from checking <container> elements,
            # check for fmt/111, which is OLE
            puid = format_.find('puid')
            if puid is not None and puid.text == 'fmt/111':
                return 'ole'
        return False

    def blocking_read(self, file: IO[bytes], bytes_to_read: int) -> bytes:
        """Perform a blocking read and return the buffer."""
        bytes_read = 0
        buffer = b''
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            buffer += readbuffer
            bytes_read = len(buffer)
            # break out if EOF is reached.
            if readbuffer == '':
                break
        return buffer

    def get_buffers(self, stream: IO[bytes], length: Optional[int] = None, seekable: bool = False) -> Tuple[bytes, bytes, int]:
        """
        Return buffers from the beginning and end of stream.

        Includes number of bytes read if there may be more bytes in the stream.

        If length is None, return the length as found.
        If seekable is False, the steam does not support a seek operation.
        """
        bytes_to_read = self.bufsize if length is None else min(length, self.bufsize)
        bofbuffer = self.blocking_read(stream, bytes_to_read)
        bytes_read = len(bofbuffer)
        if length is None:
            # A stream with unknown length; have to keep two buffers around
            # Use a deque for efficient fixed-size buffer management
            last_two_buffers = deque([bofbuffer], maxlen=2)
            while True:
                buffer = self.blocking_read(stream, self.bufsize)
                bytes_read += len(buffer)
                if len(buffer) == self.bufsize:
                    last_two_buffers.append(buffer)
                else:
                    eofbuffer = last_two_buffers[0] if len(buffer) == 0 else last_two_buffers[0][-(self.bufsize - len(buffer)):] + buffer
                    break
            return bofbuffer, eofbuffer, bytes_read
        bytes_unread = length - len(bofbuffer)
        if bytes_unread == 0:
            eofbuffer = bofbuffer
        elif bytes_unread < self.bufsize:
            # The buffs overlap
            eofbuffer = bofbuffer[bytes_unread:] + self.blocking_read(stream, bytes_unread)
        elif bytes_unread == self.bufsize:
            eofbuffer = self.blocking_read(stream, self.bufsize)
        elif seekable:  # easy case when we can just seek!
            stream.seek(length - self.bufsize)
            eofbuffer = self.blocking_read(stream, self.bufsize)
        else:
            # We have more to read and know how much.
            # n*bufsize + r = length
            (n, r) = divmod(bytes_unread, self.bufsize)
            # skip n-1*bufsize bytes
            for unused_i in range(1, n):
                self.blocking_read(stream, self.bufsize)
            # skip r bytes
            self.blocking_read(stream, r)
            # and read the remaining bufsize bytes into the eofbuffer
            eofbuffer = self.blocking_read(stream, self.bufsize)
        return bofbuffer, eofbuffer, bytes_to_read

    async def get_buffers_async(self, stream: AsyncIterator[bytes], length: Optional[int] = None, seekable: bool = False) -> Tuple[bytes, bytes, int]:
        """
        Asynchronously return buffers from the beginning and end of stream.

        Includes number of bytes read if there may be more bytes in the stream.

        If length is None, return the length as found.
        If seekable is False, the steam does not support a seek operation.
        """
        bytes_to_read = self.bufsize if length is None else min(length, self.bufsize)
        bofbuffer = await stream.read(bytes_to_read)
        bytes_read = len(bofbuffer)

        if length is None:
            # A stream with unknown length; have to keep two buffers around
            # Use a deque for efficient fixed-size buffer management
            last_two_buffers = deque([bofbuffer], maxlen=2)
            while True:
                buffer = await stream.read(self.bufsize)
                bytes_read += len(buffer)
                if len(buffer) == self.bufsize:
                    last_two_buffers.append(buffer)
                else:
                    eofbuffer = last_two_buffers[0] if len(buffer) == 0 else last_two_buffers[0][-(self.bufsize - len(buffer)):] + buffer
                    break
            return bofbuffer, eofbuffer, bytes_read

        bytes_unread = length - len(bofbuffer)
        if bytes_unread == 0:
            eofbuffer = bofbuffer
        elif bytes_unread < self.bufsize:
            # The buffs overlap
            eofbuffer = bofbuffer[bytes_unread:] + await stream.read(bytes_unread)
        elif bytes_unread == self.bufsize:
            eofbuffer = await stream.read(self.bufsize)
        elif seekable:  # easy case when we can just seek!
            await stream.seek(length - self.bufsize)
            eofbuffer = await stream.read(self.bufsize)
        else:
            # This part for non-seekable streams of known length is complex and less common.
            # For now, we'll re-read, but a more optimized solution could be implemented if needed.
            await stream.seek(0)
            # Simplified for this example; a full async implementation would avoid re-reading the whole stream.
            content = await stream.read()
            eofbuffer = content[-self.bufsize:]

        return bofbuffer, eofbuffer, bytes_to_read

    def as_good_as_any(self, f1: FileFormat, match_list: List[Dict[str, Any]]) -> bool:
        """
        Return True if the proposed format is as good as any in the match_list.

        For example, if there is no format in the match_list that has priority over the proposed one
        """
        if match_list != []:
            for match in match_list:
                f2 = match['format']
                if f1 == f2:
                    continue
                if f1.puid in f2.has_priority_over:
                    return False
        return True

    # This method is not used in the library and seems to be a remnant of a different design.
    def buffered_read(self, file_pos: int, overlap: int) -> bytes:
        """Buffered read of data chunks."""
        buf = ""
        if not overlap:
            bufsize = self.container_bufsize
        else:
            bufsize = self.container_bufsize + overlap
        file_end = self.current_filesize
        with open(self.current_file, 'rb') as file_handle:
            file_handle.seek(file_pos)
            if file_end - file_pos < bufsize:
                file_read = file_end - file_pos
            else:
                file_read = self.bufsize
            buf = file_handle.read(file_read)
        return buf

    def _format_matches(self, matches: List[Dict[str, Any]], filename: str, match_type: str) -> List[Dict[str, Any]]:
        """Helper to format match results into the desired dictionary structure."""
        formatted = []
        for match in matches:
            file_format = match['format']
            formatted.append({
                'filename': filename,
                'puid': file_format.puid,
                'format_name': file_format.name,
                'version': file_format.version,
                'mime': file_format.mime,
                'match_type': match_type,
                'signature_name': match['signature_name']
            })
        return formatted

    def match_formats(self, bofbuffer: bytes, eofbuffer: bytes) -> List[Dict[str, Any]]:
        """
        Apply the patterns for formats to the supplied buffers.

        Returns a match list of (format, signature) tuples.
        The list has inferior matches removed.
        """
        self.current_count += 1 # type: ignore
        result: List[Dict[str, Any]] = []
        for format in self.formats:
            try:
                if self.as_good_as_any(format, result):
                    for sig in format.signatures:
                        success = True
                        for pat in sig.patterns:
                            pos = pat.position
                            regex = pat.regex
                            # print 'trying ', regex
                            if pos == 'BOF':
                                if not re.match(regex, bofbuffer):
                                    success = False
                                    break
                            elif pos == 'EOF':
                                if not re.search(regex, eofbuffer):
                                    success = False
                                    break
                            elif pos == 'VAR':
                                if not re.search(regex, bofbuffer):
                                    success = False
                                    break
                            elif pos == 'IFB':
                                if not re.search(regex, bofbuffer):
                                    success = False
                                    break
                        if success:
                            result.append({
                                'format': format,
                                'puid': format.puid,
                                'name': format.name,
                                'signature_name': sig.name
                            })
            except Exception as e:
                print(e)
                continue
            # TODO: MdR: needs some <3
            # print "Unexpected error:", sys.exc_info()[0], e
            # sys.stdout.write('***', self.get_puid(format), regex)

        # Filter out inferior matches in-place if possible, or with a new list if not.
        final_result = []
        for match in result:
            if self.as_good_as_any(match['format'], result):
                final_result.append(match)

        return final_result

    def match_extensions(self, filename: str) -> List[Dict[str, Any]]:
        """Return the list of (format, self.externalsig) for every format whose extension matches the filename."""
        myext = Path(filename).suffix.lower().lstrip(".")
        result: List[Dict[str, Any]] = []
        if not myext:
            return result
        for file_format in self.formats:
            for extension in file_format.extensions:
                if myext == extension:
                    result.append({
                        'format': file_format,
                        'puid': file_format.puid,
                        'name': file_format.name,
                        'signature_name': self.externalsig.findtext("name")
                    })
                    break
        return result

    def match_container_contents(self, filename: str, container_type: str) -> List[Dict[str, Any]]:
        """
        Identify files within a container.
        """
        results = []
        package_class = None
        signatures = None

        if container_type == "zip":
            package_class = ZipPackage
            signatures = self.zip_signatures
        elif container_type == "ole":
            package_class = OlePackage
            signatures = self.ole_signatures

        if package_class and signatures:
            package = package_class(filename, signatures)
            detected_puids = package.detect_formats()
            for puid in detected_puids:
                if puid in self.puid_format_map:
                    file_format = self.puid_format_map[puid]
                    results.append({
                        'filename': filename,
                        'puid': puid,
                        'format_name': file_format.name,
                        'version': file_format.version,
                        'mime': file_format.mime,
                        'match_type': 'container',
                        'signature_name': 'Container signature for ' + file_format.name
                    })
        return results

    async def match_container_contents_async(self, filename: str, container_type: str) -> List[Dict[str, Any]]:
        """
        Asynchronously identify files within a container.
        """
        results = []
        package_class = None
        signatures = None

        if container_type == "zip":
            package_class = ZipPackage
            signatures = self.zip_signatures
        elif container_type == "ole":
            package_class = OlePackage
            signatures = self.ole_signatures

        if package_class and signatures:
            package = package_class(filename, signatures)
            detected_puids = await package.detect_formats_async()
            for puid in detected_puids:
                if puid in self.puid_format_map:
                    file_format = self.puid_format_map[puid]
                    results.append({
                        'filename': filename,
                        'puid': puid,
                        'format_name': file_format.name,
                        'version': file_format.version,
                        'mime': file_format.mime,
                        'match_type': 'container',
                        'signature_name': 'Container signature for ' + file_format.name
                    })
        return results
